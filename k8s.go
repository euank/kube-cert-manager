// Copyright 2016 Google Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/pkg/errors"
	"github.com/xenolf/lego/acme"
	"k8s.io/client-go/kubernetes"
	kerrors "k8s.io/client-go/pkg/api/errors"
	"k8s.io/client-go/pkg/api/meta"
	"k8s.io/client-go/pkg/api/unversioned"
	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/pkg/apis/extensions/v1beta1"
	"k8s.io/client-go/pkg/fields"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

const (
	eventsEndpoint = "/api/v1/namespaces/%s/events"
)

// K8sClient provides convenience functions for handling resources this project
// cares about
// TODO: merge the two clients
type K8sClient struct {
	c          *kubernetes.Clientset
	certClient *kubernetes.Clientset
}

type WatchEvent struct {
	Type   string          `json:"type"`
	Object json.RawMessage `json:"object"`
}

type CertificateEvent struct {
	Type   string      `json:"type"`
	Object Certificate `json:"object"`
}

type Certificate struct {
	unversioned.TypeMeta `json:",inline"`
	Metadata             v1.ObjectMeta   `json:"metadata"`
	Spec                 CertificateSpec `json:"spec"`
}

func (c *Certificate) GetObjectKind() unversioned.ObjectKind {
	return &c.TypeMeta
}

func (c *Certificate) GetObjectMeta() meta.Object {
	return &c.Metadata
}

func (c *CertificateList) GetObjectKind() unversioned.ObjectKind {
	return &c.TypeMeta
}

func (c *CertificateList) GetObjectMeta() unversioned.List {
	return &c.Metadata
}

type CertificateSpec struct {
	Domain     string `json:"domain"`
	Provider   string `json:"provider"`
	Email      string `json:"email"`
	SecretName string `json:"secretName"`
}

type CertificateList struct {
	unversioned.TypeMeta `json:",inline"`
	Metadata             unversioned.ListMeta `json:"metadata"`
	Items                []Certificate        `json:"items"`
}

type ACMECertData struct {
	DomainName string
	Cert       []byte
	PrivateKey []byte
}

type IngressEvent struct {
	Type   string          `json:"type"`
	Object v1beta1.Ingress `json:"object"`
}

func ingressReference(ing v1beta1.Ingress, path string) v1.ObjectReference {
	return v1.ObjectReference{
		Kind:            "Ingress",
		Namespace:       ing.Namespace,
		Name:            ing.Name,
		UID:             ing.UID,
		ResourceVersion: ing.ResourceVersion,
		FieldPath:       path,
	}
}

func (k K8sClient) createEvent(ev v1.Event) {
	now := unversioned.Now()
	ev.Name = fmt.Sprintf("%s.%x", ev.InvolvedObject.Name, now.UnixNano())
	if ev.Kind == "" {
		ev.Kind = "Event"
	}
	if ev.APIVersion == "" {
		ev.APIVersion = "v1"
	}
	if ev.FirstTimestamp.IsZero() {
		ev.FirstTimestamp = now
	}
	if ev.LastTimestamp.IsZero() {
		ev.LastTimestamp = now
	}
	if ev.Count == 0 {
		ev.Count = 1
	}
	b, err := json.Marshal(ev)
	if err != nil {
		log.Println("internal error:", err)
		return
	}
	resp := k.c.Extensions().RESTClient().Post().AbsPath(eventsEndpoint).Body(b).Do()
	if resp.Error() != nil {
		switch e := resp.Error().(type) {
		case *kerrors.StatusError:
			log.Printf("unexpected HTTP status code while creating event: %d\n", e.Status().Code)
		default:
			log.Println("internal error:", err)
			return
		}
	}
}

type ACMEUserData struct {
	Email        string                     `json:"email"`
	Registration *acme.RegistrationResource `json:"registration"`
	Key          []byte                     `json:"key"`
}

type ACMECertDetails struct {
	Domain        string `json:"domain"`
	CertURL       string `json:"certUrl"`
	CertStableURL string `json:"certStableUrl"`
	AccountRef    string `json:"accountRef,omitempty"`
}

func (u *ACMEUserData) GetEmail() string {
	return u.Email
}

func (u *ACMEUserData) GetRegistration() *acme.RegistrationResource {
	return u.Registration
}

func (u *ACMEUserData) GetPrivateKey() crypto.PrivateKey {
	pemBlock, _ := pem.Decode(u.Key)
	if pemBlock.Type != "RSA PRIVATE KEY" {
		log.Printf("Invalid PEM user key: Expected RSA PRIVATE KEY, got %v", pemBlock.Type)
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		log.Printf("Error while parsing private key: %v", err)
	}

	return privateKey
}

// ToSecret creates a Kubernetes Secret from an ACME Certificate
func (c *ACMECertData) ToSecret(tagPrefix, class string) *v1.Secret {
	var metadata v1.ObjectMeta

	// The "true" annotation is deprecated when a class label is used
	if class != "" {
		metadata.Labels = map[string]string{
			addTagPrefix(tagPrefix, "domain"): c.DomainName,
			addTagPrefix(tagPrefix, "class"):  class,
		}
	} else {
		metadata.Labels = map[string]string{
			addTagPrefix(tagPrefix, "domain"): c.DomainName,
		}
		metadata.Annotations = map[string]string{
			addTagPrefix(tagPrefix, "enabled"): "true",
		}
	}

	data := make(map[string][]byte)
	data["tls.crt"] = c.Cert
	data["tls.key"] = c.PrivateKey

	return &v1.Secret{
		TypeMeta: unversioned.TypeMeta{
			APIVersion: "v1",
			Kind:       "Secret",
		},
		Data:       data,
		ObjectMeta: metadata,
		Type:       "kubernetes.io/tls",
	}
}

func NewACMECertDataFromSecret(s *v1.Secret, tagPrefix string) (ACMECertData, error) {
	var acmeCertData ACMECertData
	var ok bool

	acmeCertData.DomainName = getDomainFromLabel(s, tagPrefix)
	acmeCertData.Cert, ok = s.Data["tls.crt"]
	if !ok {
		return acmeCertData, errors.Errorf("Could not find key tls.crt in secret %v", s.Name)
	}
	acmeCertData.PrivateKey, ok = s.Data["tls.key"]
	if !ok {
		return acmeCertData, errors.Errorf("Could not find key tls.key in secret %v", s.Name)
	}
	return acmeCertData, nil
}

func NewACMECertDetailsFromResource(certRes acme.CertificateResource) ACMECertDetails {
	return ACMECertDetails{
		Domain:        certRes.Domain,
		CertURL:       certRes.CertURL,
		CertStableURL: certRes.CertStableURL,
		AccountRef:    certRes.AccountRef,
	}
}

func (certDetails *ACMECertDetails) ToCertResource() acme.CertificateResource {
	return acme.CertificateResource{
		Domain:        certDetails.Domain,
		CertURL:       certDetails.CertURL,
		CertStableURL: certDetails.CertStableURL,
		AccountRef:    certDetails.AccountRef,
	}
}

func (k K8sClient) getSecret(namespace string, key string) (*v1.Secret, error) {
	secret, err := k.c.Core().Secrets(namespace).Get(key)
	if err != nil {
		switch kerr := err.(type) {
		case kerrors.APIStatus:
			if kerr.Status().Code == http.StatusNotFound {
				return nil, nil
			} else {
				return nil, errors.Wrapf(err, "Unexpected status code  whle fetching secret %q: %v", key, kerr.Status())
			}
		}
		return nil, errors.Wrapf(err, "Unexpected error while fetching secret %q", key)
	}
	return secret, nil
}

func (k K8sClient) saveSecret(namespace string, secret *v1.Secret, isUpdate bool) error {
	if secret.Name == "" {
		return errors.New("Secret name must be specified in metadata")
	}

	if isUpdate {
		_, err := k.c.Secrets(namespace).Update(secret)
		return err
	} else {
		_, err := k.c.Secrets(namespace).Create(secret)
		return err
	}
}

func (k K8sClient) deleteSecret(namespace string, key string) error {
	return k.c.Secrets(namespace).Delete(key, nil)
}

func (k K8sClient) getSecrets(namespace string) ([]v1.Secret, error) {
	list, err := k.c.Secrets(namespace).List(v1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return list.Items, nil
}

func (k K8sClient) getCertificates(namespace string) ([]Certificate, error) {
	var resp rest.Result

	var certList CertificateList
	for {
		err := k.c.Extensions().RESTClient().Get().Resource("certificates").Namespace(namespace).Do().Into(&certList)
		if err != nil {
			log.Printf("Error while retrieving certificate: %v. Retrying in 5 seconds", resp.Error())
			time.Sleep(5 * time.Second)
			continue
		}
		break
	}

	return certList.Items, nil
}

func (k K8sClient) getIngresses(namespace string) ([]v1beta1.Ingress, error) {
	for {
		ingresses, err := k.c.Extensions().Ingresses(namespace).List(v1.ListOptions{})
		if err != nil {
			log.Printf("Error while retrieving ingress: %v. Retrying in 5 seconds", err)
			time.Sleep(5 * time.Second)
			continue
		} else {
			return ingresses.Items, nil
		}
	}
}

func (k K8sClient) monitorCertificateEvents(namespace string, done <-chan struct{}) <-chan CertificateEvent {
	events := make(chan CertificateEvent)

	// curry func for add/update/delete events
	evFunc := func(evType string) func(obj interface{}) {
		return func(obj interface{}) {
			cert, ok := obj.(*Certificate)
			if !ok {
				log.Printf("could not convert %#v into Certificate", obj)
				return
			}
			events <- CertificateEvent{
				Type:   evType,
				Object: *cert,
			}
		}
	}

	source := cache.NewListWatchFromClient(k.certClient.Extensions().RESTClient(), "certificates", v1.NamespaceAll, fields.Everything())
	_, controller := cache.NewInformer(source, &Certificate{}, 0, cache.ResourceEventHandlerFuncs{
		AddFunc:    evFunc("ADDED"),
		DeleteFunc: evFunc("DELETED"),
		UpdateFunc: func(old, new interface{}) {
			evFunc("MODIFIED")(new)
		},
	})

	go controller.Run(done)

	return events
}

func (k K8sClient) monitorIngressEvents(namespace string, done <-chan struct{}) <-chan IngressEvent {
	events := make(chan IngressEvent)

	// curry func for add/update/delete events
	evFunc := func(evType string) func(obj interface{}) {
		return func(obj interface{}) {
			ing, ok := obj.(*v1beta1.Ingress)
			if !ok {
				log.Printf("could not convert %#v into Certificate", obj)
				return
			}
			events <- IngressEvent{
				Type:   evType,
				Object: *ing,
			}
		}
	}
	source := cache.NewListWatchFromClient(k.c.Extensions().RESTClient(), "ingresses", v1.NamespaceAll, fields.Everything())
	_, controller := cache.NewInformer(source, &v1beta1.Ingress{}, 0, cache.ResourceEventHandlerFuncs{
		AddFunc:    evFunc("ADDED"),
		DeleteFunc: evFunc("DELETED"),
		UpdateFunc: func(old, new interface{}) {
			evFunc("MODIFIED")(new)
		},
	})

	go controller.Run(done)

	return events
}

func namespacedEndpoint(endpoint, namespace string) string {
	return fmt.Sprintf(endpoint, namespace)
}

func namespacedAllCertEndpoint(endpoint, certNamespace string) string {
	return fmt.Sprintf(endpoint, certNamespace)
}

func namespacedCertEndpoint(endpoint, certNamespace, namespace string) string {
	return fmt.Sprintf(endpoint, certNamespace, namespace)
}

func addURLArgument(urlString string, key string, value string) (string, error) {
	u, err := url.Parse(urlString)
	if err != nil {
		return "", errors.Wrapf(err, "Error parsing URL: %v", err)
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func getDomainFromLabel(s *v1.Secret, tagPrefix string) string {
	domain := s.Labels[addTagPrefix(tagPrefix, "domain")]
	if domain == "" {
		// deprecated plain "domain" label
		// check for it in case people have the plain label in secrets when upgrading
		// will be updated to the prefixed label when the Secret is next updated
		domain = s.Labels["domain"]
	}
	return domain
}
