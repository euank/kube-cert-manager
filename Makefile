./kube-cert-manager:
	GOARCH=amd64 GOOS=linux CGO_ENABLED=0 go build -i -o kube-cert-manager .

.PHONY: clean
clean:
	rm -f ./kube-cert-manager
