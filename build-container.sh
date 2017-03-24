#!/usr/bin/env bash
name=euank/kube-cert-manager:$(git rev-parse --short HEAD)
docker build -t $name $(dirname "$0")
docker push $name
echo $name
