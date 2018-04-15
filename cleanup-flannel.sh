#!/bin/bash

kubectl delete -f flannel.yaml
kubectl delete -f kube-dns.yaml 