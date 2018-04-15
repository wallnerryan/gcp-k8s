#!/bin/bash

kubectl delete -f calico.yaml
kubectl delete -f calico-tls.yaml
kubectl delete -f calico-node.yaml
kubectl delete -f calico-controller.yaml
kubectl deletec -f calico-sa-controller.yaml
kubectl delete -f calico-sa-node.yaml
kubectl delete -f kube-dns.yaml 

gcloud -q compute firewall-rules delete calico-ipip