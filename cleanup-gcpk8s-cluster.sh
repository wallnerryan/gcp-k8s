#!/bin/bash

FIREWALLRULE_NAMES=${1:-''} 
GCPROUTES=${2:-'n'} 

echo "deleteing extra firewall rules: $FIREWALLRULE_NAMES"
echo "cleanup GCP routes?: "

gcloud -q compute instances delete \
  controller-0 controller-1 controller-2 \
  worker-0 worker-1 worker-2

gcloud -q compute forwarding-rules delete kubernetes-forwarding-rule \
  --region $(gcloud config get-value compute/region)

gcloud -q compute target-pools delete kubernetes-target-pool

gcloud -q compute addresses delete kubernetes-the-hard-way

gcloud -q compute firewall-rules delete \
     kubernetes-the-hard-way-allow-internal \
     kubernetes-the-hard-way-allow-external \
     $FIREWALLRULE_NAMES

echo "cleaning up routes"
gcloud -q compute routes delete \
  kubernetes-route-10-200-0-0-24 \
  kubernetes-route-10-200-1-0-24 \
  ubernetes-route-10-200-2-0-24


gcloud -q compute networks subnets delete kubernetes

gcloud -q compute networks delete kubernetes-the-hard-way


rm *.json *.pem *.kubeconfig *.worker* *.controller* *.csr *.yml *.yaml *.retry