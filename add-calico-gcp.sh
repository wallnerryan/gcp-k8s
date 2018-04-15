#!/bin/bash

# Based on 
# https://docs.projectcalico.org/v3.0/getting-started/kubernetes/installation/hosted/hosted
# https://docs.projectcalico.org/v2.0/getting-started/kubernetes/installation/gce
# https://docs.projectcalico.org/v3.0/getting-started/kubernetes/installation/hosted/index#configuration-options
# git clone https://github.com/projectcalico/calico.git

gcloud compute firewall-rules create calico-ipip --allow 4 --network "default" --source-ranges "10.240.0.0/24,10.200.0.0/16"

#RBAC
kubectl apply -f https://docs.projectcalico.org/v3.0/getting-started/kubernetes/installation/rbac.yaml

# Get base64 of certs for etcd
ETCDCABASE64=$(cat ca.pem | base64 -o -)
ETCDCERTBASE64=$(cat kubernetes.pem | base64 -o -)
ETCDKEYBASE64=$(cat kubernetes-key.pem | base64 -o -)
GCPPODCIDR="10.200.0.0/16"
# remove existing net
ansible k8sworkers -i k8shardway.yml --private-key ~/.ssh/wallnerryan -m shell -b -a "rm -rf /etc/cni/net.d/*"
ansible k8sworkers -i k8shardway.yml --private-key ~/.ssh/wallnerryan -m shell -b -a "systemctl restart kubelet"
sleep 5
# update etcd_endpoints: "https://10.240.0.10:2379,https://10.240.0.11:2379,https://10.240.0.12:2379"

# Update to use secret paths
# etcd_ca: "" #/calico-secrets/etcd-ca"
# etcd_cert: "" #"/calico-secrets/etcd-cert"
# etcd_key: "" #/calico-secrets/etcd-key"

# Update secrets in config yaml with base64 outputs from above
# etcd-key: null
# etcd-cert: null
# etcd-ca: null
# Example below
# """
# apiVersion: v1
# kind: Secret
# metadata:
#   name: calico-etcd-secrets
#   namespace: kube-system
# type: Opaque
# data:
#   etcd-ca: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURxakNDQXBLZ0F3SUJBZ0lVTzdJdk1veVlybGZpWWJlZTVYOWZoRWxpUFJjd0RRWUpLb1pJaHZjTkFRRUwKQlFBd2JURUxNQWtHQTFVRUJoTUNWVk14RmpBVUJnTlZCQWdURFUxaGMzTmhZMmgxYzJWMGRITXhEekFOQmdOVgpCQWNUQmtKdmMzUnZiakVUTUJFR0ExVUVDaE1LUzNWaVpYSnVaWFJsY3pFTE1Ba0dBMVVFQ3hNQ1RVRXhFekFSCkJnTlZCQU1UQ2t0MVltVnlibVYwWlhNd0hoY05NVGd3TkRBMU1ERXlNekF3V2hjTk1qTXdOREEwTURFeU16QXcKV2pCdE1Rc3dDUVlEVlFRR0V3SlZVekVXTUJRR0ExVUVDQk1OVFdGemMyRmphSFZ6WlhSMGN6RVBNQTBHQTFVRQpCeE1HUW05emRHOXVNUk13RVFZRFZRUUtFd3BMZFdKbGNtNWxkR1Z6TVFzd0NRWURWUVFMRXdKTlFURVRNQkVHCkExVUVBeE1LUzNWaVpYSnVaWFJsY3pDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUIKQU11RWY3QlhCVGYvWTB1bnFOejgxNUNXTU43OXhVbEM2NVpERGE3SUhrOWM4WkhXTVZtbWhIZHl5aTlRL3IzdQpzOEdkNjJwZHZMek5zSXZMeUdQL0s0Mm95Q2d4QVhrVWJUeU1oRk4wSytObWFxRUFHd2x1UUNjSGdqL3VLTzFtCjFZb0VaQ2h2eldldlhHM1VPcWZDaHY5N0pUdTBJQWFjdmwreWRFNnlzOFNWakR1djdVS1ZzQmVOUFVMVlBSOXoKQy8vMm9uL01xNlFQSTlTYjRCZFJHZzNBTEQrbWF2Yzc1UHFWNUxnTU1NREo4SjRVOEJ0NjF5VkZ0M2lxckpZaQpyQ29iakhPY3V6WEtSTFdsUGpQalRCcnE1Y1ZoQ3Q1MGhwWnViYlg4WGVGMFlNVU0vOFhsM0puL21RQU1lRG11CkdLVlRDSDI2TjlRb29GVHlvVkhWaHRNQ0F3RUFBYU5DTUVBd0RnWURWUjBQQVFIL0JBUURBZ0VHTUE4R0ExVWQKRXdFQi93UUZNQU1CQWY4d0hRWURWUjBPQkJZRUZNNENYTE4rOEk0akJWem5NbTZQL1F4ZXFnUXNNQTBHQ1NxRwpTSWIzRFFFQkN3VUFBNElCQVFDeDI2Szc5RG1MMUxnN3N3Vk1TZGJZT3ZKLzc5b2NBYUx4OHlmUTh0ZmdqN1l4CnRHcVpoZXk0d083OWg1TjJZNldxQVIydzcxdVNpMFM1QXc4RitSbWMvS052dngrZlR4a3hEd2oybDlUQTBGZzIKV29UVnJyalgwK0UwQXJrRmhISG1uZ0hWdlRqLzZ2T1FFaW5PMEJ5VTc1NVhwbWxwQjNwanI1eFFVYW10NHRNQgpUSzZMaDFFTjlEcjlWcU5tbnlkTE9tLzZLck9SVXVLUkJUTGFTYlJ6SU53WU5YeGIxbGg1d1FzWUdVRWYxQTNHCkFCKytSbEIyTzVJekRteXBhRXBKMEEwQlFHSlJmai9oTDFLb1dRcWJPbW1NUEFVUVVmUk5FZWVCaU5RT1lEQ3MKaEh1SUdYWXFuODRram54NTg5WWthelEyVVZlbkY4UnJGYkVEdlJwNAotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==
#   etcd-cert: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUVRakNDQXlxZ0F3SUJBZ0lVVnRjV0JuM3czdlovb3BHZHVFMkxyTkxveXRzd0RRWUpLb1pJaHZjTkFRRUwKQlFBd2JURUxNQWtHQTFVRUJoTUNWVk14RmpBVUJnTlZCQWdURFUxaGMzTmhZMmgxYzJWMGRITXhEekFOQmdOVgpCQWNUQmtKdmMzUnZiakVUTUJFR0ExVUVDaE1LUzNWaVpYSnVaWFJsY3pFTE1Ba0dBMVVFQ3hNQ1RVRXhFekFSCkJnTlZCQU1UQ2t0MVltVnlibVYwWlhNd0hoY05NVGd3TkRBMU1ERXlNekF3V2hjTk1Ua3dOREExTURFeU16QXcKV2pDQmdqRUxNQWtHQTFVRUJoTUNWVk14RmpBVUJnTlZCQWdURFUxaGMzTmhZMmgxYzJWMGRITXhEekFOQmdOVgpCQWNUQmtKdmMzUnZiakVUTUJFR0ExVUVDaE1LUzNWaVpYSnVaWFJsY3pFZ01CNEdBMVVFQ3hNWFMzVmlaWEp1ClpYUmxjeUJVYUdVZ1NHRnlaQ0JYWVhreEV6QVJCZ05WQkFNVENtdDFZbVZ5Ym1WMFpYTXdnZ0VpTUEwR0NTcUcKU0liM0RRRUJBUVVBQTRJQkR3QXdnZ0VLQW9JQkFRQytlT0NmYXZ4L1FXZXRLZFRFVGFqaHNFS3hGS0YyNFNOdwppdk11YVdjUE9jUDVvU2JlOFRicXpVV0R5bEoxRGVaeDFGMkJJN0xXRHNYS2RWU2ZWUFZSanNQUndVaVlEMUFWCjRtQjhxWlJneENreHlQbnZiS3hjK2M5YjdueDIrTTNZR203MnRTQlV5aEJzczVCVjlYRzV4bmpOVGRKTzRxNXUKYkdJVTVwSXdkSlMvcU5SdnBDZGlwbU5XckNhdUo3SFNPd3ZSMUo5V2VWUncwLzRzRUNqMVFUV1JweXNPQ1FkRApJbmVMTk9QT1A5T3dZRmxxWmxtdEZtZFVQQUFzcnNMNnduOFY1c1NBZjQrd1YzZSswS09zMlJFOS9GZjVKS0lrCmh2UDcyRUU4UVY5bkNJUUJWeUtITm11bEh4NzBSay9nTXl1VHJOODc3RUFUN09ENDVrMzdBZ01CQUFHamdjTXcKZ2NBd0RnWURWUjBQQVFIL0JBUURBZ1dnTUIwR0ExVWRKUVFXTUJRR0NDc0dBUVVGQndNQkJnZ3JCZ0VGQlFjRApBakFNQmdOVkhSTUJBZjhFQWpBQU1CMEdBMVVkRGdRV0JCUUZodnlpa1FKZERiS1c0Nk04NEEzVFlxMUZ0REFmCkJnTlZIU01FR0RBV2dCVE9BbHl6ZnZDT0l3VmM1ekp1ai8wTVhxb0VMREJCQmdOVkhSRUVPakE0Z2hKcmRXSmwKY201bGRHVnpMbVJsWm1GMWJIU0hCQW9nQUFHSEJBcndBQXFIQkFyd0FBdUhCQXJ3QUF5SEJDUGpNZG1IQkg4QQpBQUV3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUo0dDdDeGV0SmpreGROUVFWY1djZllBMC91bVpqVW1RK2k5CnZLZ3FJamJiUlQ1NWxyWnBmRFRacS9UNU1oWjE4VWpuQmtRMGdnRjRNRjYrSFJsNUtWWFZ5ZXBmekN2bXlUNG8KbEtLcGxBRHVZRVdYOGRwUnM0c1R1cE1PVTc3YzNnMHhkMWREWlROUStucEdOWktSbTRIdHhrV08rb2c5L2k0ZApIc3ZMWFZWbkZBamsydXJ6emZ4c1Y1Z0RtaDQzbnRlbE95MHJHQzIrcFFHR1Y5cU1BRXoyd0RLVFlqZmtEUmNDCllUTTRMWXhDVDhVcnpqd0RWZVZ3aEt0Ym1hZE9nMnFIK0Y1RGpWTTd0cTVaOS9DaE02bjlnZlNIMGlWM2RsSTgKS0xWdnR6Q1V4UFZ1MVhRd2pOQjdFQnFmT2dJbXEzN3AvYThrQlJjS2FlMTNDbUN4ZUM4PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg== 
#   etcd-key: LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcEFJQkFBS0NBUUVBdm5qZ24ycjhmMEZuclNuVXhFMm80YkJDc1JTaGR1RWpjSXJ6TG1sbkR6bkQrYUVtCjN2RTI2czFGZzhwU2RRM21jZFJkZ1NPeTFnN0Z5blZVbjFUMVVZN0QwY0ZJbUE5UUZlSmdmS21VWU1RcE1jajUKNzJ5c1hQblBXKzU4ZHZqTjJCcHU5clVnVk1vUWJMT1FWZlZ4dWNaNHpVM1NUdUt1Ym14aUZPYVNNSFNVdjZqVQpiNlFuWXFaalZxd21yaWV4MGpzTDBkU2ZWbmxVY05QK0xCQW85VUUxa2FjckRna0hReUozaXpUanpqL1RzR0JaCmFtWlpyUlpuVkR3QUxLN0Mrc0ovRmViRWdIK1BzRmQzdnRDanJOa1JQZnhYK1NTaUpJYnorOWhCUEVGZlp3aUUKQVZjaWh6WnJwUjhlOUVaUDRETXJrNnpmTyt4QUUremcrT1pOK3dJREFRQUJBb0lCQUJ4ZHBCWVp1TUM2M05YTgpCUUszRGcrT1VHQk8wajBDQ21VWVRGNzlFM3dRL2o2TzRWc1NVVHRtbHBPcDdkM0ExRERmajQxTDQ3WTlQUGVKCndiQjQxby91MHZySjdpVzNJaFlnUUg1UVF1aW1UZnc4RWZ5MkVuVkdQcnRTS1BjTzFwajRWczRtNjBtMVRmemkKUVB5TU1RT1pxeVBvRXduc2VFMjVsbUhHZEw4Q1c3L3c5TXY2akE3UTk2WkRrRGpjU1NGWWpRcjRVY3g0U1pYVQpDc2puK0JPc25hRHpHakZrYno0MzE4MTNmc05XakU0T0MxNHAxc0JJaHA3alZ0VmJUeWlrc0IzOWo0Q29LVldyCjhGeHBiWlg0Z3RGeDlBSjl3WlJFa2wyRmRSVFFCdmJyQU9mc01NVDZQeDdWWnhoV1BBeTJFSDNJcnQ2aHRpalMKNkg3N2ZBRUNnWUVBejhFWUdwWWVjRWV0Szg1cXZ0WWcrWnhxSzc2dW1URGxhVlBmMW1HTE9SYnFFOVM5cytVKwo4UE9iMTl3WGd6cUd4dWtCVE5QdFRzYnBib3VTcWlsTWpNcUNrMUZzOVRSeU81cHV5TDhDd1pKRTZ5VGVxcmVkCmVwUVRORFZTZnh3WVUrTDVzRUdkaThybEpNZWNsRzNIMUF4NkRWNzA3SWxqY3ZXVmxCTVJBT3NDZ1lFQTZyUmUKcVNTcExUVVNPa2ZBWld0c09sN21VaUlkdHg5d0ZtT0ZXSTJZTjFPNXVIYk91OTRmcndCeEVBUlRuU1UxczdBRQprcEFLaWpiRmpTYy9Ba1UzU1dQRXVpMEkrOVErbG5OYmcvbEFuSFE2aHpOdUhGbytCbHRwZ01VTzdENCtJNnkyCjZSTlEzTXBNSWgyWjR5S3VvWVV3WU5VMlcyeHZFMWpiZG1WUEl6RUNnWUVBdFBoL0JxbTkyaENWeUpNR2FUWWQKZzFHOUtsM3Z1WUhlVk9HN0dnUGVRdHl6Q3BOR3JHNEZaZDdPNGpuV1FYbTU3WXNLbHVJRTFacHZ2TnZYNW1JVApUSkViTFRqQXNOZitxZXpjbEFIUFpNOEZPYy9rSnRITFcvdWd2dG0wQXdWMks1eUw0LzFFUDRGK0dZdkgyWVBICmplOVFZbFZWQkxhbzZuc0MwUG5LMWdFQ2dZQi9lMXNUU210dHQ2N2Y0d3M0eTBGczd4RHhPY0NrTDdwRkh1ZFYKOHdyanVtRmROWU1TL2hKOWpxTGF6VTdSUTEzSTdPbCs1aWdqYko2ZkRkc21rNHYxRy9ER0l5SUhEd0N6M1pLdQp1MXNCNEF2T1Zmd1FBR0JDT2JLems5V0lNa0swUStMUjlJRHVmQjhnUkszS2RwTWQvbWNKb2FXMXdNOFFWaXBXClE2N1pjUUtCZ1FEQkN3ZFJGbE5Fbi8rUEEvN3dHWkZWQng2NEIvdjB0cmRLRWZVbGlxSmJVOC9BZUxUb1dEaFQKNzlReGtGdDdiS0NHTmwwVmt2ZG1MU25weWJBTHRMaUFEWC8zbHFMNjBEUG9ueENaMFBLZjcrZnRXdkRBK3hXVQpIdVp4MnNvZXdnRXdabkdnL2hOYWxqb2ZZeGRkVDhzd1ZPMEpxRXNPck9ES2pRK2xPMG5CZGc9PQotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo=
#   """

# # update the ippool to the POD_CIDR
# # modify the CALICO_IPV4POOL_CIDR section of the calico.yaml 
# '''
#  name: CALICO_IPV4POOL_CIDR
#               value: "10.200.0.0/16"
# '''

cat > calico.yaml <<EOF
kind: ConfigMap
apiVersion: v1
metadata:
  name: calico-config
  namespace: kube-system
data:
  # Configure this with the location of your etcd cluster.
  etcd_endpoints: "https://10.240.0.10:2379,https://10.240.0.11:2379,https://10.240.0.12:2379"

  # Configure the Calico backend to use.
  calico_backend: "bird"

  # The CNI network configuration to install on each node.
  cni_network_config: |-
    {
      "name": "k8s-pod-network",
      "cniVersion": "0.3.0",
      "plugins": [
        {
            "type": "calico",
            "etcd_endpoints": "__ETCD_ENDPOINTS__",
            "etcd_key_file": "__ETCD_KEY_FILE__",
            "etcd_cert_file": "__ETCD_CERT_FILE__",
            "etcd_ca_cert_file": "__ETCD_CA_CERT_FILE__",
            "log_level": "info",
            "mtu": 1500,
            "ipam": {
                "type": "calico-ipam"
            },
            "policy": {
                "type": "k8s",
                "k8s_api_root": "https://__KUBERNETES_SERVICE_HOST__:__KUBERNETES_SERVICE_PORT__",
                "k8s_auth_token": "__SERVICEACCOUNT_TOKEN__"
            },
            "kubernetes": {
                "kubeconfig": "__KUBECONFIG_FILEPATH__"
            }
        },
        {
          "type": "portmap",
          "snat": true,
          "capabilities": {"portMappings": true}
        }
      ]
    }

  # If you're using TLS enabled etcd uncomment the following.
  # You must also populate the Secret below with these files.
  etcd_ca: "/calico-secrets/etcd-ca"
  etcd_cert: "/calico-secrets/etcd-cert"
  etcd_key: "/calico-secrets/etcd-key"
EOF


cat > calico-tls.yaml <<EOF
# The following contains k8s Secrets for use with a TLS enabled etcd cluster.
# For information on populating Secrets, see http://kubernetes.io/docs/user-guide/secrets/
apiVersion: v1
kind: Secret
type: Opaque
metadata:
  name: calico-etcd-secrets
  namespace: kube-system
data:
  # Populate the following files with etcd TLS configuration if desired, but leave blank if
  # not using TLS for etcd.
  # This self-hosted install expects three files with the following names.  The values
  # should be base64 encoded strings of the entire contents of each file.
  etcd-key: $ETCDKEYBASE64
  etcd-cert: $ETCDCERTBASE64
  etcd-ca: $ETCDCABASE64
EOF

cat > calico-node.yaml <<EOF
# This manifest installs the calico/node container, as well
# as the Calico CNI plugins and network config on
# each master and worker node in a Kubernetes cluster.
kind: DaemonSet
apiVersion: extensions/v1beta1
metadata:
  name: calico-node
  namespace: kube-system
  labels:
    k8s-app: calico-node
spec:
  selector:
    matchLabels:
      k8s-app: calico-node
  updateStrategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1
  template:
    metadata:
      labels:
        k8s-app: calico-node
      annotations:
        scheduler.alpha.kubernetes.io/critical-pod: ''
    spec:
      hostNetwork: true
      tolerations:
        # Make sure calico/node gets scheduled on all nodes.
        - effect: NoSchedule
          operator: Exists
        # Mark the pod as a critical add-on for rescheduling.
        - key: CriticalAddonsOnly
          operator: Exists
        - effect: NoExecute
          operator: Exists
      serviceAccountName: calico-node
      # Minimize downtime during a rolling upgrade or deletion; tell Kubernetes to do a "force
      # deletion": https://kubernetes.io/docs/concepts/workloads/pods/pod/#termination-of-pods.
      terminationGracePeriodSeconds: 0
      containers:
        # Runs calico/node container on each Kubernetes node.  This
        # container programs network policy and routes on each
        # host.
        - name: calico-node
          image: quay.io/calico/node:v3.0.4
          env:
            # The location of the Calico etcd cluster.
            - name: ETCD_ENDPOINTS
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: etcd_endpoints
            # Choose the backend to use.
            - name: CALICO_NETWORKING_BACKEND
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: calico_backend
            # Cluster type to identify the deployment type
            - name: CLUSTER_TYPE
              value: "k8s,bgp"
            # Disable file logging so kubectl logs works.
            - name: CALICO_DISABLE_FILE_LOGGING
              value: "true"
            # Set noderef for node controller.
            - name: CALICO_K8S_NODE_REF
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
            # Set Felix endpoint to host default action to ACCEPT.
            - name: FELIX_DEFAULTENDPOINTTOHOSTACTION
              value: "ACCEPT"
            # The default IPv4 pool to create on startup if none exists. Pod IPs will be
            # chosen from this range. Changing this value after installation will have
            # no effect. 
            - name: CALICO_IPV4POOL_CIDR
              value: $GCPPODCIDR
            - name: CALICO_IPV4POOL_IPIP
              value: "Always"
            # Disable IPv6 on Kubernetes.
            - name: FELIX_IPV6SUPPORT
              value: "false"
            # Set Felix logging to "info"
            - name: FELIX_LOGSEVERITYSCREEN
              value: "info"
            # Set MTU for tunnel device used if ipip is enabled
            - name: FELIX_IPINIPMTU
              value: "1440"
            # Location of the CA certificate for etcd.
            - name: ETCD_CA_CERT_FILE
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: etcd_ca
            # Location of the client key for etcd.
            - name: ETCD_KEY_FILE
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: etcd_key
            # Location of the client certificate for etcd.
            - name: ETCD_CERT_FILE
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: etcd_cert
            # Auto-detect the BGP IP address.
            - name: IP
              value: "autodetect"
            - name: FELIX_HEALTHENABLED
              value: "true"
          securityContext:
            privileged: true
          resources:
            requests:
              cpu: 250m
          livenessProbe:
            httpGet:
              path: /liveness
              port: 9099
            periodSeconds: 10
            initialDelaySeconds: 10
            failureThreshold: 6
          readinessProbe:
            httpGet:
              path: /readiness
              port: 9099
            periodSeconds: 10
          volumeMounts:
            - mountPath: /lib/modules
              name: lib-modules
              readOnly: true
            - mountPath: /var/run/calico
              name: var-run-calico
              readOnly: false
            - mountPath: /calico-secrets
              name: etcd-certs
        # This container installs the Calico CNI binaries
        # and CNI network config file on each node.
        - name: install-cni
          image: quay.io/calico/cni:v2.0.3
          command: ["/install-cni.sh"]
          env:
            # Name of the CNI config file to create.
            - name: CNI_CONF_NAME
              value: "10-calico.conflist"
            # The location of the Calico etcd cluster.
            - name: ETCD_ENDPOINTS
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: etcd_endpoints
            # The CNI network config to install on each node.
            - name: CNI_NETWORK_CONFIG
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: cni_network_config
          volumeMounts:
            - mountPath: /host/opt/cni/bin
              name: cni-bin-dir
            - mountPath: /host/etc/cni/net.d
              name: cni-net-dir
            - mountPath: /calico-secrets
              name: etcd-certs
      volumes:
        # Used by calico/node.
        - name: lib-modules
          hostPath:
            path: /lib/modules
        - name: var-run-calico
          hostPath:
            path: /var/run/calico
        # Used to install CNI.
        - name: cni-bin-dir
          hostPath:
            path: /opt/cni/bin
        - name: cni-net-dir
          hostPath:
            path: /etc/cni/net.d
        # Mount in the etcd TLS secrets.
        - name: etcd-certs
          secret:
            secretName: calico-etcd-secrets
EOF

cat > calico-controller.yaml <<EOF
# This manifest deploys the Calico Kubernetes controllers.
# See https://github.com/projectcalico/kube-controllers
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: calico-kube-controllers
  namespace: kube-system
  labels:
    k8s-app: calico-kube-controllers
  annotations:
    scheduler.alpha.kubernetes.io/critical-pod: ''
    scheduler.alpha.kubernetes.io/tolerations: |
      [{"key": "dedicated", "value": "master", "effect": "NoSchedule" },
       {"key":"CriticalAddonsOnly", "operator":"Exists"}]
spec:
  # The controllers can only have a single active instance.
  replicas: 1
  strategy:
    type: Recreate
  template:
    metadata:
      name: calico-kube-controllers
      namespace: kube-system
      labels:
        k8s-app: calico-kube-controllers
    spec:
      # The controllers must run in the host network namespace so that
      # it isn't governed by policy that would prevent it from working.
      hostNetwork: true
      serviceAccountName: calico-kube-controllers
      containers:
        - name: calico-kube-controllers
          image: quay.io/calico/kube-controllers:v2.0.2
          env:
            # The location of the Calico etcd cluster.
            - name: ETCD_ENDPOINTS
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: etcd_endpoints
            # Location of the CA certificate for etcd.
            - name: ETCD_CA_CERT_FILE
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: etcd_ca
            # Location of the client key for etcd.
            - name: ETCD_KEY_FILE
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: etcd_key
            # Location of the client certificate for etcd.
            - name: ETCD_CERT_FILE
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: etcd_cert
            # Choose which controllers to run.
            - name: ENABLED_CONTROLLERS
              value: policy,profile,workloadendpoint,node
          volumeMounts:
            # Mount in the etcd TLS secrets.
            - mountPath: /calico-secrets
              name: etcd-certs
      volumes:
        # Mount in the etcd TLS secrets.
        - name: etcd-certs
          secret:
            secretName: calico-etcd-secrets
EOF

cat > calico-sa-controller.yaml <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: calico-kube-controllers
  namespace: kube-system
EOF

cat > calico-sa-node.yaml <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: calico-node
  namespace: kube-system
EOF

kubectl create -f calico.yaml
kubectl create -f calico-tls.yaml
kubectl create -f calico-node.yaml
kubectl create -f calico-controller.yaml
kubectl create -f calico-sa-controller.yaml
kubectl create -f calico-sa-node.yaml



#Then deploy DNS

# update clusterIP: 10.100.0.10 to clusterIP: 10.100.0.10 
cat > kube-dns-service.yaml <<EOF
apiVersion: v1
kind: Service
metadata:
  name: kube-dns
  namespace: kube-system
  labels:
    k8s-app: kube-dns
    kubernetes.io/cluster-service: "true"
    kubernetes.io/name: "KubeDNS"
spec:
  selector:
    k8s-app: kube-dns
  clusterIP: 10.100.0.10 
  ports:
  - name: dns
    port: 53
    protocol: UDP
  - name: dns-tcp
    port: 53
    protocol: TCP
EOF

cat > kube-dns.yaml <<EOF
# Copyright 2016 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

apiVersion: v1
kind: Service
metadata:
  name: kube-dns
  namespace: kube-system
  labels:
    k8s-app: kube-dns
    kubernetes.io/cluster-service: "true"
    addonmanager.kubernetes.io/mode: Reconcile
    kubernetes.io/name: "KubeDNS"
spec:
  selector:
    k8s-app: kube-dns
  clusterIP: 10.100.0.10
  ports:
  - name: dns
    port: 53
    protocol: UDP
  - name: dns-tcp
    port: 53
    protocol: TCP
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: kube-dns
  namespace: kube-system
  labels:
    kubernetes.io/cluster-service: "true"
    addonmanager.kubernetes.io/mode: Reconcile
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: kube-dns
  namespace: kube-system
  labels:
    addonmanager.kubernetes.io/mode: EnsureExists
---
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: kube-dns
  namespace: kube-system
  labels:
    k8s-app: kube-dns
    kubernetes.io/cluster-service: "true"
    addonmanager.kubernetes.io/mode: Reconcile
spec:
  # replicas: not specified here:
  # 1. In order to make Addon Manager do not reconcile this replicas parameter.
  # 2. Default is 1.
  # 3. Will be tuned in real time if DNS horizontal auto-scaling is turned on.
  strategy:
    rollingUpdate:
      maxSurge: 10%
      maxUnavailable: 0
  selector:
    matchLabels:
      k8s-app: kube-dns
  template:
    metadata:
      labels:
        k8s-app: kube-dns
      annotations:
        scheduler.alpha.kubernetes.io/critical-pod: ''
    spec:
      tolerations:
      - key: "CriticalAddonsOnly"
        operator: "Exists"
      volumes:
      - name: kube-dns-config
        configMap:
          name: kube-dns
          optional: true
      containers:
      - name: kubedns
        image: gcr.io/google_containers/k8s-dns-kube-dns-amd64:1.14.7
        resources:
          # TODO: Set memory limits when we've profiled the container for large
          # clusters, then set request = limit to keep this container in
          # guaranteed class. Currently, this container falls into the
          # "burstable" category so the kubelet doesn't backoff from restarting it.
          limits:
            memory: 170Mi
          requests:
            cpu: 100m
            memory: 70Mi
        livenessProbe:
          httpGet:
            path: /healthcheck/kubedns
            port: 10054
            scheme: HTTP
          initialDelaySeconds: 60
          timeoutSeconds: 5
          successThreshold: 1
          failureThreshold: 5
        readinessProbe:
          httpGet:
            path: /readiness
            port: 8081
            scheme: HTTP
          # we poll on pod startup for the Kubernetes master service and
          # only setup the /readiness HTTP server once that's available.
          initialDelaySeconds: 3
          timeoutSeconds: 5
        args:
        - --domain=cluster.local.
        - --dns-port=10053
        - --config-dir=/kube-dns-config
        - --v=2
        env:
        - name: PROMETHEUS_PORT
          value: "10055"
        ports:
        - containerPort: 10053
          name: dns-local
          protocol: UDP
        - containerPort: 10053
          name: dns-tcp-local
          protocol: TCP
        - containerPort: 10055
          name: metrics
          protocol: TCP
        volumeMounts:
        - name: kube-dns-config
          mountPath: /kube-dns-config
      - name: dnsmasq
        image: gcr.io/google_containers/k8s-dns-dnsmasq-nanny-amd64:1.14.7
        livenessProbe:
          httpGet:
            path: /healthcheck/dnsmasq
            port: 10054
            scheme: HTTP
          initialDelaySeconds: 60
          timeoutSeconds: 5
          successThreshold: 1
          failureThreshold: 5
        args:
        - -v=2
        - -logtostderr
        - -configDir=/etc/k8s/dns/dnsmasq-nanny
        - -restartDnsmasq=true
        - --
        - -k
        - --cache-size=1000
        - --no-negcache
        - --log-facility=-
        - --server=/cluster.local/127.0.0.1#10053
        - --server=/in-addr.arpa/127.0.0.1#10053
        - --server=/ip6.arpa/127.0.0.1#10053
        ports:
        - containerPort: 53
          name: dns
          protocol: UDP
        - containerPort: 53
          name: dns-tcp
          protocol: TCP
        # see: https://github.com/kubernetes/kubernetes/issues/29055 for details
        resources:
          requests:
            cpu: 150m
            memory: 20Mi
        volumeMounts:
        - name: kube-dns-config
          mountPath: /etc/k8s/dns/dnsmasq-nanny
      - name: sidecar
        image: gcr.io/google_containers/k8s-dns-sidecar-amd64:1.14.7
        livenessProbe:
          httpGet:
            path: /metrics
            port: 10054
            scheme: HTTP
          initialDelaySeconds: 60
          timeoutSeconds: 5
          successThreshold: 1
          failureThreshold: 5
        args:
        - --v=2
        - --logtostderr
        - --probe=kubedns,127.0.0.1:10053,kubernetes.default.svc.cluster.local,5,SRV
        - --probe=dnsmasq,127.0.0.1:53,kubernetes.default.svc.cluster.local,5,SRV
        ports:
        - containerPort: 10054
          name: metrics
          protocol: TCP
        resources:
          requests:
            memory: 20Mi
            cpu: 10m
      dnsPolicy: Default  # Don't use cluster DNS.
      serviceAccountName: kube-dns
EOF

kubectl create -f kube-dns.yaml 

kubectl get po -n kube-system
