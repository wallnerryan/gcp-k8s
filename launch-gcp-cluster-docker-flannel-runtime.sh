#!/bin/bash

# TODO
# make things configurable 


gcloud config list

read -p "The above config is where gcloud will use, contune??" -n 1 -r
echo    # (optional) move to a new line
if [[ $REPLY =~ ^[Yy]$ ]]
then
    echo "Launching k8s on GCP!"
else
    echo "exiting..."
    exit 0
fi


gcloud compute networks create kubernetes-the-hard-way --subnet-mode custom

gcloud compute networks subnets create kubernetes \
  --network kubernetes-the-hard-way \
  --range 10.240.0.0/24

gcloud compute firewall-rules create kubernetes-the-hard-way-allow-internal \
  --allow tcp,udp,icmp \
  --network kubernetes-the-hard-way \
  --source-ranges 10.240.0.0/24,10.200.0.0/16

gcloud compute firewall-rules create kubernetes-the-hard-way-allow-external \
  --allow tcp:22,tcp:6443,icmp \
  --network kubernetes-the-hard-way \
  --source-ranges 0.0.0.0/0


gcloud compute addresses create kubernetes-the-hard-way \
  --region $(gcloud config get-value compute/region)

echo "Creatting controller VMs 1-3"
for i in 0 1 2; do
  gcloud compute instances create controller-${i} \
    --async \
    --boot-disk-size 200GB \
    --can-ip-forward \
    --image-family ubuntu-1604-lts \
    --image-project ubuntu-os-cloud \
    --machine-type n1-standard-1 \
    --private-network-ip 10.240.0.1${i} \
    --scopes compute-rw,storage-ro,service-management,service-control,logging-write,monitoring \
    --subnet kubernetes \
    --tags kubernetes-the-hard-way,controller
done

echo "Creating Worker VMs 1-3"
for i in 0 1 2; do
  gcloud compute instances create worker-${i} \
    --async \
    --boot-disk-size 200GB \
    --can-ip-forward \
    --image-family ubuntu-1604-lts \
    --image-project ubuntu-os-cloud \
    --machine-type n1-standard-1 \
    --metadata pod-cidr=10.200.${i}.0/24 \
    --private-network-ip 10.240.0.2${i} \
    --scopes compute-rw,storage-ro,service-management,service-control,logging-write,monitoring \
    --subnet kubernetes \
    --tags kubernetes-the-hard-way,worker
done

echo "[k8snodes]" > k8shardway.yml 
gcloud compute instances list --format=json     | jq '.[].networkInterfaces[].accessConfigs[].natIP' >> k8shardway.yml 

echo "Nodes in ansible"
cat k8shardway.yml 

cat > wait_for_ssh.yml <<EOF
---
- name: wait for connection to new VMs
  hosts: k8snodes
  tasks:
  - name: Wait for ssh
    wait_for:
      port: 22
      host: '{{ (ansible_ssh_host|default(ansible_host))|default(inventory_hostname) }}'
      search_regex: OpenSSH
      delay: 10
    connection: local
EOF

echo "waiting for SSH come up on the VMs"
until ansible-playbook --private-key ~/.ssh/wallnerryan -i k8shardway.yml wait_for_ssh.yml
do
  echo "waiting, then trying again"
  sleep 10
done

echo "install docker"
ansible k8snodes -i k8shardway.yml --private-key ~/.ssh/wallnerryan -m shell -b -a "apt-get update; apt-get install -y docker.io"
ansible k8snodes -i k8shardway.yml --private-key ~/.ssh/wallnerryan -m lineinfile -b -a 'dest=/etc/default/docker line="DOCKER_OPTS=--iptables=false --ip-masq=false"'
ansible k8snodes -i k8shardway.yml --private-key ~/.ssh/wallnerryan -m shell -b -a "systemctl daemon-reload; systemctl enable docker; systemctl restart docker;"
ansible k8snodes -i k8shardway.yml --private-key ~/.ssh/wallnerryan -m shell -b -a "ps ax | grep docker"

cat > ca-config.json <<EOF
{
  "signing": {
    "default": {
      "expiry": "8760h"
    },
    "profiles": {
      "kubernetes": {
        "usages": ["signing", "key encipherment", "server auth", "client auth"],
        "expiry": "8760h"
      }
    }
  }
}
EOF

cat > ca-csr.json <<EOF
{
  "CN": "Kubernetes",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "Boston",
      "O": "Kubernetes",
      "OU": "MA",
      "ST": "Massachusetts"
    }
  ]
}
EOF

cfssl gencert -initca ca-csr.json | cfssljson -bare ca

cat > admin-csr.json <<EOF
{
  "CN": "admin",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "Boston",
      "O": "system:masters",
      "OU": "Kubernetes The Hard Way",
      "ST": "Massachusetts"
    }
  ]
}
EOF

cfssl gencert \
  -ca=ca.pem \
  -ca-key=ca-key.pem \
  -config=ca-config.json \
  -profile=kubernetes \
  admin-csr.json | cfssljson -bare admin

for instance in worker-0 worker-1 worker-2; do
cat > ${instance}-csr.json <<EOF
{
  "CN": "system:node:${instance}",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "Boston",
      "O": "system:nodes",
      "OU": "Kubernetes The Hard Way",
      "ST": "Massachusetts"
    }
  ]
}
EOF

EXTERNAL_IP=$(gcloud compute instances describe ${instance} \
  --format 'value(networkInterfaces[0].accessConfigs[0].natIP)')

INTERNAL_IP=$(gcloud compute instances describe ${instance} \
  --format 'value(networkInterfaces[0].networkIP)')

cfssl gencert \
  -ca=ca.pem \
  -ca-key=ca-key.pem \
  -config=ca-config.json \
  -hostname=${instance},${EXTERNAL_IP},${INTERNAL_IP} \
  -profile=kubernetes \
  ${instance}-csr.json | cfssljson -bare ${instance}
done

cat > kube-proxy-csr.json <<EOF
{
  "CN": "system:kube-proxy",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "Boston",
      "O": "system:node-proxier",
      "OU": "Kubernetes The Hard Way",
      "ST": "Massachusetts"
    }
  ]
}
EOF

cfssl gencert \
  -ca=ca.pem \
  -ca-key=ca-key.pem \
  -config=ca-config.json \
  -profile=kubernetes \
  kube-proxy-csr.json | cfssljson -bare kube-proxy


KUBERNETES_PUBLIC_ADDRESS=$(gcloud compute addresses describe kubernetes-the-hard-way \
  --region $(gcloud config get-value compute/region) \
  --format 'value(address)')

cat > kubernetes-csr.json <<EOF
{
  "CN": "kubernetes",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "US",
      "L": "Boston",
      "O": "Kubernetes",
      "OU": "Kubernetes The Hard Way",
      "ST": "Massachusetts"
    }
  ]
}
EOF


cfssl gencert \
  -ca=ca.pem \
  -ca-key=ca-key.pem \
  -config=ca-config.json \
  -hostname=10.100.0.1,10.240.0.10,10.240.0.11,10.240.0.12,${KUBERNETES_PUBLIC_ADDRESS},127.0.0.1,kubernetes.default \
  -profile=kubernetes \
  kubernetes-csr.json | cfssljson -bare kubernetes

for instance in worker-0 worker-1 worker-2; do
  gcloud compute scp ca.pem ${instance}-key.pem ${instance}.pem ${instance}:~/
done

for instance in controller-0 controller-1 controller-2; do
  gcloud compute scp ca.pem ca-key.pem kubernetes-key.pem kubernetes.pem ${instance}:~/
done

KUBERNETES_PUBLIC_ADDRESS=$(gcloud compute addresses describe kubernetes-the-hard-way \
  --region $(gcloud config get-value compute/region) \
  --format 'value(address)')


for instance in worker-0 worker-1 worker-2; do
  kubectl config set-cluster kubernetes-the-hard-way \
    --certificate-authority=ca.pem \
    --embed-certs=true \
    --server=https://${KUBERNETES_PUBLIC_ADDRESS}:6443 \
    --kubeconfig=${instance}.kubeconfig

  kubectl config set-credentials system:node:${instance} \
    --client-certificate=${instance}.pem \
    --client-key=${instance}-key.pem \
    --embed-certs=true \
    --kubeconfig=${instance}.kubeconfig

  kubectl config set-context default \
    --cluster=kubernetes-the-hard-way \
    --user=system:node:${instance} \
    --kubeconfig=${instance}.kubeconfig

  kubectl config use-context default --kubeconfig=${instance}.kubeconfig
done


kubectl config set-cluster kubernetes-the-hard-way \
  --certificate-authority=ca.pem \
  --embed-certs=true \
  --server=https://${KUBERNETES_PUBLIC_ADDRESS}:6443 \
  --kubeconfig=kube-proxy.kubeconfig

kubectl config set-credentials kube-proxy \
  --client-certificate=kube-proxy.pem \
  --client-key=kube-proxy-key.pem \
  --embed-certs=true \
  --kubeconfig=kube-proxy.kubeconfig

kubectl config set-context default \
  --cluster=kubernetes-the-hard-way \
  --user=kube-proxy \
  --kubeconfig=kube-proxy.kubeconfig

kubectl config use-context default --kubeconfig=kube-proxy.kubeconfig

for instance in worker-0 worker-1 worker-2; do
  gcloud compute scp ${instance}.kubeconfig kube-proxy.kubeconfig ${instance}:~/
done

ENCRYPTION_KEY=$(head -c 32 /dev/urandom | base64)

cat > encryption-config.yaml <<EOF
kind: EncryptionConfig
apiVersion: v1
resources:
  - resources:
      - secrets
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: ${ENCRYPTION_KEY}
      - identity: {}
EOF

for instance in controller-0 controller-1 controller-2; do
  gcloud compute scp encryption-config.yaml ${instance}:~/
done


echo "" >> k8shardway.yml; echo "[k8scontrollers]" >> k8shardway.yml; gcloud compute instances list --regexp "^controller.*" --format=json     | jq '.[].networkInterfaces[].accessConfigs[].natIP' >> k8shardway.yml

ansible k8scontrollers -i k8shardway.yml --private-key ~/.ssh/wallnerryan -m shell -b -a "wget -q --show-progress --https-only --timestamping  'https://github.com/coreos/etcd/releases/download/v3.2.11/etcd-v3.2.11-linux-amd64.tar.gz'"

ansible k8scontrollers -i k8shardway.yml --private-key ~/.ssh/wallnerryan -m shell -b -a "tar -xvf etcd-v3.2.11-linux-amd64.tar.gz"

ansible k8scontrollers -i k8shardway.yml --private-key ~/.ssh/wallnerryan -m shell -b -a "mv etcd-v3.2.11-linux-amd64/etcd* /usr/local/bin/"

ansible k8scontrollers -i k8shardway.yml --private-key ~/.ssh/wallnerryan -m shell -b -a "mkdir -p /etc/etcd /var/lib/etcd"

ansible k8scontrollers -i k8shardway.yml --private-key ~/.ssh/wallnerryan -m shell -b -a "cp ca.pem kubernetes-key.pem kubernetes.pem /etc/etcd/"

for instance in controller-0 controller-1 controller-2; do

INTERNAL_IP=$(gcloud compute instances describe ${instance} \
  --format 'value(networkInterfaces[0].networkIP)')

cat > etcd.service.${instance} <<EOF
[Unit]
Description=etcd
Documentation=https://github.com/coreos

[Service]
ExecStart=/usr/local/bin/etcd \\
  --name ${instance} \\
  --cert-file=/etc/etcd/kubernetes.pem \\
  --key-file=/etc/etcd/kubernetes-key.pem \\
  --peer-cert-file=/etc/etcd/kubernetes.pem \\
  --peer-key-file=/etc/etcd/kubernetes-key.pem \\
  --trusted-ca-file=/etc/etcd/ca.pem \\
  --peer-trusted-ca-file=/etc/etcd/ca.pem \\
  --peer-client-cert-auth \\
  --client-cert-auth \\
  --initial-advertise-peer-urls https://${INTERNAL_IP}:2380 \\
  --listen-peer-urls https://${INTERNAL_IP}:2380 \\
  --listen-client-urls https://${INTERNAL_IP}:2379,http://127.0.0.1:2379 \\
  --advertise-client-urls https://${INTERNAL_IP}:2379 \\
  --initial-cluster-token etcd-cluster-0 \\
  --initial-cluster controller-0=https://10.240.0.10:2380,controller-1=https://10.240.0.11:2380,controller-2=https://10.240.0.12:2380 \\
  --initial-cluster-state new \\
  --data-dir=/var/lib/etcd
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

gcloud compute scp etcd.service.${instance}  ${instance}:~/etcd.service

done

ansible k8scontrollers -i k8shardway.yml --private-key ~/.ssh/wallnerryan -m shell -b -a " mv etcd.service /etc/systemd/system/etcd.service"

ansible k8scontrollers -i k8shardway.yml --private-key ~/.ssh/wallnerryan -m shell -b -a "systemctl daemon-reload"

ansible k8scontrollers -i k8shardway.yml --private-key ~/.ssh/wallnerryan -m shell -b -a "systemctl enable etcd"

ansible k8scontrollers -i k8shardway.yml --private-key ~/.ssh/wallnerryan -m shell -b -a "systemctl start etcd"

echo "sleeping after etcd install"
sleep 10

gcloud compute ssh controller-0 --command "ETCDCTL_API=3 etcdctl member list"

ansible k8scontrollers -i k8shardway.yml --private-key ~/.ssh/wallnerryan -m shell -b -a "wget -q --show-progress --https-only --timestamping https://storage.googleapis.com/kubernetes-release/release/v1.9.0/bin/linux/amd64/kube-apiserver https://storage.googleapis.com/kubernetes-release/release/v1.9.0/bin/linux/amd64/kube-controller-manager https://storage.googleapis.com/kubernetes-release/release/v1.9.0/bin/linux/amd64/kube-scheduler https://storage.googleapis.com/kubernetes-release/release/v1.9.0/bin/linux/amd64/kubectl"

ansible k8scontrollers -i k8shardway.yml --private-key ~/.ssh/wallnerryan -m shell -b -a "chmod +x kube-apiserver kube-controller-manager kube-scheduler kubectl"

ansible k8scontrollers -i k8shardway.yml --private-key ~/.ssh/wallnerryan -m shell -b -a "mv kube-apiserver kube-controller-manager kube-scheduler kubectl /usr/local/bin/"

ansible k8scontrollers -i k8shardway.yml --private-key ~/.ssh/wallnerryan -m shell -b -a "mkdir -p /var/lib/kubernetes/"

ansible k8scontrollers -i k8shardway.yml --private-key ~/.ssh/wallnerryan -m shell -b -a "mv ca.pem ca-key.pem kubernetes-key.pem kubernetes.pem encryption-config.yaml /var/lib/kubernetes/"

for instance in controller-0 controller-1 controller-2; do

INTERNAL_IP=$(gcloud compute instances describe ${instance} \
  --format 'value(networkInterfaces[0].networkIP)')

cat > kube-apiserver.service.${instance} <<EOF
[Unit]
Description=Kubernetes API Server
Documentation=https://github.com/kubernetes/kubernetes

[Service]
ExecStart=/usr/local/bin/kube-apiserver \\
  --admission-control=Initializers,NamespaceLifecycle,NodeRestriction,LimitRanger,ServiceAccount,DefaultStorageClass,ResourceQuota \\
  --advertise-address=${INTERNAL_IP} \\
  --allow-privileged=true \\
  --apiserver-count=3 \\
  --audit-log-maxage=30 \\
  --audit-log-maxbackup=3 \\
  --audit-log-maxsize=100 \\
  --audit-log-path=/var/log/audit.log \\
  --authorization-mode=Node,RBAC \\
  --bind-address=0.0.0.0 \\
  --client-ca-file=/var/lib/kubernetes/ca.pem \\
  --enable-swagger-ui=true \\
  --etcd-cafile=/var/lib/kubernetes/ca.pem \\
  --etcd-certfile=/var/lib/kubernetes/kubernetes.pem \\
  --etcd-keyfile=/var/lib/kubernetes/kubernetes-key.pem \\
  --etcd-servers=https://10.240.0.10:2379,https://10.240.0.11:2379,https://10.240.0.12:2379 \\
  --event-ttl=1h \\
  --experimental-encryption-provider-config=/var/lib/kubernetes/encryption-config.yaml \\
  --insecure-bind-address=127.0.0.1 \\
  --kubelet-certificate-authority=/var/lib/kubernetes/ca.pem \\
  --kubelet-client-certificate=/var/lib/kubernetes/kubernetes.pem \\
  --kubelet-client-key=/var/lib/kubernetes/kubernetes-key.pem \\
  --kubelet-https=true \\
  --runtime-config=api/all \\
  --service-account-key-file=/var/lib/kubernetes/ca-key.pem \\
  --service-cluster-ip-range=10.100.0.0/24 \\
  --service-node-port-range=30000-32767 \\
  --tls-ca-file=/var/lib/kubernetes/ca.pem \\
  --tls-cert-file=/var/lib/kubernetes/kubernetes.pem \\
  --tls-private-key-file=/var/lib/kubernetes/kubernetes-key.pem \\
  --v=2
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

cat > kube-controller-manager.service.${instance} <<EOF
[Unit]
Description=Kubernetes Controller Manager
Documentation=https://github.com/kubernetes/kubernetes

[Service]
ExecStart=/usr/local/bin/kube-controller-manager \\
  --address=0.0.0.0 \\
  --cluster-cidr=10.200.0.0/16 \\
  --cluster-name=kubernetes \\
  --cluster-signing-cert-file=/var/lib/kubernetes/ca.pem \\
  --cluster-signing-key-file=/var/lib/kubernetes/ca-key.pem \\
  --leader-elect=true \\
  --master=http://127.0.0.1:8080 \\
  --root-ca-file=/var/lib/kubernetes/ca.pem \\
  --service-account-private-key-file=/var/lib/kubernetes/ca-key.pem \\
  --service-cluster-ip-range=10.100.0.0/24 \\
  --v=2
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

cat > kube-scheduler.service.${instance} <<EOF
[Unit]
Description=Kubernetes Scheduler
Documentation=https://github.com/kubernetes/kubernetes

[Service]
ExecStart=/usr/local/bin/kube-scheduler \\
  --leader-elect=true \\
  --master=http://127.0.0.1:8080 \\
  --v=2
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF


gcloud compute scp kube-apiserver.service.${instance}  ${instance}:~/kube-apiserver.service
gcloud compute scp kube-controller-manager.service.${instance}   ${instance}:~/kube-controller-manager.service
gcloud compute scp kube-scheduler.service.${instance}  ${instance}:~/kube-scheduler.service

done

ansible k8scontrollers -i k8shardway.yml --private-key ~/.ssh/wallnerryan -m shell -b -a "mv kube-apiserver.service kube-scheduler.service kube-controller-manager.service /etc/systemd/system/"

ansible k8scontrollers -i k8shardway.yml --private-key ~/.ssh/wallnerryan -m shell -b -a "systemctl daemon-reload"

ansible k8scontrollers -i k8shardway.yml --private-key ~/.ssh/wallnerryan -m shell -b -a "systemctl enable kube-apiserver kube-controller-manager kube-scheduler"

ansible k8scontrollers -i k8shardway.yml --private-key ~/.ssh/wallnerryan -m shell -b -a "systemctl start kube-apiserver kube-controller-manager kube-scheduler"


echo "Sleeping after kubernetes component installation"
sleep 10
ansible k8scontrollers -i k8shardway.yml --private-key ~/.ssh/wallnerryan -m shell -b -a "kubectl get componentstatuses"

for instance in controller-0 controller-1 controller-2; do

cat > kube-apiserver-to-kublete.${instance} <<EOF
apiVersion: rbac.authorization.k8s.io/v1beta1 
kind: ClusterRole 
metadata: 
  annotations: 
    rbac.authorization.kubernetes.io/autoupdate: "true" 
  labels: 
    kubernetes.io/bootstrapping: rbac-defaults 
  name: system:kube-apiserver-to-kubelet 
rules: 
  - apiGroups: 
      - "" 
    resources: 
      - nodes/proxy 
      - nodes/stats 
      - nodes/log 
      - nodes/spec 
      - nodes/metrics 
    verbs: 
      - "*" 
EOF

gcloud compute scp kube-apiserver-to-kublete.${instance}  ${instance}:~/kube-apiserver-to-kublete.yaml

done

ansible k8scontrollers -i k8shardway.yml --private-key ~/.ssh/wallnerryan -m shell -b -a "kubectl apply -f kube-apiserver-to-kublete.yaml"

for instance in controller-0 controller-1 controller-2; do

cat > kube-apiserver-to-kublete-binding.${instance} <<EOF
apiVersion: rbac.authorization.k8s.io/v1beta1
kind: ClusterRoleBinding
metadata:
  name: system:kube-apiserver
  namespace: ""
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:kube-apiserver-to-kubelet
subjects:
  - apiGroup: rbac.authorization.k8s.io
    kind: User
    name: kubernetes
EOF

gcloud compute scp kube-apiserver-to-kublete-binding.${instance}  ${instance}:~/kube-apiserver-to-kublete-binding.yaml

done

ansible k8scontrollers -i k8shardway.yml --private-key ~/.ssh/wallnerryan -m shell -b -a " kubectl apply -f kube-apiserver-to-kublete-binding.yaml"

gcloud compute target-pools create kubernetes-target-pool


gcloud compute target-pools add-instances kubernetes-target-pool \
  --instances controller-0,controller-1,controller-2

KUBERNETES_PUBLIC_ADDRESS=$(gcloud compute addresses describe kubernetes-the-hard-way \
  --region $(gcloud config get-value compute/region) \
  --format 'value(name)')

gcloud compute forwarding-rules create kubernetes-forwarding-rule \
  --address ${KUBERNETES_PUBLIC_ADDRESS} \
  --ports 6443 \
  --region $(gcloud config get-value compute/region) \
  --target-pool kubernetes-target-pool

KUBERNETES_PUBLIC_ADDRESS=$(gcloud compute addresses describe kubernetes-the-hard-way \
  --region $(gcloud config get-value compute/region) \
  --format 'value(address)')

curl --cacert cfssl/ca.pem https://${KUBERNETES_PUBLIC_ADDRESS}:6443/version


echo "adding workers"

echo "" >> k8shardway.yml; echo "[k8sworkers]" >> k8shardway.yml; gcloud compute instances list --regexp "^worker.*" --format=json     | jq '.[].networkInterfaces[].accessConfigs[].natIP' >> k8shardway.yml

ansible k8sworkers -i k8shardway.yml --private-key ~/.ssh/wallnerryan -m shell -b -a "apt-get install -y socat"

ansible k8sworkers -i k8shardway.yml --private-key ~/.ssh/wallnerryan -m shell -b -a "wget -q --show-progress --https-only --timestamping https://github.com/containernetworking/plugins/releases/download/v0.6.0/cni-plugins-amd64-v0.6.0.tgz https://storage.googleapis.com/kubernetes-release/release/v1.9.0/bin/linux/amd64/kubectl https://storage.googleapis.com/kubernetes-release/release/v1.9.0/bin/linux/amd64/kube-proxy https://storage.googleapis.com/kubernetes-release/release/v1.9.0/bin/linux/amd64/kubelet"

ansible k8sworkers -i k8shardway.yml --private-key ~/.ssh/wallnerryan -m shell -b -a "mkdir -p /etc/cni/net.d /opt/cni/bin /var/lib/kubelet /var/lib/kube-proxy /var/lib/kubernetes /var/run/kubernetes"

ansible k8sworkers -i k8shardway.yml --private-key ~/.ssh/wallnerryan -m shell -b -a "tar -xvf cni-plugins-amd64-v0.6.0.tgz -C /opt/cni/bin/"

ansible k8sworkers -i k8shardway.yml --private-key ~/.ssh/wallnerryan -m shell -b -a "chmod +x kubectl kube-proxy kubelet"

ansible k8sworkers -i k8shardway.yml --private-key ~/.ssh/wallnerryan -m shell -b -a "mv kubectl kube-proxy kubelet /usr/local/bin/"

for instance in worker-0 worker-1 worker-2; do

POD_CIDR=$(gcloud compute instances describe ${instance} --format 'value(metadata[items][0].value)')

gcloud compute ssh ${instance} --command "sudo mv ${instance}-key.pem ${instance}.pem /var/lib/kubelet/"
gcloud compute ssh ${instance} --command "sudo mv ${instance}.kubeconfig /var/lib/kubelet/kubeconfig"
gcloud compute ssh ${instance} --command "sudo mv ca.pem /var/lib/kubernetes/"

cat > kubelet.service.${instance} <<EOF
[Unit]
Description=Kubernetes Kubelet
Documentation=https://github.com/kubernetes/kubernetes
After=docker.service
Requires=docker.service

[Service]
ExecStart=/usr/local/bin/kubelet \\
  --allow-privileged=true \\
  --anonymous-auth=false \\
  --authorization-mode=Webhook \\
  --client-ca-file=/var/lib/kubernetes/ca.pem \\
  --cloud-provider= \\
  --cluster-dns=10.100.0.10 \\
  --cluster-domain=cluster.local \\
  --image-pull-progress-deadline=2m \\
  --kubeconfig=/var/lib/kubelet/kubeconfig \\
  --network-plugin=cni \\
  --pod-cidr=${POD_CIDR} \\
  --register-node=true \\
  --runtime-request-timeout=15m \\
  --tls-cert-file=/var/lib/kubelet/${instance}.pem \\
  --tls-private-key-file=/var/lib/kubelet/${instance}-key.pem \\
  --v=2
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

gcloud compute scp kubelet.service.${instance}  ${instance}:~/kubelet.service
gcloud compute ssh ${instance} --command "sudo mv kube-proxy.kubeconfig /var/lib/kube-proxy/kubeconfig"

cat > kube-proxy.service.${instance} <<EOF
[Unit]
Description=Kubernetes Kube Proxy
Documentation=https://github.com/kubernetes/kubernetes

[Service]
ExecStart=/usr/local/bin/kube-proxy \\
  --cluster-cidr=10.200.0.0/16 \\
  --kubeconfig=/var/lib/kube-proxy/kubeconfig \\
  --proxy-mode=iptables \\
  --v=2
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

gcloud compute scp kube-proxy.service.${instance} ${instance}:~/kube-proxy.service
gcloud compute ssh ${instance} --command "sudo mv kubelet.service kube-proxy.service /etc/systemd/system/"

done

ansible k8sworkers -i k8shardway.yml --private-key ~/.ssh/wallnerryan -m shell -b -a "systemctl daemon-reload"

ansible k8sworkers -i k8shardway.yml --private-key ~/.ssh/wallnerryan -m shell -b -a "systemctl enable docker kubelet kube-proxy"

ansible k8sworkers -i k8shardway.yml --private-key ~/.ssh/wallnerryan -m shell -b -a "systemctl start docker kubelet kube-proxy"

echo "sleeping to let workers come online"
sleep 5

gcloud compute ssh controller-0 --command "kubectl get nodes"

echo "Setting up remote access for kubectl"
KUBERNETES_PUBLIC_ADDRESS=$(gcloud compute addresses describe kubernetes-the-hard-way \
  --region $(gcloud config get-value compute/region) \
  --format 'value(address)')

kubectl config set-cluster kubernetes-the-hard-way \
  --certificate-authority=ca.pem \
  --embed-certs=true \
  --server=https://${KUBERNETES_PUBLIC_ADDRESS}:6443

kubectl config set-credentials admin \
  --client-certificate=admin.pem \
  --client-key=admin-key.pem

kubectl config set-context kubernetes-the-hard-way \
  --cluster=kubernetes-the-hard-way \
  --user=admin

kubectl config use-context kubernetes-the-hard-way
kubectl config view
kubectl get no

echo "Use kubctl locally to interact with the cluster."
echo "Use ./cleanup-gcpk8s-cluster.sh to cleanup"

