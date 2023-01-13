function generate_kubelet_tls_certs() {
    # generate kubelet tls openssl.cnf
    cat <<EOF | tee ${kubelet_tls_openssl_file}
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
[req_distinguished_name]
[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = kubernetes
DNS.2 = kubernetes.default
DNS.3 = kubernetes.default.svc
DNS.4 = kubernetes.default.svc.cluster
DNS.5 = kubernetes.default.svc.cluster.local
IP.1 = ${host_ip_address}
EOF

    # generate kubelet tls certs
    kubelet_tls_key_file="${kubernetes_config_dir}/pki/kubelet-tls.key"
    kubelet_tls_cert_file="${kubernetes_config_dir}/pki/kubelet-tls.crt"
    kubelet_tls_csr_file="${kubernetes_config_dir}/pki/kubelet-tls.csr"
    kubelet_ca_key_file="certs/kubelet-ca.key"
    kubelet_ca_cert_file="certs/kubelet-ca.crt"

    openssl genrsa -out ${kubelet_tls_key_file} 2048

    openssl req -new -key ${kubelet_tls_key_file} -out ${kubelet_tls_csr_file} -subj "/CN=kubernetes/O=k8s" -config ${kubelet_tls_openssl_file}

    openssl x509 -req -in ${kubelet_tls_csr_file} -CA ${kubelet_ca_cert_file} -CAkey ${kubelet_ca_key_file} -CAcreateserial -out ${kubelet_tls_cert_file} \
        -days 36135 -extensions v3_req -extfile ${kubelet_tls_openssl_file}
}

kubelet_tls_openssl_file="config"
kubernetes_config_dir="./"
host_ip_address=${NODE_IP-"196.168.0.1"}
generate_kubelet_tls_certs