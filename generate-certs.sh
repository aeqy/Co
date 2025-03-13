#!/bin/bash
set -eo pipefail

CERT_DIR="./certs"
PASSWORD="YourStrongPass!2024"

mkdir -p ${CERT_DIR}

openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout "${CERT_DIR}/co.key" \
  -out "${CERT_DIR}/co.crt" \
  -days 3650 \
  -subj "/C=CN/ST=Shanghai/L=Shanghai/O=Co/OU=Dev/CN=co.local" \
  -addext "subjectAltName=DNS:co.local,DNS:*.co.local,IP:127.0.0.1"

openssl pkcs12 -export \
  -inkey "${CERT_DIR}/co.key" \
  -in "${CERT_DIR}/co.crt" \
  -out "${CERT_DIR}/co.pfx" \
  -passout pass:"${PASSWORD}"

echo "证书生成完成！"
chmod 600 ${CERT_DIR}/*
