#!/usr/bin/env bash
set -Eeuo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
secrets_dir="$root/secrets"
mkdir -p "$secrets_dir"

for required in openssl; do
  command -v "$required" >/dev/null 2>&1 || { echo "$required is required" >&2; exit 1; }
done

protected=(ca.key ca.crt postgres_password.txt keycloak_admin_password.txt)
for file in "${protected[@]}"; do
  if [[ -e "$secrets_dir/$file" ]]; then
    echo "Refusing to overwrite existing staging secret: $file" >&2
    exit 1
  fi
done

openssl rand -base64 32 > "$secrets_dir/postgres_password.txt"
openssl rand -base64 32 > "$secrets_dir/keycloak_admin_password.txt"
openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 30 \
  -subj "/CN=AAK Staging CA" -keyout "$secrets_dir/ca.key" -out "$secrets_dir/ca.crt"

issue() {
  local name="$1" san="$2" usage="$3"
  openssl req -newkey rsa:3072 -sha256 -nodes -subj "/CN=$name" \
    -keyout "$secrets_dir/$name.key" -out "$secrets_dir/$name.csr"
  {
    echo "subjectAltName=$san"
    echo "extendedKeyUsage=$usage"
  } > "$secrets_dir/$name.ext"
  openssl x509 -req -sha256 -days 30 -in "$secrets_dir/$name.csr" \
    -CA "$secrets_dir/ca.crt" -CAkey "$secrets_dir/ca.key" -CAcreateserial \
    -extfile "$secrets_dir/$name.ext" -out "$secrets_dir/$name.crt"
}

issue opa "DNS:opa,URI:spiffe://aak/opa" "serverAuth"
issue gateway "DNS:gateway,URI:spiffe://aak/gateway" "clientAuth,serverAuth"
issue resource "DNS:resource,URI:spiffe://aak/resource" "clientAuth,serverAuth"
issue broker "DNS:broker,URI:spiffe://aak/broker" "clientAuth,serverAuth"
issue audit "DNS:audit,URI:spiffe://aak/audit" "clientAuth,serverAuth"

mv "$secrets_dir/opa.crt" "$secrets_dir/opa_tls.crt"
mv "$secrets_dir/opa.key" "$secrets_dir/opa_tls.key"
rm -f "$secrets_dir"/*.csr "$secrets_dir"/*.ext "$secrets_dir"/*.srl
chmod 600 "$secrets_dir"/*.key "$secrets_dir"/*.txt
echo "Created staging-only credentials in deploy/staging/secrets. Do not commit them."
