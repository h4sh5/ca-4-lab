#!/usr/bin/env python3
"""Unpack the public eMudhra certificate material into certs/.

Input (in dist/ - fetched by fetch-certs.sh):
    impacted-intermediates.json  16 certs: 8 weak keys, each issued twice
                                 (once by eMudhra, once by Sectigo/AAA)
    roots.json                   the 3 issuing roots + the cross-signer
    chains.zip                   real chains as served on the test hosts
                                 (carries the cross-signed roots we need)

Output (certs/):
    em-dv-tls-ca-g3b.pem ...             the weak eMudhra-issued intermediates
    aaa/em-dv-tls-ca-g3b.pem ...         the same keys, Sectigo (AAA) issued
    issuers/emsign-root-tls-ca-g3.cross.pem   root TLS CA - G3, cross-signed
                                              by emSign ECC Root CA - G3
    issuers/emsign-root-cs-ca-g3.cross.pem    same for the CS root (if present)
    issuers/emsign-ecc-root-ca-g3.pem    the still-included trust anchor
    issuers/aaa-certificate-services.pem the Comodo/Sectigo trust anchor
"""
import json
import os
import re
import subprocess
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.join(HERE, "dist")
CERTS = os.path.join(HERE, "certs")


def slug(name):
    """'EM DV TLS CA - G3B' -> 'em-dv-tls-ca-g3b'"""
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def pem_certs(text):
    return re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----\n",
                      text, re.S)


def write(path, pemtext):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(pemtext if pemtext.endswith("\n") else pemtext + "\n")
    print(os.path.relpath(path, HERE))


def main():
    inters = json.load(open(os.path.join(DIST, "impacted-intermediates.json")))
    roots = json.load(open(os.path.join(DIST, "roots.json")))

    for e in inters:
        s = slug(e["name"])
        if e["issuer_operator"] == "eMudhra":
            write(os.path.join(CERTS, f"{s}.pem"), e["pem"])
        else:                                    # Sectigo / AAA Certificate Services
            write(os.path.join(CERTS, "aaa", f"{s}.pem"), e["pem"])

    for r in roots:
        n = r["name"]
        if n == "emSign ECC Root CA - G3":
            write(os.path.join(CERTS, "issuers", "emsign-ecc-root-ca-g3.pem"), r["pem"])
        elif n == "AAA Certificate Services":
            write(os.path.join(CERTS, "issuers", "aaa-certificate-services.pem"), r["pem"])
        elif n == "emSign Root CS CA - G3":
            write(os.path.join(CERTS, "issuers", "emsign-root-cs-ca-g3.self.pem"), r["pem"])

    # The cross-signed copies of the eMudhra roots only appear inside the real
    # chains captured from the test hosts (cert #3 of each file).
    with zipfile.ZipFile(os.path.join(DIST, "chains.zip")) as z:
        seen = set()
        for n in z.namelist():
            if not n.endswith(".pem") or "-aaa-" in n:
                continue
            certs = pem_certs(z.read(n).decode())
            for c in certs[1:]:                  # skip the test-host leaf
                subj = subprocess.run(
                    ["openssl", "x509", "-noout", "-subject", "-issuer"],
                    input=c, capture_output=True, text=True).stdout
                if "emSign Root TLS CA - G3" in subj and "subject=C=IN, O=eMudhra Technologies Limited, CN=emSign Root TLS CA - G3" in subj:
                    key = "emsign-root-tls-ca-g3.cross.pem"
                elif "emSign Root CS CA - G3" in subj and "subject=C=IN, O=eMudhra Technologies Limited, CN=emSign Root CS CA - G3" in subj:
                    key = "emsign-root-cs-ca-g3.cross.pem"
                else:
                    continue
                if key not in seen:
                    seen.add(key)
                    write(os.path.join(CERTS, "issuers", key), c)


if __name__ == "__main__":
    main()
