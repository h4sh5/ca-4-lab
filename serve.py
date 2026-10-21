#!/usr/bin/env python3
"""http.server over TLS, with the certificate recovered from a weak eMudhra CA.

This is just http.server plus an SSLContext.  The interesting part is what it
loads: a leaf for the requested domain, signed with the CA *private key* that
was rebuilt from the leaked `d`, and the real intermediate + cross-signed root
so the client can build a path to a root it already trusts.

    ./serve.py --domain localhost --port 8443 \
               --cert out/localhost.dv-g3b/chain.pem --key out/localhost.dv-g3b/leaf.key

Plain HTTP still works if you leave out --cert/--key.

Two things it also does:

  --dir DIR        what to serve from (default: ./www next to this script)
  --upstream URL   act as a reverse proxy to another web server instead of
                   serving files, e.g. --upstream http://localhost:8000.
                   /json and /status are always answered locally so you can
                   still ask the TLS server who it is.
"""
import argparse
import http.client
import http.server
import json
import os
import socket
import ssl
import sys
import urllib.parse

DEFAULT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "www")

# hop-by-hop headers (RFC 7230 6.1): must not be forwarded either way
HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate",
              "proxy-authorization", "te", "trailer", "transfer-encoding",
              "upgrade"}


class Upstream:
    """Where --upstream points, plus a connection factory."""

    def __init__(self, url, insecure=False, timeout=30.0):
        p = urllib.parse.urlsplit(url if "//" in url else "http://" + url)
        if p.scheme not in ("http", "https"):
            raise ValueError(f"unsupported upstream scheme: {p.scheme!r}")
        self.secure = p.scheme == "https"
        self.host = p.hostname
        self.port = p.port or (443 if self.secure else 80)
        self.prefix = p.path.rstrip("/")
        self.insecure = insecure
        self.timeout = timeout
        if not self.host:
            raise ValueError("--upstream needs a host, e.g. http://localhost:8000")

    def connect(self):
        ctx = None
        if self.secure:
            ctx = ssl.create_default_context()
            if self.insecure:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
        if self.secure:
            conn = http.client.HTTPSConnection(self.host, self.port,
                                               timeout=self.timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(self.host, self.port,
                                             timeout=self.timeout)
        return conn

    def __str__(self):
        return "%s://%s:%d%s" % ("https" if self.secure else "http",
                                 self.host, self.port, self.prefix or "")


class Handler(http.server.SimpleHTTPRequestHandler):
    """Static files from --dir, or a reverse proxy to --upstream."""

    server_name = None
    subject = None
    issuer = None
    not_after = None
    san = None
    chain_files = None
    root = None
    upstream = None          # Upstream, or None for plain static serving
    preserve_host = False

    def _info(self):
        return {
            "served_by": "python3 http.server (tls)",
            "domain": type(self).server_name,
            "root": type(self).root,
            "upstream": str(type(self).upstream) if type(self).upstream else None,
            "leaf_subject": type(self).subject,
            "leaf_issuer": type(self).issuer,
            "leaf_san": type(self).san,
            "leaf_not_after": type(self).not_after,
            "chain_sent": type(self).chain_files,
            "client": "%s:%s" % self.client_address[:2],
            "request": self.command + " " + self.path,
            "python_version": sys.version.split()[0],
            "openssl_version": ssl.OPENSSL_VERSION,
        }

    def _send(self, body, ctype, status=200):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    # ------------------------------------------------------ local endpoints
    def _local(self):
        """/json and /status are answered by us even when proxying."""
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        if path not in ("/json", "/status"):
            return False
        info = self._info()
        if path == "/json":
            self._send(json.dumps(info, indent=2) + "\n", "application/json")
            return True
        rows = "".join(f"<tr><td><b>{k}</b></td><td>{v}</td></tr>\n"
                       for k, v in info.items())
        self._send(
            "<html><head><title>emudhra weak-ca</title></head><body>"
            "<h2>TLS handshake OK - you did not need <code>-k</code></h2>"
            f"<table cellpadding=3>{rows}</table></body></html>\n",
            "text/html; charset=utf-8")
        return True

    def do_GET(self):
        if self._local():
            return
        if type(self).upstream:
            self._proxy()
        else:
            super().do_GET()

    def do_HEAD(self):
        if self._local():
            return
        if type(self).upstream:
            self._proxy()
        else:
            super().do_HEAD()

    def _other(self):
        if type(self).upstream:
            self._proxy()
        else:
            self._send(f"{self.command} not implemented (no --upstream)\n",
                       "text/plain; charset=utf-8", status=501)

    do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = _other

    # ---------------------------------------------------------- proxying
    def _proxy(self):
        up = type(self).upstream
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else None
        hdrs = {k: v for k, v in self.headers.items()
                if k.lower() not in HOP_BY_HOP and k.lower() != "host"}
        orig_host = self.headers.get("Host")
        hdrs["Host"] = (orig_host if (type(self).preserve_host and orig_host)
                        else "%s%s" % (up.host,
                                       "" if up.port in (80, 443) else ":%d" % up.port))
        peer = self.client_address[0]
        xff = hdrs.get("X-Forwarded-For")
        hdrs["X-Forwarded-For"] = f"{xff}, {peer}" if xff else peer
        hdrs["X-Forwarded-Proto"] = ("https" if getattr(self.connection, "version", None)
                                     else "http")
        hdrs["X-Forwarded-Host"] = orig_host or hdrs["Host"]
        target = up.prefix + self.path

        conn = getattr(self, "_up_conn", None) or up.connect()
        for attempt in (1, 2):
            try:
                conn.request(self.command, target, body=body, headers=hdrs)
                resp = conn.getresponse()
                break
            except (http.client.HTTPException, OSError) as exc:
                try:
                    conn.close()
                except Exception:
                    pass
                if attempt == 2:
                    self._send(f"502 Bad Gateway - upstream {up} "
                               f"({type(exc).__name__}: {exc})\n",
                               "text/plain; charset=utf-8", status=502)
                    return
                conn = up.connect()
        self._up_conn = conn

        data = b"" if self.command == "HEAD" else resp.read()
        cl = resp.getheader("Content-Length") if self.command == "HEAD" else None
        self.send_response(resp.status)
        for k, v in resp.getheaders():
            kl = k.lower()
            if kl in HOP_BY_HOP or kl in ("content-length", "server", "date"):
                continue   # send_response/end_headers supply our own server+date
            self.send_header(k, v)
        self.send_header("Content-Length", cl if cl is not None else str(len(data)))
        self.send_header("X-Proxied-By", "serve.py")
        self.end_headers()
        if data:
            self.wfile.write(data)

    def finish(self):
        conn = getattr(self, "_up_conn", None)
        if conn:
            try:
                conn.close()
            except Exception:
                pass
        super().finish()

    def handle_one_request(self):
        # A client that rejects the certificate disappears in the middle of the
        # exchange (TLS alert, then gone).  That is expected, not a bug.
        try:
            super().handle_one_request()
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError, OSError) as exc:
            self.close_connection = True
            sys.stderr.write(f"  [server] client went away: {type(exc).__name__}\n")

    def log_message(self, fmt, *args):
        peer = "%s:%s" % self.client_address[:2]
        tls = getattr(self.connection, "version", lambda: "plaintext")()
        sys.stderr.write(f"  [server] {peer} {tls or ''} "
                         f"{fmt % args}\n".rstrip() + "\n")


class Server(http.server.ThreadingHTTPServer):
    """One line per problem instead of a traceback."""
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        import traceback
        exc = sys.exc_info()[1]
        if isinstance(exc, (BrokenPipeError, ConnectionResetError, ssl.SSLError, OSError)):
            sys.stderr.write(f"  [server] {client_address[0]}: "
                             f"{type(exc).__name__} (client went away)\n")
        else:
            traceback.print_exc()


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--domain", default="localhost",
                    help="name this server is answering for (banner only)")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--address", default="0.0.0.0")
    ap.add_argument("--dir", "--directory", "-d", default=DEFAULT_DIR,
                    help="directory to serve (default: %(default)s)")
    ap.add_argument("--upstream", metavar="URL",
                    help="reverse proxy everything (except /json and /status) "
                         "to this web server, e.g. http://localhost:8000")
    ap.add_argument("--preserve-host", action="store_true",
                    help="with --upstream: forward the original Host header "
                         "(default: the upstream host, for plain vhost servers)")
    ap.add_argument("--insecure-upstream", action="store_true",
                    help="with --upstream https://...: do not verify the backend cert")
    ap.add_argument("--cert", help="leaf certificate followed by the chain (PEM)")
    ap.add_argument("--key", help="leaf private key (PEM)")
    ap.add_argument("--cafile", help="client CA to require (optional, mTLS off by default)")
    ap.add_argument("--list-certs", action="store_true",
                    help="print what --cert contains and exit")
    a = ap.parse_args()

    if bool(a.cert) != bool(a.key):
        ap.error("--cert and --key go together")
    a.dir = os.path.abspath(os.path.expanduser(a.dir))
    if a.list_certs:
        if not a.cert:
            ap.error("--list-certs needs --cert")
        import subprocess
        p = subprocess.run("openssl crl2pkcs7 -nocrl -certfile '%s'"
                           " | openssl pkcs7 -print_certs -noout" % a.cert,
                           shell=True, capture_output=True, text=True)
        print("%s contains:" % a.cert)
        print((p.stdout or p.stderr).strip())
        return
    upstream = None
    if a.upstream:
        try:
            upstream = Upstream(a.upstream, insecure=a.insecure_upstream)
        except ValueError as exc:
            ap.error(str(exc))

    def cert_details(path):
        """Leaf subject/issuer/SAN/expiry via openssl, no python crypto needed.

        Handles both ``subject=CN=x`` style lines and extension blocks whose
        value continues on the following (indented) line, as -ext does.
        """
        import subprocess
        out = subprocess.run(["openssl", "x509", "-in", path, "-noout",
                              "-subject", "-issuer", "-enddate", "-ext",
                              "subjectAltName"],
                             capture_output=True, text=True)
        d, last = {}, None
        for line in out.stdout.splitlines():
            if not line.strip():
                continue
            if line[:1] in (" ", "\t"):            # continuation of an extension
                if last:
                    d[last] = (d[last] + ", " + line.strip()).strip(", ")
                continue
            key, sep, val = line.partition("=")
            if not sep:
                key, _, val = line.partition(":")
            key = key.strip()
            d[key] = val.strip()
            last = key if _is_san(key) else None
        return d

    def _is_san(key):
        k = (key or "").lower()
        return "alternative name" in k or "subjectaltname" in k

    def count_certs(path):
        n = 0
        with open(path) as fh:
            txt = fh.read()
        start, end = "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----"
        while end in txt:
            txt = txt.split(end, 1)[1]
            n += 1
        return n

    Handler.server_name = a.domain
    Handler.root = a.dir
    Handler.upstream = upstream
    Handler.preserve_host = a.preserve_host
    if a.cert:
        d = cert_details(a.cert)
        Handler.subject = d.get("subject")
        Handler.issuer = d.get("issuer")
        Handler.not_after = d.get("notAfter")
        Handler.san = next((v for k, v in d.items() if _is_san(k)), None)
        Handler.chain_files = f"{count_certs(a.cert)} certificate(s): leaf + intermediates"

    server = Server((a.address, a.port),
                    lambda *args: Handler(*args, directory=a.dir))

    scheme = "http"
    if a.cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile=a.cert, keyfile=a.key)
        if a.cafile:
            ctx.load_verify_locations(cafile=a.cafile)
            ctx.verify_mode = ssl.CERTOptional
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        scheme = "https"

    print(f"  [server] {scheme}://{a.domain}:{a.port}/  "
          f"(pid {os.getpid()}, {ssl.OPENSSL_VERSION})")
    if a.cert:
        print(f"  [server] key   {a.key}")
        print(f"  [server] chain {a.cert} ({Handler.chain_files})")
    if upstream:
        print(f"  [server] reverse proxy  ->  {upstream}")
        print(f"  [server] listening on {a.address}:{a.port} "
              f"(/json and /status answered here), Ctrl-C to stop", flush=True)
    else:
        if not os.path.isdir(a.dir):
            sys.stderr.write(f"  [server] warning: {a.dir} does not exist, "
                             f"/ will 404\n")
        print(f"  [server] serving {a.dir} on {a.address}:{a.port}, Ctrl-C to stop",
              flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
