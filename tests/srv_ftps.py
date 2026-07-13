#!/usr/bin/env python3
"""Local FTPS (explicit TLS) test server for gmacFTP, using pyftpdlib.

Configurable via env so a single script can serve MANY instances (e.g. FTP→FTP relay
testing between two distinct local servers — a safe substitute for real hosts):
  MACKFTP_FTP_PORT  default 2210
  MACKFTP_FTP_ROOT  default /tmp/mackftp_ftpd
  MACKFTP_FTP_USER  default testuser
  MACKFTP_FTP_PASS  default testpass

Standalone:  python3 tests/srv_ftps.py
Pair:        see tests/run-test-servers.sh
"""
import os
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import TLS_FTPHandler
from pyftpdlib.servers import FTPServer

PORT = int(os.environ.get("MACKFTP_FTP_PORT", "2210"))
ROOT = os.environ.get("MACKFTP_FTP_ROOT", "/tmp/mackftp_ftpd")
USER = os.environ.get("MACKFTP_FTP_USER", "testuser")
PASS = os.environ.get("MACKFTP_FTP_PASS", "testpass")
CERT = os.environ.get("MACKFTP_FTP_CERT", "/tmp/mackftp_ftps.pem")

os.makedirs(ROOT, exist_ok=True)

auth = DummyAuthorizer()
auth.add_user(USER, PASS, ROOT, perm="elradfmwMT")  # full read/write + mkdir

handler = TLS_FTPHandler
handler.authorizer = auth
handler.certfile = CERT
handler.passive_ports = range(50100, 50200)
handler.masquerade_address = "127.0.0.1"

server = FTPServer(("127.0.0.1", PORT), handler)
server.max_cons = 20
print(f"FTPS server on 127.0.0.1:{PORT}  user={USER} pass={PASS}  root={ROOT}  (AUTH TLS)")
server.serve_forever()
