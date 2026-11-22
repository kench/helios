"""A stand-in for Helios's publish hook (LLD 4, section 4.3), for the stream harness.

Records every call nginx makes as a JSON line and answers like Helios will: 403 without the
token, 200 for the key "ingest" (and "ingest-<n>"), 403 for any other key.

Usage: python3 -I hook.py PORT TOKEN LOG_FILE
"""

import json
import re
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

PORT, TOKEN, LOG = int(sys.argv[1]), sys.argv[2], sys.argv[3]
KEY = re.compile(r"^ingest(-[1-9][0-9]*)?$")


class Hook(BaseHTTPRequestHandler):
    def do_POST(self):
        url = urlsplit(self.path)
        body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
        form = parse_qs(body)
        authorized = parse_qs(url.query).get("token") == [TOKEN]
        name = form.get("name", [""])[0]
        accept = authorized and (url.path != "/rtmp/publish" or bool(KEY.match(name)))
        with open(LOG, "a") as log:
            log.write(json.dumps({"path": url.path, "form": form, "authorized": authorized,
                                  "accepted": accept, "name": name}) + "\n")
        self.send_response(200 if accept else 403)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


HTTPServer(("127.0.0.1", PORT), Hook).serve_forever()
