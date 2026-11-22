"""Reads one stats snapshot from srtla_send's control socket (JSON-RPC, one message per line):
subscribes to "stats" and prints the first stats.update's data. Falls back to get_stats.

Usage: python3 -I srtla_stats.py SOCKET
"""

import json
import socket
import sys

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.settimeout(5)
sock.connect(sys.argv[1])
stream = sock.makefile("rw")
stream.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "subscribe",
                         "params": {"topic": "stats"}}) + "\n")
stream.flush()
for _ in range(20):
    message = json.loads(stream.readline())
    if message.get("method") == "stats.update":
        print(json.dumps(message["params"]["data"]))
        sys.exit(0)
stream.write(json.dumps({"jsonrpc": "2.0", "id": 2, "method": "get_stats"}) + "\n")
stream.flush()
print(json.dumps(json.loads(stream.readline()).get("result")))
