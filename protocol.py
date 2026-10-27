"""
protocol.py
-----------
Shared helper module for JSON-over-TCP messaging.
Used by kdc_server.py, alice.py, and bob.py to send and receive
newline-delimited JSON messages over TCP sockets.
"""

import json
import socket


def send_msg(sock: socket.socket, data: dict) -> None:
    """Send a JSON-serialised dict over a socket, delimited by a newline.

    Args:
        sock: An open, connected TCP socket.
        data: A Python dict that will be JSON-serialised and sent.
    """
    msg = json.dumps(data) + '\n'
    sock.sendall(msg.encode('utf-8'))


def recv_msg(sock: socket.socket) -> dict:
    """Receive a newline-delimited JSON message from a socket.

    Blocks until a full newline-terminated message is received.

    Args:
        sock: An open, connected TCP socket.

    Returns:
        The parsed Python dict from the JSON message.

    Raises:
        ConnectionError: If the remote side closes the connection mid-receive.
    """
    buf = b''
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Connection closed by remote host")
        buf += chunk
        if b'\n' in buf:
            line, _ = buf.split(b'\n', 1)
            return json.loads(line.decode('utf-8'))
