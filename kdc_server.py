import os
import sys
import socket
import threading
import secrets
import string

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from protocol import send_msg, recv_msg
from crypto.aes_wrapper import encrypt

MASTER_KEYS = {}
KS_CHARS = ''.join(c for c in string.printable[:94] if c != '|')


def gen_session_key(n=16):
    return ''.join(secrets.choice(KS_CHARS) for _ in range(n))


def handle(conn, addr):
    peer = f"{addr[0]}:{addr[1]}"
    print(f"[KDC] connection from {peer}")
    try:
        while True:
            try:
                msg = recv_msg(conn)
            except Exception:
                print(f"[KDC] {peer} disconnected")
                break

            if msg.get("type") != "key_request":
                print(f"[KDC] unexpected type from {peer}: {msg.get('type')}")
                continue

            id_a = msg.get("id_a", "")
            id_b = msg.get("id_b", "")
            n1   = msg.get("n1", "")
            print(f"[KDC] step 1 from {id_a}: requesting key for {id_a}<->{id_b}, N1={n1}")

            if id_a not in MASTER_KEYS:
                send_msg(conn, {"type": "error", "message": f"unknown principal: {id_a}"})
                continue
            if id_b not in MASTER_KEYS:
                send_msg(conn, {"type": "error", "message": f"unknown principal: {id_b}"})
                continue

            ka = MASTER_KEYS[id_a]
            kb = MASTER_KEYS[id_b]
            ks = gen_session_key()
            print(f"[KDC] generated Ks={ks!r}")

            ct_a, nonce_a = encrypt(f"{ks}|{id_a}|{id_b}|{n1}", ka)
            ct_b, nonce_b = encrypt(f"{ks}|{id_a}", kb)

            print(f"[KDC] payload_a (hex): {ct_a}")
            print(f"[KDC] payload_b (hex): {ct_b}")

            send_msg(conn, {
                "type":      "key_response",
                "payload_a": ct_a,
                "nonce_a":   nonce_a,
                "payload_b": ct_b,
                "nonce_b":   nonce_b,
            })
            print(f"[KDC] step 2 sent to {id_a}")
    finally:
        conn.close()


def main():
    print("[KDC] AES-KDC Server")
    ka = input("Ka (Alice master key): ").strip()
    kb = input("Kb (Bob master key)  : ").strip()
    if not ka or not kb:
        print("[KDC] keys cannot be empty")
        sys.exit(1)

    MASTER_KEYS["Alice"] = ka
    MASTER_KEYS["Bob"]   = kb

    port_in = input("Port [8888]: ").strip()
    port = int(port_in) if port_in.isdigit() else 8888

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(10)
    print(f"[KDC] listening on 0.0.0.0:{port}")

    try:
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=handle, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\n[KDC] shutting down")
    finally:
        srv.close()


if __name__ == "__main__":
    main()
