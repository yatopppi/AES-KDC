import os
import sys
import socket
import threading
import secrets
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from protocol import send_msg, recv_msg
from crypto.aes_wrapper import encrypt, decrypt


def xor_0xff(data):
    return bytes(b ^ 0xFF for b in data)


def receiver(sock, ks_ref, stop):
    while not stop.is_set():
        try:
            msg = recv_msg(sock)
        except Exception:
            if not stop.is_set():
                print("\n[Bob] connection lost")
                stop.set()
            return

        t = msg.get("type")
        if t == "message":
            try:
                pt = decrypt(msg["payload"], ks_ref[0], msg["nonce"])
                print(f"\n[Alice] {pt}")
                print("[Bob] > ", end="", flush=True)
            except Exception:
                print("\n[Bob] decrypt error")
                print("[Bob] > ", end="", flush=True)
        elif t == "setkey":
            try:
                new_ks = decrypt(msg["payload"], ks_ref[0], msg["nonce"])
                ks_ref[0] = new_ks
                print(f"\n[Bob] session key changed by Alice: {new_ks!r}")
                print("[Bob] > ", end="", flush=True)
            except Exception:
                print("\n[Bob] setkey error")
                print("[Bob] > ", end="", flush=True)


def chat(sock, ks_ref):
    stop = threading.Event()
    threading.Thread(target=receiver, args=(sock, ks_ref, stop), daemon=True).start()

    print("[Bob] chat ready. commands: setkey, quit")
    while not stop.is_set():
        try:
            line = input("[Bob] > ").strip()
        except (EOFError, KeyboardInterrupt):
            break

        if stop.is_set():
            break

        if line == "quit":
            break

        if line == "setkey":
            new_ks = input("[Bob] new session key: ").strip()
            if not new_ks:
                continue
            try:
                ct, nonce = encrypt(new_ks, ks_ref[0])
                send_msg(sock, {"type": "setkey", "payload": ct, "nonce": nonce})
                ks_ref[0] = new_ks
                print(f"[Bob] session key updated: {new_ks!r}")
            except Exception as e:
                print(f"[Bob] setkey failed: {e}")
            continue

        if not line:
            continue

        try:
            ct, nonce = encrypt(line, ks_ref[0])
            send_msg(sock, {"type": "message", "payload": ct, "nonce": nonce})
            print(f"[Bob] sent (hex): {ct}")
        except Exception as e:
            print(f"[Bob] send failed: {e}")

    stop.set()


def handle_session(alice_sock, kb):
    try:
        ticket = recv_msg(alice_sock)
    except Exception as e:
        print(f"[Bob] receive ticket error: {e}")
        return

    if ticket.get("type") != "ticket":
        print(f"[Bob] expected ticket, got {ticket.get('type')}")
        return

    try:
        plain_b = decrypt(ticket["payload_b"], kb, ticket["nonce_b"])
    except Exception as e:
        print(f"[Bob] decrypt ticket failed (wrong Kb?): {e}")
        return

    parts = plain_b.split("|")
    if len(parts) != 2:
        print(f"[Bob] unexpected ticket format: {plain_b!r}")
        return

    ks, ida = parts
    print(f"[Bob] step 3 ok. Ks={ks!r}, IDA={ida}")
    print(f"[Bob] payload_b (hex): {ticket['payload_b']}")

    n2 = secrets.token_bytes(8)
    n2_hex = n2.hex()
    ct, nonce = encrypt(n2_hex, ks)
    send_msg(alice_sock, {"type": "challenge", "payload": ct, "nonce": nonce})
    print(f"[Bob] step 4 sent. N2={n2_hex}")

    try:
        cr = recv_msg(alice_sock)
    except Exception as e:
        print(f"[Bob] receive challenge_response error: {e}")
        return

    if cr.get("type") != "challenge_response":
        print(f"[Bob] expected challenge_response, got {cr.get('type')}")
        return

    try:
        recv_fn2 = decrypt(cr["payload"], ks, cr["nonce"])
    except Exception as e:
        print(f"[Bob] decrypt challenge_response failed: {e}")
        return

    expected = xor_0xff(n2).hex()
    if recv_fn2 != expected:
        print(f"[Bob] authentication failed. f(N2) mismatch")
        print(f"[Bob] expected={expected}, got={recv_fn2}")
        return

    print(f"[Bob] step 5 ok. Authentication successful.")

    chat(alice_sock, [ks])


def main():
    print("[Bob] AES-KDC Client")
    kb = input("Kb (Bob master key): ").strip()
    if not kb:
        print("[Bob] key required")
        sys.exit(1)

    bob_port_in = input("Bob port [9999]: ").strip()
    bob_port = int(bob_port_in) if bob_port_in.isdigit() else 9999

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", bob_port))
    srv.listen(5)
    print(f"[Bob] listening on 0.0.0.0:{bob_port}")

    try:
        while True:
            print("[Bob] waiting for Alice...")
            try:
                alice_sock, addr = srv.accept()
            except Exception as e:
                print(f"[Bob] accept error: {e}")
                time.sleep(1)
                continue

            print(f"[Bob] Alice connected from {addr[0]}:{addr[1]}")
            try:
                handle_session(alice_sock, kb)
            except Exception as e:
                print(f"[Bob] session error: {e}")
            finally:
                alice_sock.close()
            print("[Bob] session ended, waiting for next connection")
    except KeyboardInterrupt:
        print("\n[Bob] bye")
    finally:
        srv.close()


if __name__ == "__main__":
    main()
