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


def connect_retry(host, port, label):
    while True:
        try:
            sock = socket.create_connection((host, port))
            print(f"[Alice] connected to {label}")
            return sock
        except Exception:
            print(f"[Alice] waiting for {label} at {host}:{port}...")
            time.sleep(2)


def receiver(sock, ks_ref, stop):
    while not stop.is_set():
        try:
            msg = recv_msg(sock)
        except Exception:
            if not stop.is_set():
                print("\n[Alice] connection lost")
                stop.set()
            return

        t = msg.get("type")
        if t == "message":
            try:
                pt = decrypt(msg["payload"], ks_ref[0], msg["nonce"])
                print(f"\n[Bob] {pt}")
                print("[Alice] > ", end="", flush=True)
            except Exception:
                print("\n[Alice] decrypt error")
                print("[Alice] > ", end="", flush=True)
        elif t == "setkey":
            try:
                new_ks = decrypt(msg["payload"], ks_ref[0], msg["nonce"])
                ks_ref[0] = new_ks
                print(f"\n[Alice] session key changed by Bob: {new_ks!r}")
                print("[Alice] > ", end="", flush=True)
            except Exception:
                print("\n[Alice] setkey error")
                print("[Alice] > ", end="", flush=True)


def chat(sock, ks_ref):
    stop = threading.Event()
    threading.Thread(target=receiver, args=(sock, ks_ref, stop), daemon=True).start()

    print("[Alice] chat ready. commands: setkey, quit")
    while not stop.is_set():
        try:
            line = input("[Alice] > ").strip()
        except (EOFError, KeyboardInterrupt):
            break

        if stop.is_set():
            break

        if line == "quit":
            break

        if line == "setkey":
            new_ks = input("[Alice] new session key: ").strip()
            if not new_ks:
                continue
            try:
                ct, nonce = encrypt(new_ks, ks_ref[0])
                send_msg(sock, {"type": "setkey", "payload": ct, "nonce": nonce})
                ks_ref[0] = new_ks
                print(f"[Alice] session key updated: {new_ks!r}")
            except Exception as e:
                print(f"[Alice] setkey failed: {e}")
            continue

        if not line:
            continue

        try:
            ct, nonce = encrypt(line, ks_ref[0])
            send_msg(sock, {"type": "message", "payload": ct, "nonce": nonce})
            print(f"[Alice] sent (hex): {ct}")
        except Exception as e:
            print(f"[Alice] send failed: {e}")

    stop.set()


def run_session(kdc_host, kdc_port, bob_host, bob_port, ka):
    n1 = secrets.token_bytes(8).hex()

    kdc = connect_retry(kdc_host, kdc_port, "KDC")
    send_msg(kdc, {"type": "key_request", "id_a": "Alice", "id_b": "Bob", "n1": n1})
    print(f"[Alice] step 1 sent. N1={n1}")

    try:
        resp = recv_msg(kdc)
    except Exception as e:
        print(f"[Alice] KDC response error: {e}")
        kdc.close()
        return
    kdc.close()

    if resp.get("type") == "error":
        print(f"[Alice] KDC error: {resp.get('message')}")
        return

    try:
        plain_a = decrypt(resp["payload_a"], ka, resp["nonce_a"])
    except Exception as e:
        print(f"[Alice] decrypt payload_a failed (wrong Ka?): {e}")
        return

    parts = plain_a.split("|")
    if len(parts) != 4:
        print(f"[Alice] unexpected payload_a format: {plain_a!r}")
        return

    ks, ida, idb, recv_n1 = parts
    if recv_n1 != n1:
        print(f"[Alice] N1 mismatch, possible replay attack")
        return

    print(f"[Alice] step 2 ok. Ks={ks!r}")
    print(f"[Alice] payload_a (hex): {resp['payload_a']}")

    bob = connect_retry(bob_host, bob_port, "Bob")
    send_msg(bob, {"type": "ticket", "payload_b": resp["payload_b"], "nonce_b": resp["nonce_b"]})
    print(f"[Alice] step 3 sent ticket to Bob")

    try:
        ch = recv_msg(bob)
    except Exception as e:
        print(f"[Alice] challenge error: {e}")
        bob.close()
        return

    if ch.get("type") != "challenge":
        print(f"[Alice] expected challenge, got {ch.get('type')}")
        bob.close()
        return

    try:
        n2_hex = decrypt(ch["payload"], ks, ch["nonce"])
    except Exception as e:
        print(f"[Alice] decrypt challenge failed: {e}")
        bob.close()
        return

    n2 = bytes.fromhex(n2_hex)
    print(f"[Alice] step 4 ok. N2={n2_hex}")

    fn2 = xor_0xff(n2).hex()
    ct, nonce = encrypt(fn2, ks)
    send_msg(bob, {"type": "challenge_response", "payload": ct, "nonce": nonce})
    print(f"[Alice] step 5 sent. f(N2)={fn2}")

    chat(bob, [ks])
    bob.close()


def main():
    print("[Alice] AES-KDC Client")
    kdc_host  = input("KDC host [127.0.0.1]: ").strip() or "127.0.0.1"
    kdc_port_in = input("KDC port [8888]: ").strip()
    kdc_port  = int(kdc_port_in) if kdc_port_in.isdigit() else 8888
    bob_host  = input("Bob host [127.0.0.1]: ").strip() or "127.0.0.1"
    bob_port_in = input("Bob port [9999]: ").strip()
    bob_port  = int(bob_port_in) if bob_port_in.isdigit() else 9999
    ka        = input("Ka (Alice master key): ").strip()
    if not ka:
        print("[Alice] key required")
        sys.exit(1)

    while True:
        try:
            run_session(kdc_host, kdc_port, bob_host, bob_port, ka)
        except KeyboardInterrupt:
            print("\n[Alice] bye")
            break
        except Exception as e:
            print(f"[Alice] session error: {e}")

        try:
            print("[Alice] restarting in 3s... (Ctrl+C to quit)")
            time.sleep(3)
        except KeyboardInterrupt:
            print("\n[Alice] bye")
            break


if __name__ == "__main__":
    main()
