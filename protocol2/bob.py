import socket
import threading
import argparse
import logging
import json
import random
from math import gcd


# ---------- RSA 유틸 ----------
def is_prime(n: int) -> bool:
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    i = 3
    while i * i <= n:
        if n % i == 0:
            return False
        i += 2
    return True


def gen_prime_400_500():
    candidates = [x for x in range(401, 500) if is_prime(x)]
    return random.choice(candidates)


def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x, y = egcd(b, a % b)
    return g, y, x - (a // b) * y


def modinv(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("modular inverse does not exist")
    return x % m


def build_rsa_keypair():
    while True:
        p = gen_prime_400_500()
        q = gen_prime_400_500()
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)

        e = 65537
        if gcd(e, phi) != 1:
            # 드물지만 φ(n)과 서로소가 아닐 수 있으므로 fallback
            # 작은 홀수 e들 시험
            for cand in [3, 5, 17, 257, 65537]:
                if gcd(cand, phi) == 1:
                    e = cand
                    break
            else:
                continue

        d = modinv(e, phi)
        return (p, q, n, e, d)


# ---------- 통신 유틸 ----------
def recv_json(sock):
    data = sock.recv(65536)
    if not data:
        return None
    # 단순 1회 왕복 가정(프로토콜 I). 여러 패킷 분할 등은 과제 범위에서 생략.
    text = data.decode("utf-8").strip()
    return json.loads(text)


def send_json(sock, obj):
    payload = (json.dumps(obj) + "\n").encode("utf-8")
    sock.sendall(payload)


# ---------- 프로토콜 처리 ----------
def handle_protocol(sock, msg):
    # 기대 메시지: {"opcode":0, "type":"RSAKey"}
    if msg.get("opcode") == 0 and msg.get("type") == "RSA":
        p, q, n, e, d = build_rsa_keypair()
        reply = {
            "opcode": 1,
            "type": "RSA",
            # 과제 예시 포맷을 따름
            # "private": d,
            "public": e,
            "parameter": {"n": n},
        }
        send_json(sock, reply)
    else:
        # 알 수 없는 요청
        send_json(sock, {"opcode": 3, "error": "unknown request"})


def handler(sock):
    try:
        msg = recv_json(sock)
        if msg is None:
            return
        handle_protocol(sock, msg)
    except Exception as e:
        logging.exception("handler error: %s", e)
        try:
            send_json(sock, {"opcode": 3, "error": str(e)})
        except Exception:
            pass
    finally:
        sock.close()


def run(addr, port):
    bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bob.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bob.bind((addr, port))
    bob.listen(10)
    logging.info("[*] Bob is listening on {}:{}".format(addr, port))

    while True:
        conn, info = bob.accept()
        logging.info(
            "[*] Bob accepts the connection from {}:{}".format(info[0], info[1])
        )
        conn_handle = threading.Thread(target=handler, args=(conn,))
        conn_handle.daemon = True
        conn_handle.start()


def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob IP>", type=str, default="0.0.0.0")
    parser.add_argument("-p", "--port", metavar="<bob port>", type=int, required=True)
    parser.add_argument(
        "-l", "--log", metavar="<DEBUG/INFO/...>", type=str, default="INFO"
    )
    args = parser.parse_args()
    return args


def main():
    args = command_line_args()
    logging.basicConfig(level=getattr(logging, args.log.upper(), logging.INFO))
    run(args.addr, args.port)


if __name__ == "__main__":
    main()
