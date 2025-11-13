import socket
import argparse
import logging
import json
from math import gcd


# --- 유틸: 간단 소수판별/역원 ---
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


def verify_rsa_keypair(p, q, e, d):
    n = p * q
    phi = (p - 1) * (q - 1)
    if gcd(e, phi) != 1:
        return False, "gcd(e, φ(n)) != 1"
    if (e * d) % phi != 1:
        return False, "e*d mod φ(n) != 1"
    # 왕복 암복호
    m = 42
    c = pow(m, e, n)
    dec = pow(c, d, n)
    if dec != m:
        return False, "decrypt(m^e) != m"
    return True, "OK"


# --- 개행까지 안전하게 수신 ---
def recv_until_newline(sock, timeout=5.0):
    sock.settimeout(timeout)
    buf = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            # 서버가 닫았는데 아직 아무 것도 못 받음
            return buf.decode("utf-8") if buf else ""
        buf += chunk
        if b"\n" in buf:
            line, _ = buf.split(b"\n", 1)
            return line.decode("utf-8")


def run(addr, port):
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        conn.settimeout(5.0)  # 연결 타임아웃
        conn.connect((addr, port))
        logging.info("Alice is connected to {}:{}".format(addr, port))

        # 1) 요청 전송 (개행으로 프레이밍)
        req = {"opcode": 0, "type": "RSAKey"}
        payload = (json.dumps(req) + "\n").encode("utf-8")
        conn.sendall(payload)
        logging.debug("Alice sent: %s", req)

        # 2) 응답 수신 (개행까지)
        line = recv_until_newline(conn, timeout=5.0)
        if not line:
            logging.error("No data from Bob (connection closed or empty)")
            return
        logging.debug("Alice received line: %r", line)

        # 3) JSON 파싱 및 검증
        resp = json.loads(line)
        if resp.get("opcode") == 3:
            logging.error("Bob error: %s", resp.get("error"))
            return

        d = int(resp["private"])
        e = int(resp["public"])
        p = int(resp["parameter"]["p"])
        q = int(resp["parameter"]["q"])
        n_from_bob = int(resp["parameter"].get("n", p * q))

        p_ok = is_prime(p)
        q_ok = is_prime(q)
        key_ok, reason = verify_rsa_keypair(p, q, e, d)

        print("=== Protocol I Verification ===")
        print(f"p={p} (prime? {p_ok})")
        print(f"q={q} (prime? {q_ok})")
        print(f"public e={e}")
        print(f"private d={d}")
        print(f"n from Bob={n_from_bob}, p*q={p*q}, match? {n_from_bob == p*q}")
        print(f"Keypair valid? {key_ok} ({reason})")

    except Exception as e:
        logging.exception("[Alice] connect/send/recv error: %s", e)
    finally:
        try:
            conn.close()
        except:
            pass


def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-a",
        "--addr",
        metavar="<bob's address>",
        help="Bob's address",
        type=str,
        required=True,
    )
    parser.add_argument(
        "-p",
        "--port",
        metavar="<bob's port>",
        help="Bob's port",
        type=int,
        required=True,
    )
    parser.add_argument(
        "-l",
        "--log",
        metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>",
        help="Log level",
        type=str,
        default="INFO",
    )
    args = parser.parse_args()
    return args


def main():
    args = command_line_args()
    # 문자열 레벨을 실제 상수로 변환
    level = getattr(logging, args.log.upper(), logging.INFO)
    logging.basicConfig(level=level)
    run(args.addr, args.port)


if __name__ == "__main__":
    main()
