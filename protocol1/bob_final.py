# bob_protocol1.py (Protocol I) - fixed to include private key
import socket, argparse, logging, json, random, time
from math import gcd


def send_json(conn, obj):
    conn.sendall((json.dumps(obj) + "\r\n").encode("utf-8"))


def recv_json(conn, timeout=30.0):
    conn.settimeout(timeout)
    data = b""
    while True:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data += chunk
        if b"\n" in data or b"\r\n" in data:
            line = data.splitlines()[0]
            return json.loads(line.decode("utf-8"))
    return None


def is_prime(n):
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


def primes_in_range(lo=400, hi=500):
    return [n for n in range(lo, hi + 1) if is_prime(n)]


def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x, y = egcd(b, a % b)
    return (g, y, x - (a // b) * y)


def modinv(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("no inverse")
    return x % m


def gen_rsa_key():
    P = primes_in_range()
    p = random.choice(P)
    q = random.choice([x for x in P if x != p])
    n = p * q
    phi = (p - 1) * (q - 1)
    e_candidates = [3, 5, 17, 257, 65537]
    e = next(ec for ec in e_candidates if ec < phi and gcd(ec, phi) == 1)
    d = modinv(e, phi)
    return p, q, n, e, d


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("-l", "--log", default="INFO")
    args = ap.parse_args()
    logging.basicConfig(level=getattr(logging, args.log.upper(), logging.INFO))

    def log(msg):
        logging.info(msg)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((args.host, args.port))
        srv.listen(1)
        log(f"[Bob] listening on {args.host}:{args.port} (Protocol I)")

        conn, addr = srv.accept()
        with conn:
            log(f"[Bob] connection from {addr}")
            msg = recv_json(conn)
            log(f"[Bob] received: {msg}")
            if (
                not msg
                or msg.get("opcode") != 0
                or str(msg.get("type", "")).upper() != "RSAKEY"
            ):
                log("[Bob] invalid start message, abort")
                return

            p, q, n, e, d = gen_rsa_key()
            log(f"[Bob] generated p={p}, q={q}, n={n}, e={e}, d={d}")

            resp = {
                "opcode": 1,
                "type": "RSAKey",
                "public": e,
                "private": d,
                "parameter": {"p": p, "q": q},
            }
            send_json(conn, resp)
            log("[Bob] sent RSAKey packet with public/private/p/q")


if __name__ == "__main__":
    main()
