import socket, threading, argparse, logging, json, random, base64
from math import gcd
from Crypto.Cipher import AES


# ===== PKCS#7 pad/unpad (no Crypto.Util.Padding) =====
def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    rem = len(data) % block_size
    pad_len = block_size - rem if rem != 0 else block_size
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    # if not data or len(data) % block_size != 0:
    #     raise ValueError("invalid padding: length")
    pad_len = data[-1]
    # if not (1 <= pad_len <= block_size):
    #     raise ValueError("invalid padding: value")
    # if data[-pad_len:] != bytes([pad_len]) * pad_len:
    #     raise ValueError("invalid padding: pattern")
    return data[:-pad_len]


# ===== RSA utils =====
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
    cands = [x for x in range(401, 500) if is_prime(x)]
    return random.choice(cands)


def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x, y = egcd(b, a % b)
    return g, y, x - (a // b) * y


def modinv(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("no modular inverse")
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
            for cand in [3, 5, 17, 257, 65537]:
                if gcd(cand, phi) == 1:
                    e = cand
                    break
            else:
                continue
        d = modinv(e, phi)
        return p, q, n, e, d


# ===== net utils =====
def recv_line(sock, timeout=10.0):
    sock.settimeout(timeout)
    buf = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            return buf.decode("utf-8") if buf else ""
        buf += chunk
        if b"\n" in buf:
            line, _ = buf.split(b"\n", 1)
            return line.decode("utf-8")


def send_json(sock, obj):
    sock.sendall((json.dumps(obj) + "\n").encode())


# ===== handler =====
def handler(sock):
    aes_key = None
    try:
        p, q, n, e, d = build_rsa_keypair()
        logging.info(f"[Bob] RSA ready: n={n}, e={e} (p={p}, q={q})")

        while True:
            line = recv_line(sock)
            if not line:
                logging.info("[Bob] client closed.")
                break
            msg = json.loads(line)
            logging.debug(f"[Bob] recv: {msg}")

            # 1) 공개키 요청
            if msg.get("opcode") == 0 and msg.get("type") == "RSA":
                reply = {"opcode": 1, "type": "RSA", "public": e, "parameter": {"n": n}}
                send_json(sock, reply)

            # 2) RSA로 암호화된 AES 키 수신
            elif msg.get("opcode") == 2 and msg.get("type") == "RSA":
                enc_list = msg.get("encrypted_key", [])
                recovered = bytes([pow(c, d, n) for c in enc_list])
                if len(recovered) != 32:
                    send_json(sock, {"opcode": 3, "error": "AES key length invalid"})
                    break
                aes_key = recovered
                logging.info("[Bob] AES key recovered (32 bytes)")

                # 3) AES로 "hello" 암호화 후 전송 (ECB-256, Base64)
                cipher = AES.new(aes_key, AES.MODE_ECB)
                ct = cipher.encrypt(pkcs7_pad(b"hello", 16))
                b64 = base64.b64encode(ct).decode("utf-8")
                send_json(sock, {"opcode": 2, "type": "AES", "encryption": b64})

            # 4) Alice가 보낸 AES 암호문 수신 → 복호화 → 출력
            elif msg.get("opcode") == 2 and msg.get("type") == "AES":
                if aes_key is None:
                    send_json(sock, {"opcode": 3, "error": "AES key not established"})
                    break
                cipher = AES.new(aes_key, AES.MODE_ECB)
                ct = base64.b64decode(msg["encryption"])
                pt = pkcs7_unpad(cipher.decrypt(ct), 16)
                logging.info(f'[Bob] Decrypted from Alice: "{pt.decode()}"')
                break

            else:
                send_json(sock, {"opcode": 3, "error": "unknown request"})
                break

    except Exception as e:
        logging.exception(f"[Bob] handler error: {e}")
        try:
            send_json(sock, {"opcode": 3, "error": str(e)})
        except Exception:
            pass
    finally:
        try:
            sock.close()
        except:
            pass


# ===== server loop =====
def run(addr, port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((addr, port))
    srv.listen(10)
    logging.info(f"[*] Bob is listening on {addr}:{port}")
    while True:
        conn, info = srv.accept()
        logging.info(f"[*] Bob accepts the connection from {info[0]}:{info[1]}")
        threading.Thread(target=handler, args=(conn,), daemon=True).start()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-a", "--addr", type=str, default="0.0.0.0")
    ap.add_argument("-p", "--port", type=int, required=True)
    ap.add_argument("-l", "--log", type=str, default="INFO")
    args = ap.parse_args()
    logging.basicConfig(level=getattr(logging, args.log.upper(), logging.INFO))
    run(args.addr, args.port)


if __name__ == "__main__":
    main()
