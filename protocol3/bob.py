import socket, threading, argparse, logging, json, random, base64, os
from Crypto.Cipher import AES


# ====== PKCS#7 pad / unpad ======
def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    rem = len(data) % block_size
    pad_len = block_size - rem if rem != 0 else block_size
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("invalid padding length")
    pad_len = data[-1]
    if not (1 <= pad_len <= block_size):
        raise ValueError("invalid padding value")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("invalid padding pattern")
    return data[:-pad_len]


# ====== number utils ======
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


def prime_factors(n: int):
    """n의 소인수 집합(중복 제거)"""
    fac = set()
    d = 2
    while d * d <= n:
        while n % d == 0:
            fac.add(d)
            n //= d
        d += 1
    if n > 1:
        fac.add(n)
    return fac


def is_generator(g: int, p: int) -> bool:
    """p 소수일 때, g가 Z_p^*의 생성자인지 검사 (모든 소인수 q | (p-1)에 대해 g^((p-1)/q) != 1 mod p)"""
    if not (2 <= g <= p - 2):  # 간단 범위체크
        return False
    if not is_prime(p):
        return False
    order = p - 1
    for q in prime_factors(order):
        if pow(g, order // q, p) == 1:
            return False
    return True


def gen_prime_400_500():
    cands = [x for x in range(401, 500) if is_prime(x)]
    return random.choice(cands)


# ====== net utils ======
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
    sock.sendall((json.dumps(obj) + "\n").encode("utf-8"))


# ====== handler ======
def handler(sock):
    try:
        # 1) DH 파라미터 생성 (p, g, b, B)
        #    p는 400~500 소수, g는 생성자
        while True:
            p = gen_prime_400_500()
            g = random.randint(2, 10)
            if is_generator(g, p):
                break

        b = random.randint(2, p - 2)
        B = pow(g, b, p)
        logging.info(f"[Bob] DH params -> p={p}, g={g}, B={B}")

        # Alice로부터 요청 기다림
        # 기대: {"opcode":0,"type":"DH"}
        line = recv_line(sock)
        if not line:
            return
        msg0 = json.loads(line)
        if not (msg0.get("opcode") == 0 and msg0.get("type") == "DH"):
            send_json(sock, {"opcode": 3, "error": "invalid start for DH"})
            return

        # 2) Bob -> Alice : p, g, B 제공
        send_json(
            sock,
            {"opcode": 1, "type": "DH", "public": B, "parameter": {"p": p, "g": g}},
        )

        # 3) Alice로부터 A 수신
        line = recv_line(sock)
        if not line:
            return
        msg1 = json.loads(line)
        if not (msg1.get("opcode") == 1 and msg1.get("type") == "DH"):
            send_json(sock, {"opcode": 3, "error": "invalid DH reply"})
            return
        A = int(msg1.get("public"))
        logging.info(f"[Bob] received A={A}")

        # 4) 공유 비밀키 s = A^b mod p
        s = pow(A, b, p)
        # PPT 명시: s.to_bytes(2,'big') 반복 → 32바이트
        s_bytes = s.to_bytes(2, byteorder="big")
        aes_key = (s_bytes * (32 // len(s_bytes)))[:32]
        logging.info("[Bob] shared secret derived (32 bytes)")

        # 5) AES-ECB로 "hello" 암호화 → 전송
        cipher = AES.new(aes_key, AES.MODE_ECB)
        ct = cipher.encrypt(pkcs7_pad(b"hello", 16))
        b64 = base64.b64encode(ct).decode("utf-8")
        send_json(sock, {"opcode": 2, "type": "AES", "encryption": b64})

        # 6) Alice가 보내는 AES 암호문 수신 → 복호화 → "world" 확인
        line = recv_line(sock)
        if not line:
            return
        msg2 = json.loads(line)
        if not (msg2.get("opcode") == 2 and msg2.get("type") == "AES"):
            send_json(sock, {"opcode": 3, "error": "invalid AES message"})
            return

        ct2 = base64.b64decode(msg2["encryption"])
        pt2 = pkcs7_unpad(cipher.decrypt(ct2), 16)
        logging.info(f'[Bob] Decrypted from Alice: "{pt2.decode()}"')

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
