import socket, argparse, logging, json, random, base64, time
from Crypto.Cipher import AES


# ===================== PKCS#7 =====================
def pkcs7_pad(data: bytes, block: int = 16) -> bytes:
    r = len(data) % block
    pad = block - r if r else block
    return data + bytes([pad]) * pad


def pkcs7_unpad(data: bytes, block: int = 16) -> bytes:
    if not data or len(data) % block != 0:
        raise ValueError("invalid padding length")
    pad = data[-1]
    if not (1 <= pad <= block) or data[-pad:] != bytes([pad]) * pad:
        raise ValueError("invalid padding pattern")
    return data[:-pad]


# ===================== 수론 유틸 =====================
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
    if not is_prime(p):
        return False
    order = p - 1
    for q in prime_factors(order):
        if pow(g, order // q, p) == 1:
            return False
    return True


# ===================== DH → AES 키 파생 =====================
def derive_aes_key_from_shared(s_val: int) -> bytes:
    s_bytes = s_val.to_bytes(2, byteorder="big", signed=False)
    return (s_bytes * (32 // len(s_bytes)))[:32]


# ===================== 전송/수신 =====================
def send_json(sock, obj, mark_sent: bool = True):
    """Alice가 보내는 모든 메시지에 sent:true 추가"""
    data = dict(obj)
    if mark_sent:
        data["sent"] = True
    sjs = json.dumps(data)
    sock.sendall((sjs + "\r\n").encode("utf-8"))
    logging.info(f"[Alice → Bob] Sent: {sjs}")


def recv_json_lenient(sock, total_timeout=30.0, max_bytes=1_000_000):
    """Bob에게서 오는 메시지를 완화된 형태로 수신"""
    deadline = time.time() + total_timeout
    buf = b""
    braces = 0
    started = False
    sock.settimeout(1.0)
    while time.time() < deadline:
        try:
            chunk = sock.recv(4096)
            if chunk:
                # 🔹 Bob에게서 받은 원본 출력
                logging.info(
                    f"[Bob → Alice] Raw recv chunk: {chunk.decode('utf-8', 'ignore').strip()}"
                )
            if not chunk:
                if not buf.strip():
                    return None
                t = buf.decode("utf-8", "ignore").strip()
                i, j = t.find("{"), t.rfind("}")
                if i != -1 and j != -1 and j > i:
                    msg = json.loads(t[i : j + 1])
                    logging.info(f"[Bob → Alice] Parsed message: {msg}")
                    return msg
                return None

            buf += chunk
            if len(buf) > max_bytes:
                raise RuntimeError("response too large")

            while b"\n" in buf or b"\r\n" in buf:
                line, sep, rest = buf.partition(b"\n")
                if sep == b"":
                    line, sep, rest = buf.partition(b"\r\n")
                buf = rest
                t = line.decode("utf-8", "ignore").strip()
                if not t:
                    continue
                i, j = t.find("{"), t.rfind("}")
                if i != -1 and j != -1 and j > i:
                    msg = json.loads(t[i : j + 1])
                    logging.info(f"[Bob → Alice] Parsed message: {msg}")
                    return msg

            for bch in chunk:
                if bch == ord("{"):
                    braces += 1
                    started = True
                elif bch == ord("}"):
                    braces -= 1
                    if started and braces == 0:
                        t = buf.decode("utf-8", "ignore")
                        i, j = t.find("{"), t.rfind("}")
                        if i != -1 and j != -1 and j > i:
                            msg = json.loads(t[i : j + 1])
                            logging.info(f"[Bob → Alice] Parsed message: {msg}")
                            return msg
        except socket.timeout:
            continue
    return None


# ===================== 메시지 필터 =====================
def _normalize_params_key(msg: dict):
    candidates = [
        "parameter",
        "parameters",
        "params",
        "Parameter",
        "Parameters",
        "Params",
    ]
    for k in candidates:
        if k in msg and isinstance(msg[k], dict):
            return msg[k]
    if "p" in msg and "g" in msg:
        return {"p": msg["p"], "g": msg["g"]}
    return None


def is_dh_params(msg):
    try:
        if not (msg.get("opcode") == 1 and str(msg.get("type", "")).upper() == "DH"):
            return False
        if "public" not in msg:
            return False
        params = _normalize_params_key(msg)
        if not params:
            return False
        return "p" in params and "g" in params
    except Exception:
        return False


def read_until(sock, want_fn, total_timeout):
    deadline = time.time() + total_timeout
    while time.time() < deadline:
        m = recv_json_lenient(
            sock, total_timeout=min(5.0, max(0.5, deadline - time.time()))
        )
        if not m:
            continue
        if isinstance(m, dict) and m.get("opcode") == 3:
            raise RuntimeError(f"Bob error: {m.get('error')}")
        if want_fn(m):
            return m
    raise TimeoutError("did not receive expected message in time")


# ===================== 메인 =====================
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-a", "--addr", required=True)
    ap.add_argument("-p", "--port", required=True, type=int)
    ap.add_argument("-l", "--log", default="INFO")
    ap.add_argument("--timeout", type=float, default=30.0)
    args = ap.parse_args()
    logging.basicConfig(level=getattr(logging, args.log.upper(), logging.INFO))

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(10.0)
        s.connect((args.addr, args.port))
        logging.info(f"[Alice] connected to {args.addr}:{args.port}")

        # (1) DH 요청
        send_json(s, {"opcode": 0, "type": "DH"})

        # (2) Bob의 DH 파라미터 수신
        resp1 = read_until(s, is_dh_params, args.timeout)
        params = _normalize_params_key(resp1)
        p = int(params["p"])
        g = int(params["g"])
        B = int(resp1["public"])
        logging.info(f"[Alice] DH params <- p={p}, g={g}, B={B}")

        # (3) p, g 검증 및 에러 전송
        if not (400 <= p <= 500):
            send_json(s, {"opcode": 3, "error": "prime must be between 400 and 500"})
            logging.error("[Alice] p out of range")
            return
        if not is_prime(p):
            send_json(s, {"opcode": 3, "error": f"{p} is not a prime number"})
            logging.error("[Alice] p not prime")
            return
        if not is_generator(g, p):
            send_json(s, {"opcode": 3, "error": f"{g} is not a generator for p={p}"})
            logging.error("[Alice] g not generator")
            return
        logging.info(f"[Alice] p={p} is prime ✔, g={g} is generator ✔")

        # (4) Alice 공개키 전송
        a = random.randint(2, p - 2)
        A = pow(g, a, p)
        send_json(s, {"opcode": 1, "type": "DH", "public": A})
        logging.info(f"[Alice] sent public A={A}")

        # (5) 공유비밀로 AES 키 파생
        s_val = pow(B, a, p)
        aes_key = derive_aes_key_from_shared(s_val)
        cipher = AES.new(aes_key, AES.MODE_ECB)
        logging.info("[Alice] derived AES-256 key")

        # (6) Bob의 AES 메시지 수신
        def is_aes_msg(m):
            return isinstance(m, dict) and m.get("opcode") == 2 and "encryption" in m

        resp2 = read_until(s, is_aes_msg, args.timeout)
        ct = base64.b64decode(resp2["encryption"])
        pt = pkcs7_unpad(cipher.decrypt(ct), 16)
        logging.info(f'[Alice] Decrypted from Bob: "{pt.decode("utf-8","ignore")}"')

        # (7) world 암호화해서 전송
        ct2 = cipher.encrypt(pkcs7_pad(b"world", 16))
        b64 = base64.b64encode(ct2).decode("utf-8")
        send_json(s, {"opcode": 2, "type": "AES", "encryption": b64})
        logging.info("[Alice] sent AES ciphertext (world)")

    except Exception as e:
        logging.exception(f"[Alice] error: {e}")
    finally:
        try:
            s.close()
        except:
            pass


if __name__ == "__main__":
    main()
