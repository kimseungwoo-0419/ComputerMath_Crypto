import socket, argparse, logging, json, base64
from Crypto.Cipher import AES
import random


# ===== PKCS#7 pad/unpad =====
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


# ===== 전송(개행 CRLF 허용) =====
def send_json(sock, obj):
    # 일부 서버는 CRLF를 기대하므로 \r\n 사용
    # sock.sendall((json.dumps(obj) + "\r\n").encode("utf-8"))
    sock.sendall(
        (json.dumps(obj) + "\r\n").encode()
    )  # 굳이 utf-8로 인코딩 안해도 될듯. str형식은 안되므로 인코딩 하여 바이트 형식으로 바꿔야함


# ===== 관대한 수신: 개행 유무/서버-먼저-전송 모두 커버 =====
def recv_json_lenient(sock, timeout=30.0, max_bytes=1_000_000):
    """
    - 서버가 개행 없이 순수 JSON만 보내도 OK
    - 개행 한 줄만 보내도 OK
    - 여러 줄이 와도 첫 줄 우선 시도 → 전체 파싱 순서로 처리
    """
    sock.settimeout(timeout)
    buf = b""

    while True:
        chunk = sock.recv(4096)  # 여기서 timeout 발생 가능
        if not chunk:
            # 연결 종료 — 남은 버퍼라도 파싱 시도
            if not buf:
                return None
            try:
                return json.loads(buf.decode("utf-8"))
            except Exception:
                return None

        buf += chunk
        if len(buf) > max_bytes:
            raise RuntimeError("response too large")

        # 0) 매 루프마다 전체 버퍼 파싱 먼저 시도 (개행이 없어도 처리)
        try:
            return json.loads(buf.decode("utf-8"))
        except Exception:
            pass

        # 1) 개행(또는 CRLF)이 있으면 첫 줄 파싱 시도
        if b"\n" in buf or b"\r\n" in buf:
            first_line = buf.splitlines()[0]
            try:
                return json.loads(first_line.decode("utf-8"))
            except Exception:
                # 2) 첫 줄이 불완전할 수 있으니 전체 버퍼 재시도(위에서 이미 시도했음)
                pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-a", "--addr", required=True)
    ap.add_argument("-p", "--port", required=True, type=int)
    ap.add_argument("-l", "--log", default="INFO")
    args = ap.parse_args()
    logging.basicConfig(level=getattr(logging, args.log.upper(), logging.INFO))

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(30.0)  # 연결/수신 모두 넉넉히
        s.connect((args.addr, args.port))
        logging.info(f"[Alice] connected to {args.addr}:{args.port}")

        # (옵션) 서버가 먼저 보내는 환경 탐지
        peek = None
        try:
            peek = recv_json_lenient(s, timeout=5.0)
        except Exception:
            peek = None

        if peek:
            logging.info(f"[Alice] server-first message: {peek}")

            # 서버가 이미 RSA 공개키를 준 경우 지원
            if str(peek.get("type", "")).upper().startswith("RSA"):
                resp1 = peek
            else:
                # 서버가 다른 안내만 보냈다면 표준 요청을 보낸다
                send_json(s, {"opcode": 0, "type": "RSA"})
                resp1 = recv_json_lenient(s, timeout=25.0)
        else:
            # 1차 시도: type="RSA"
            send_json(s, {"opcode": 0, "type": "RSA"})
            resp1 = recv_json_lenient(s, timeout=18.0)
            # 2차 시도: type="RSAKey"
            if not resp1:
                send_json(s, {"opcode": 0, "type": "RSAKey"})
                resp1 = recv_json_lenient(s, timeout=18.0)

        if not resp1:
            raise RuntimeError("no response for RSA pubkey")
        if resp1.get("opcode") == 3:
            raise RuntimeError(f"Bob error: {resp1.get('error')}")

        e = int(resp1["public"])
        n = int(resp1["parameter"]["n"])
        logging.info(f"[Alice] received RSA pubkey e={e}, n={n}")

        # --- AES 키 생성 & RSA로 바이트 단위 암호화 전송 ---
        aes_key = bytes(random.getrandbits(8) for _ in range(32))  # 256-bit
        enc_list = [pow(b, e, n) for b in aes_key]
        send_json(s, {"opcode": 2, "type": "RSA", "encrypted_key": enc_list})
        logging.info("[Alice] sent RSA-encrypted AES key")

        # --- Bob → AES("hello") 수신 & 복호 ---
        resp2 = recv_json_lenient(s, timeout=25.0)
        if not resp2:
            raise RuntimeError("no AES message from Bob")
        if resp2.get("opcode") == 3:
            raise RuntimeError(f"Bob error: {resp2.get('error')}")
        cipher = AES.new(aes_key, AES.MODE_ECB)
        ct = base64.b64decode(resp2["encryption"])
        pt = pkcs7_unpad(cipher.decrypt(ct), 16)
        logging.info(f'[Alice] Decrypted from Bob: "{pt.decode()}"')

        # --- "world" 암호화해서 전송 ---
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
