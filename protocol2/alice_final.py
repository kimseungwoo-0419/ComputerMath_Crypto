import socket, argparse, logging, json, base64
from Crypto.Cipher import AES
import random


# PKCS#7 pad/unpad
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


# 전송(개행 CRLF 허용)
def send_json(sock, obj):
    sock.sendall((json.dumps(obj) + "\n").encode())


# 관대한 수신: 개행 유무/서버-먼저-전송 모두 커버
def recv_json_lenient(sock, timeout=30.0, max_bytes=1_000_000):
    sock.settimeout(timeout)
    buf = b""

    while True:
        chunk = sock.recv(4096)
        buf += chunk
        return json.loads(buf.decode())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-a", "--addr", required=True)
    ap.add_argument("-p", "--port", required=True, type=int)
    ap.add_argument("-l", "--log", default="INFO")
    args = ap.parse_args()
    logging.basicConfig(level=getattr(logging, args.log.upper(), logging.INFO))

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(10.0)
        s.connect((args.addr, args.port))
        logging.info(f"[Alice] connected to {args.addr}:{args.port}")
        # 1차 시도: type="RSA"
        send_json(s, {"opcode": 0, "type": "RSA"})
        resp1 = recv_json_lenient(s, timeout=18.0)

        e = int(resp1["public"])
        n = int(resp1["parameter"]["n"])
        logging.info(f"[Alice] received RSA pubkey e={e}, n={n}")

        # AES 키 생성 & RSA로 바이트 단위 암호화 전송
        aes_key = bytes(random.getrandbits(8) for _ in range(32))  # 256-bit
        enc_list = [pow(b, e, n) for b in aes_key]
        send_json(s, {"opcode": 2, "type": "RSA", "encrypted_key": enc_list})
        logging.info("[Alice] sent RSA-encrypted AES key")

        # Bob → AES 수신 & 복호
        resp2 = recv_json_lenient(s, timeout=25.0)
        cipher = AES.new(aes_key, AES.MODE_ECB)
        ct = base64.b64decode(resp2["encryption"])
        pt = pkcs7_unpad(cipher.decrypt(ct), 16)
        logging.info(f'[Alice] Decrypted from Bob: "{pt.decode()}"')

        # 암호화해서 전송
        ct2 = cipher.encrypt(pkcs7_pad(b"KENDEX", 16))
        b64 = base64.b64encode(ct2).decode("utf-8")
        send_json(s, {"opcode": 2, "type": "AES", "encryption": b64})
        logging.info("[Alice] sent AES ciphertext")

    except Exception as e:
        logging.exception(f"[Alice] error: {e}")
    finally:
        try:
            s.close()
        except:
            pass


if __name__ == "__main__":
    main()
