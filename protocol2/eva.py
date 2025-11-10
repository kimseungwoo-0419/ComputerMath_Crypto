import argparse
import base64
import json
import logging
import socket
import threading
from typing import Optional, Dict
from Crypto.Cipher import AES
from Crypto.Cipher._mode_ecb import EcbMode


# ===== PKCS#7 =====
def pkcs7_unpad(data: bytes, block: int = 16) -> bytes:
    if not data or len(data) % block != 0:
        raise ValueError("invalid padding length")
    pad = data[-1]
    if not (1 <= pad <= block) or data[-pad:] != bytes([pad]) * pad:
        raise ValueError("invalid padding pattern")
    return data[:-pad]


# ===== 유틸 =====
def send_all(sock: socket.socket, data: bytes):
    """에러 없이 끝까지 보냄"""
    sock.sendall(data)


def try_json(line: bytes) -> Optional[dict]:
    try:
        return json.loads(line.decode("utf-8"))
    except Exception:
        return None


class EveState:
    """스레드 간 공유 상태: RSA (e,n), AES key/cipher"""

    def __init__(self):
        self.lock = threading.Lock()
        self.e: Optional[int] = None
        self.n: Optional[int] = None
        self.byte_map: Optional[Dict[int, int]] = None  # c -> byte
        self.aes_key: Optional[bytes] = None
        self.cipher: Optional[EcbMode] = None

    def set_rsa_pub(self, e: int, n: int):
        with self.lock:
            self.e, self.n = e, n
            # 0..255 바이트에 대한 RSA 암호화 결과를 미리 테이블화(역매핑)
            self.byte_map = {pow(b, e, n): b for b in range(256)}
            logging.info(f"[Eve] Learned RSA pubkey: e={e}, n={n}")
            logging.info(f"[Eve] Built inverse table for 256 bytes.")

    def try_recover_aes_key_from_list(self, enc_list):
        """Alice가 보낸 enc_list(각 바이트를 RSA로 암호화한 정수 리스트)로부터 키 복원"""
        with self.lock:
            if self.byte_map is None:
                return False
            key_bytes = bytearray()
            miss = 0
            for c in enc_list:
                b = self.byte_map.get(int(c))
                if b is None:
                    # 혹시 테이블에 없으면 브루트(256회) 한번 더
                    found = None
                    for k in range(256):
                        if pow(k, self.e, self.n) == int(c):
                            found = k
                            break
                    if found is None:
                        miss += 1
                        b = 0  # placeholder
                    else:
                        b = found
                key_bytes.append(b)
            if miss:
                logging.warning(
                    f"[Eve] {miss} byte(s) could not be mapped deterministically."
                )
            self.aes_key = bytes(key_bytes)
            self.cipher = AES.new(self.aes_key, AES.MODE_ECB)
            logging.info(f"[Eve] Recovered AES-256 key (hex): {self.aes_key.hex()}")
            return True

    def decrypt_base64(self, b64: str) -> Optional[str]:
        with self.lock:
            if self.cipher is None:
                return None
            try:
                ct = base64.b64decode(b64)
                pt = pkcs7_unpad(self.cipher.decrypt(ct), 16)
                return pt.decode("utf-8", "ignore")
            except Exception as e:
                logging.warning(f"[Eve] AES decrypt failed: {e}")
                return None


def _pretty_json(obj: dict) -> str:
    try:
        return json.dumps(obj, ensure_ascii=False, indent=2)
    except Exception:
        return str(obj)


def forward_loop(
    src: socket.socket, dst: socket.socket, state: EveState, direction: str
):
    """
    한 방향으로 바이트를 그대로 포워딩하면서, 줄 단위(개행)로 JSON을 파싱해
    RSA/AES 정보를 추출하고 평문을 로그로 출력한다.
    direction: "A->B" 또는 "B->A"
    """
    buffer = b""
    try:
        while True:
            chunk = src.recv(4096)
            if not chunk:
                # 반대쪽도 정리
                try:
                    dst.shutdown(socket.SHUT_WR)
                except Exception:
                    pass
                break

            # 즉시 원본 그대로 전달(패시브)
            send_all(dst, chunk)

            # 로그: forwarded raw (safe decode)
            try:
                decoded = chunk.decode("utf-8", "ignore")
                # 줄바꿈이 길면 한 줄로 축약해서 보여줌
                one_line = " ".join(decoded.splitlines())
                logging.info(
                    f"[Forward {direction}] forwarded {len(chunk)} bytes: {one_line}"
                )
            except Exception:
                logging.info(
                    f"[Forward {direction}] forwarded {len(chunk)} bytes (binary)"
                )

            buffer += chunk

            # 개행 기준으로 라인 파싱 (CR/LF 모두 허용)
            while True:
                lf_pos = buffer.find(b"\n")
                crlf_pos = buffer.find(b"\r\n")
                split_pos = -1
                sep_len = 1
                if crlf_pos != -1:
                    split_pos = crlf_pos
                    sep_len = 2
                elif lf_pos != -1:
                    split_pos = lf_pos
                    sep_len = 1

                if split_pos == -1:
                    break

                line = buffer[:split_pos]
                buffer = buffer[split_pos + sep_len :]

                text = line.decode("utf-8", "ignore").strip()
                if not text:
                    continue

                # 로그: 원문 라인
                logging.info(f"[{direction}] raw line: {text}")

                msg = try_json(line)
                if not msg:
                    # JSON 파싱 불가한 라인도 그대로 보여줌
                    logging.debug(f"[{direction}] non-JSON line: {text}")
                    continue

                # pretty print parsed JSON with direction and human-friendly arrow
                if direction == "A->B":
                    logging.info(f"[Alice → Bob] { _pretty_json(msg) }")
                else:
                    logging.info(f"[Bob → Alice] { _pretty_json(msg) }")

                # --- Eve 분석 로직 ---
                # 1) Bob -> Alice: RSA 공개키
                if (
                    direction == "B->A"
                    and isinstance(msg, dict)
                    and msg.get("opcode") == 1
                    and str(msg.get("type", "")).upper().startswith("RSA")
                ):
                    try:
                        e = int(msg["public"])
                        # parameter / parameters / flat 모두 지원
                        param = msg.get("parameter") or msg.get("parameters") or {}
                        n = int(param.get("n", msg.get("n")))
                        if e and n:
                            state.set_rsa_pub(e, n)
                    except Exception as e:
                        logging.debug(f"[Eve] RSA pub parse fail: {e}")

                # 2) Alice -> Bob: RSA로 바이트 단위 암호화된 AES 키
                if (
                    direction == "A->B"
                    and isinstance(msg, dict)
                    and msg.get("opcode") == 2
                    and str(msg.get("type", "")).upper() == "RSA"
                ):
                    enc_list = (
                        msg.get("encrypted_key")
                        or msg.get("encryption")
                        or msg.get("cipher")
                    )
                    if isinstance(enc_list, list):
                        ok = state.try_recover_aes_key_from_list(enc_list)
                        if ok:
                            logging.info("[Eve] AES key recovered ✅")

                # 3) 양방향 AES 메시지 복호
                if (
                    isinstance(msg, dict)
                    and msg.get("opcode") == 2
                    and str(msg.get("type", "")).upper() == "AES"
                    and "encryption" in msg
                ):
                    pt = state.decrypt_base64(msg["encryption"])
                    if pt is not None:
                        who = "Bob→Alice" if direction == "B->A" else "Alice→Bob"
                        logging.warning(f'[Eve] Decrypted {who}: "{pt}"')

    except Exception as e:
        logging.debug(f"[{direction}] forward loop ended: {e}")
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except Exception:
            pass


def serve(listen_addr: str, listen_port: int, bob_addr: str, bob_port: int):
    """Eve가 프록시로 리슨; Alice가 Eve에 접속하면 Bob으로 연결 후 양방향 포워드"""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((listen_addr, listen_port))
    srv.listen(5)
    logging.info(f"[*] Eve listening on {listen_addr}:{listen_port}")

    while True:
        alice_sock, alice_info = srv.accept()
        logging.info(f"[*] Alice connected from {alice_info[0]}:{alice_info[1]}")
        bob_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        bob_sock.connect((bob_addr, bob_port))
        logging.info(f"[*] Eve connected to Bob at {bob_addr}:{bob_port}")

        state = EveState()

        th1 = threading.Thread(
            target=forward_loop, args=(alice_sock, bob_sock, state, "A->B"), daemon=True
        )
        th2 = threading.Thread(
            target=forward_loop, args=(bob_sock, alice_sock, state, "B->A"), daemon=True
        )
        th1.start()
        th2.start()

        # 두 방향 스레드 종료까지 대기
        th1.join()
        th2.join()

        try:
            alice_sock.close()
        except Exception:
            pass
        try:
            bob_sock.close()
        except Exception:
            pass
        logging.info("[*] Connection closed.\n")


def main():
    p = argparse.ArgumentParser(
        description="Eve: passive MITM for Protocol II (RSA→AES)"
    )
    p.add_argument("--listen-addr", "-la", default="0.0.0.0")
    p.add_argument("--listen-port", "-lp", type=int, required=True)
    p.add_argument("--bob-addr", "-ba", required=True)
    p.add_argument("--bob-port", "-bp", type=int, required=True)
    p.add_argument("-l", "--log", default="DEBUG")
    args = p.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log.upper(), logging.INFO),
        format="%(levelname)s:%(message)s",
    )

    serve(args.listen_addr, args.listen_port, args.bob_addr, args.bob_port)


if __name__ == "__main__":
    main()
