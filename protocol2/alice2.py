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
