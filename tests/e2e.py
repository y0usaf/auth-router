import concurrent.futures
import http.server
import json
import os
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time


def run_cmd(bin_path, args, env=None, check=True):
    clean_env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    if env:
        clean_env.update(env)
    p = subprocess.run(
        [bin_path] + args,
        env=clean_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
    )
    if check and p.returncode != 0:
        raise AssertionError(
            f"cmd failed ({p.returncode}): {args}\nstdout={p.stdout}\nstderr={p.stderr}"
        )
    return p


def unix_rpc_raw(sock_path, line):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect(sock_path)
    s.sendall((line + "\n").encode())
    buf = b""
    while b"\n" not in buf:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
    s.close()
    return json.loads(buf.decode().strip())


def gen_self_signed_cert(tmp_dir, name, cn="localhost", san="DNS:localhost,IP:127.0.0.1"):
    key = os.path.join(tmp_dir, f"{name}.key")
    crt = os.path.join(tmp_dir, f"{name}.crt")
    cfg = os.path.join(tmp_dir, f"{name}.cnf")
    with open(cfg, "w") as f:
        f.write(
            "[req]\n"
            "distinguished_name=dn\n"
            "x509_extensions=v3_req\n"
            "prompt=no\n"
            "[dn]\n"
            f"CN={cn}\n"
            "[v3_req]\n"
            f"subjectAltName={san}\n"
            "basicConstraints=CA:TRUE\n"
        )
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            key,
            "-out",
            crt,
            "-days",
            "2",
            "-nodes",
            "-config",
            cfg,
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return crt, key


def start_https_token_server(crt, key, delay_s=0.0, chunked=False):
    state = {"count": 0, "lock": threading.Lock(), "ua_headers": []}

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            _ = self.rfile.read(length) if length > 0 else b""
            if delay_s > 0:
                time.sleep(delay_s)
            uas = self.headers.get_all("User-Agent") or []
            with state["lock"]:
                state["ua_headers"].append(list(uas))
                state["count"] += 1
                n = state["count"]
            payload = json.dumps(
                {
                    "access_token": f"fresh-tok-{n}",
                    "refresh_token": f"fresh-ref-{n}",
                    "expires_in": 3600,
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            if chunked:
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                mid = len(payload) // 2
                for part in (payload[:mid], payload[mid:]):
                    self.wfile.write(f"{len(part):x}\r\n".encode() + part + b"\r\n")
                self.wfile.write(b"0\r\n\r\n")
            else:
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=crt, keyfile=key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, port, state


def start_raw_tls_server(crt, key, raw_response):
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(5)
    port = lsock.getsockname()[1]
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=crt, keyfile=key)
    stop_ev = threading.Event()

    def run():
        lsock.settimeout(0.2)
        while not stop_ev.is_set():
            try:
                conn, _ = lsock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                tls = ctx.wrap_socket(conn, server_side=True)
                tls.settimeout(2.0)
                try:
                    tls.recv(4096)
                except Exception:
                    pass
                tls.sendall(raw_response)
                try:
                    tls.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                tls.close()
            except Exception:
                try:
                    conn.close()
                except Exception:
                    pass

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return lsock, stop_ev, port


def read_proc_rss_kib(pid):
    vm_rss = 0
    vm_hwm = 0
    with open(f"/proc/{pid}/status") as f:
        for line in f:
            if line.startswith("VmRSS:"):
                vm_rss = int(line.split()[1])
            elif line.startswith("VmHWM:"):
                vm_hwm = int(line.split()[1])
    return vm_rss, vm_hwm


def read_proc_cpu_ticks(pid):
    with open(f"/proc/{pid}/stat") as f:
        parts = f.read().rsplit(")", 1)[1].split()
    return int(parts[11]) + int(parts[12])


def wait_for_daemon(bin_path, sock_path, env):
    for _ in range(60):
        p = run_cmd(bin_path, ["--socket", sock_path, "ping"], env=env, check=False)
        if p.returncode == 0:
            return json.loads(p.stdout)
        time.sleep(0.05)
    raise AssertionError("daemon did not become ready")


def test_ldd(bin_path):
    p = subprocess.run(["ldd", bin_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
    allowed = ("linux-vdso.so", "libc.so", "libm.so", "ld-linux")
    for line in p.stdout.splitlines():
        s = line.strip()
        if not s:
            continue
        if not any(a in s for a in allowed):
            raise AssertionError(f"forbidden shared library in ldd: {s}")
    print("PASS ldd glibc-only")


def test_tls_and_chunked(bin_path, tmp_dir):
    crt1, key1 = gen_self_signed_cert(tmp_dir, "ca1")
    crt2, _ = gen_self_signed_cert(tmp_dir, "ca2")

    srv, port, st = start_https_token_server(crt1, key1, delay_s=0.0, chunked=True)
    try:
        sdir = os.path.join(tmp_dir, "tls_state")
        os.makedirs(sdir, mode=0o700, exist_ok=True)
        with open(os.path.join(sdir, "logins"), "w") as f:
            f.write("main\told-tok\tref-tok\t1000\t0\t\n")

        bad_env = {
            "AUTH_ROUTER_STATE_DIR": sdir,
            "CREST_AUTH_TOKEN_URL": f"https://localhost:{port}/token",
            "SSL_CERT_FILE": crt2,
        }
        p_bad = run_cmd(bin_path, ["--direct", "token", "anthropic", "claude-opus-5-5", "--json"], env=bad_env, check=False)
        assert p_bad.returncode != 0, "untrusted cert must fail"
        assert "certificate" in p_bad.stderr.lower() or "tls" in p_bad.stderr.lower(), p_bad.stderr

        good_env = {
            "AUTH_ROUTER_STATE_DIR": sdir,
            "CREST_AUTH_TOKEN_URL": f"https://localhost:{port}/token",
            "SSL_CERT_FILE": crt1,
        }
        p_ok = run_cmd(bin_path, ["--direct", "token", "anthropic", "claude-opus-5-5", "--json"], env=good_env)
        data = json.loads(p_ok.stdout)
        assert data["ok"] is True
        assert data["access"] == "fresh-tok-1"
        assert st["count"] == 1
        print("PASS tls verification + chunked HTTPS + untrusted cert rejection")
    finally:
        srv.shutdown()
        srv.server_close()


def test_http_tls_adversarial(bin_path, tmp_dir):
    crt, key = gen_self_signed_cert(tmp_dir, "adv_ca")
    sdir = os.path.join(tmp_dir, "adv_http_state")
    os.makedirs(sdir, mode=0o700, exist_ok=True)
    with open(os.path.join(sdir, "logins"), "w") as f:
        f.write("main\told-tok\tref-tok\t1000\t0\t\n")

    raw_overflow = (
        b"HTTP/1.1 200 OK\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n"
        b"ffffffffffffffff\r\nboom\r\n0\r\n\r\n"
    )
    ls1, ev1, port1 = start_raw_tls_server(crt, key, raw_overflow)
    try:
        env1 = {
            "AUTH_ROUTER_STATE_DIR": sdir,
            "CREST_AUTH_TOKEN_URL": f"https://localhost:{port1}/token",
            "SSL_CERT_FILE": crt,
        }
        p1 = run_cmd(bin_path, ["--direct", "token", "anthropic", "claude-opus-5-5", "--json"], env=env1, check=False)
        assert p1.returncode != 0, "chunked overflow must fail"
        assert "chunked" in p1.stderr.lower(), p1.stderr
    finally:
        ev1.set()
        ls1.close()

    raw_trunc = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: 200\r\n\r\n"
        b"{\"access_token\":\"x\"}"
    )
    ls2, ev2, port2 = start_raw_tls_server(crt, key, raw_trunc)
    try:
        env2 = {
            "AUTH_ROUTER_STATE_DIR": sdir,
            "CREST_AUTH_TOKEN_URL": f"https://localhost:{port2}/token",
            "SSL_CERT_FILE": crt,
        }
        p2 = run_cmd(bin_path, ["--direct", "token", "anthropic", "claude-opus-5-5", "--json"], env=env2, check=False)
        assert p2.returncode != 0, "truncated Content-Length must fail"
        assert "truncated" in p2.stderr.lower(), p2.stderr
    finally:
        ev2.set()
        ls2.close()

    wrong_crt, wrong_key = gen_self_signed_cert(
        tmp_dir, "wrong_host", cn="other.example.com", san="DNS:other.example.com"
    )
    srv3, port3, _ = start_https_token_server(wrong_crt, wrong_key)
    try:
        env3 = {
            "AUTH_ROUTER_STATE_DIR": sdir,
            "CREST_AUTH_TOKEN_URL": f"https://localhost:{port3}/token",
            "SSL_CERT_FILE": wrong_crt,
        }
        p3 = run_cmd(bin_path, ["--direct", "token", "anthropic", "claude-opus-5-5", "--json"], env=env3, check=False)
        assert p3.returncode != 0, "wrong hostname cert must fail even when CA is trusted"
        assert "certificate" in p3.stderr.lower() or "tls" in p3.stderr.lower(), p3.stderr
    finally:
        srv3.shutdown()
        srv3.server_close()

    env4 = {
        "AUTH_ROUTER_STATE_DIR": sdir,
        "CREST_AUTH_TOKEN_URL": f"https://localhost:{port1}/token\r\nX-Injected: 1",
        "SSL_CERT_FILE": crt,
    }
    p4 = run_cmd(bin_path, ["--direct", "token", "anthropic", "claude-opus-5-5", "--json"], env=env4, check=False)
    assert p4.returncode != 0, "CRLF injection in URL must fail"
    assert "invalid" in p4.stderr.lower(), p4.stderr

    print("PASS adversarial HTTP/TLS (chunked overflow, truncated body, wrong hostname, CRLF injection)")


def test_daemon_full(bin_path, tmp_dir):
    crt, key = gen_self_signed_cert(tmp_dir, "dcert")
    srv, port, st = start_https_token_server(crt, key, delay_s=0.25, chunked=False)
    sdir = os.path.join(tmp_dir, "daemon_state")
    os.makedirs(sdir, mode=0o700, exist_ok=True)
    sock = os.path.join(tmp_dir, "router.sock")
    rsock = os.path.join(tmp_dir, "restricted.sock")

    stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stale.bind(sock)
    stale.close()
    assert os.path.exists(sock)

    with open(os.path.join(sdir, "logins"), "w") as f:
        f.write("acct1\texpired-tok\tref-acct1\t1000\t0\t\n")

    denv = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "AUTH_ROUTER_STATE_DIR": sdir,
        "CREST_AUTH_TOKEN_URL": f"https://localhost:{port}/token",
        "AUTH_ROUTER_CA_FILE": crt,
    }
    proc = subprocess.Popen(
        [
            bin_path,
            "daemon",
            "--socket",
            sock,
            "--restricted-socket",
            rsock,
            "--restricted-mode",
            "0660",
            "--state-dir",
            sdir,
            "--no-bg-refresh",
        ],
        env=denv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        ping = wait_for_daemon(bin_path, sock, denv)
        assert ping["ok"] is True and ping["v"] == 1

        assert stat.S_IMODE(os.stat(sock).st_mode) == 0o600
        assert stat.S_IMODE(os.stat(rsock).st_mode) == 0o660

        bad_v = unix_rpc_raw(sock, json.dumps({"v": 2, "op": "ping"}))
        assert bad_v["ok"] is False and "wire version" in bad_v["error"]
        no_v = unix_rpc_raw(sock, json.dumps({"op": "ping"}))
        assert no_v["ok"] is False and "wire version" in no_v["error"]

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
            futs = [
                ex.submit(
                    run_cmd,
                    bin_path,
                    ["--socket", sock, "token", "anthropic", "claude-opus-5-5", "--json"],
                    denv,
                )
                for _ in range(3)
            ]
            results = [json.loads(f.result().stdout) for f in futs]
        for r in results:
            assert r["ok"] is True
            assert r["access"] == "fresh-tok-1"
            assert "refresh" not in r
        assert st["count"] == 1, f"expected 1 serialized refresh, got {st['count']}"

        r_ping = unix_rpc_raw(rsock, json.dumps({"v": 1, "op": "ping"}))
        assert r_ping["ok"] is True
        r_status = unix_rpc_raw(rsock, json.dumps({"v": 1, "op": "status"}))
        assert r_status["ok"] is True
        assert "ref-acct1" not in json.dumps(r_status)
        r_tok = unix_rpc_raw(rsock, json.dumps({"v": 1, "op": "token", "provider": "anthropic", "model": "claude-opus-5-5"}))
        assert r_tok["ok"] is True and r_tok["access"] == "fresh-tok-1"
        assert "refresh" not in r_tok

        for forbidden_op in (
            {"v": 1, "op": "add", "provider": "deepseek", "name": "ds", "key": "sk-1"},
            {"v": 1, "op": "remove", "name": "acct1"},
            {"v": 1, "op": "order", "names": ["acct1"]},
            {"v": 1, "op": "export"},
        ):
            r_deny = unix_rpc_raw(rsock, json.dumps(forbidden_op))
            assert r_deny["ok"] is False and "restricted" in r_deny["error"]

        p_add = run_cmd(bin_path, ["--socket", sock, "add", "deepseek", "ds1", "sk-ds-1234567890"], env=denv)
        assert p_add.returncode == 0
        p_cool = run_cmd(bin_path, ["--socket", sock, "cool", "anthropic:acct1", "claude-opus-5-5", "32m17s"], env=denv)
        cd = json.loads(p_cool.stdout)
        assert cd["ok"] is True and cd["cooldown_ms"] == 1937000

        deep_resp = unix_rpc_raw(sock, "[" * 500 + "]" * 500)
        assert deep_resp["ok"] is False, f"expected error for 500-deep JSON, got {deep_resp}"
        still_alive = unix_rpc_raw(sock, json.dumps({"v": 1, "op": "ping"}))
        assert still_alive["ok"] is True

        proc.send_signal(signal.SIGTERM)
        rc = proc.wait(timeout=5)
        assert rc == 0, f"expected clean exit 0 on SIGTERM, got {rc}"
        assert not os.path.exists(sock), "primary socket residue left"
        assert not os.path.exists(rsock), "restricted socket residue left"
        assert os.path.exists(os.path.join(sdir, "daemon.lock")), "daemon.lock must not be unlinked"

        p_fb = run_cmd(bin_path, ["--socket", sock, "--state-dir", sdir, "list", "--json"], env=denv)
        ld = json.loads(p_fb.stdout)
        assert ld["ok"] is True and ld["count"] == 2
        print("PASS daemon + stale recovery + wire v1 + serialized refresh + restricted mode + JSON depth DoS + clean shutdown + direct fallback")
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        srv.shutdown()
        srv.server_close()


def test_aba_and_half_close(bin_path, tmp_dir):
    crt, key = gen_self_signed_cert(tmp_dir, "aba_cert")
    srv, port, st = start_https_token_server(crt, key, delay_s=0.4, chunked=False)
    sdir = os.path.join(tmp_dir, "aba_state")
    os.makedirs(sdir, mode=0o700, exist_ok=True)
    sock = os.path.join(tmp_dir, "aba.sock")

    with open(os.path.join(sdir, "logins"), "w") as f:
        f.write("acct_a\texpired-a\tref-a\t1000\t0\t\n")
        f.write("acct_b\texpired-b\tref-b\t1000\t0\t\n")

    denv = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "AUTH_ROUTER_STATE_DIR": sdir,
        "CREST_AUTH_TOKEN_URL": f"https://localhost:{port}/token",
        "AUTH_ROUTER_CA_FILE": crt,
    }
    proc = subprocess.Popen(
        [
            bin_path,
            "daemon",
            "--socket",
            sock,
            "--state-dir",
            sdir,
            "--no-bg-refresh",
        ],
        env=denv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        wait_for_daemon(bin_path, sock, denv)

        sa = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sa.settimeout(5)
        sa.connect(sock)
        sa.sendall((json.dumps({"v": 1, "op": "token", "provider": "anthropic", "model": "claude-opus-5-5", "prefer": "acct_a"}) + "\n").encode())
        time.sleep(0.05)
        sa.close()

        sb = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sb.settimeout(5)
        sb.connect(sock)
        sb.sendall((json.dumps({"v": 1, "op": "ping"}) + "\n").encode())
        first_line = b""
        while b"\n" not in first_line:
            chunk = sb.recv(4096)
            assert chunk
            first_line += chunk
        r1 = json.loads(first_line.decode().strip())
        assert r1["ok"] is True and "access" not in r1, f"leaked token on first reply: {r1}"

        time.sleep(0.55)
        sb.sendall((json.dumps({"v": 1, "op": "ping"}) + "\n").encode())
        second_line = b""
        while b"\n" not in second_line:
            chunk = sb.recv(4096)
            assert chunk
            second_line += chunk
        lines = [ln for ln in second_line.decode().splitlines() if ln.strip()]
        assert len(lines) == 1, f"unexpected extra messages delivered to client B: {lines}"
        r2 = json.loads(lines[0])
        assert r2["ok"] is True and "access" not in r2, f"leaked token after refresh finished: {r2}"
        sb.close()

        cpu_before = read_proc_cpu_ticks(proc.pid)
        sh = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sh.settimeout(5)
        sh.connect(sock)
        sh.sendall((json.dumps({"v": 1, "op": "token", "provider": "anthropic", "model": "claude-opus-5-5", "prefer": "acct_b"}) + "\n").encode())
        sh.shutdown(socket.SHUT_WR)
        buf = b""
        while True:
            chunk = sh.recv(4096)
            if not chunk:
                break
            buf += chunk
        sh.close()
        cpu_after = read_proc_cpu_ticks(proc.pid)
        rh = json.loads(buf.decode().strip())
        assert rh["ok"] is True and rh["access"].startswith("fresh-tok-"), rh
        hz = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
        cpu_s = (cpu_after - cpu_before) / float(hz)
        assert cpu_s < 0.15, f"half-close caused CPU spin: {cpu_s:.3f}s"

        proc.send_signal(signal.SIGTERM)
        assert proc.wait(timeout=5) == 0
        print(f"PASS ABA slot-reuse isolation + half-close without spin (cpu={cpu_s:.3f}s)")
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        srv.shutdown()
        srv.server_close()


def test_proactive_bg_refresh(bin_path, tmp_dir):
    crt, key = gen_self_signed_cert(tmp_dir, "bg_cert")
    srv, port, st = start_https_token_server(crt, key, delay_s=0.0, chunked=False)
    sdir = os.path.join(tmp_dir, "bg_state")
    os.makedirs(sdir, mode=0o700, exist_ok=True)
    sock = os.path.join(tmp_dir, "bg.sock")

    near_exp = int(time.time() * 1000) + 30000
    with open(os.path.join(sdir, "logins"), "w") as f:
        f.write(f"bg1\told-bg-tok\tref-bg1\t{near_exp}\t0\t\n")

    denv = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "AUTH_ROUTER_STATE_DIR": sdir,
        "CREST_AUTH_TOKEN_URL": f"https://localhost:{port}/token",
        "AUTH_ROUTER_CA_FILE": crt,
        "AUTH_ROUTER_BG_CHECK_MS": "100",
        "AUTH_ROUTER_BG_LEAD_MS": "120000",
    }
    proc = subprocess.Popen(
        [
            bin_path,
            "daemon",
            "--socket",
            sock,
            "--state-dir",
            sdir,
        ],
        env=denv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        wait_for_daemon(bin_path, sock, denv)
        for _ in range(40):
            if st["count"] >= 1:
                break
            time.sleep(0.05)
        assert st["count"] >= 1, "proactive background refresh did not fire"
        time.sleep(0.1)
        tok = unix_rpc_raw(sock, json.dumps({"v": 1, "op": "token", "provider": "anthropic", "model": "claude-opus-5-5"}))
        assert tok["ok"] is True and tok["access"] == "fresh-tok-1", tok
        assert st["count"] == 1, f"expected no extra on-demand refresh, got {st['count']}"
        proc.send_signal(signal.SIGTERM)
        assert proc.wait(timeout=5) == 0
        print("PASS proactive background refresh")
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        srv.shutdown()
        srv.server_close()


def test_unfinished_and_acp_filtering(bin_path, tmp_dir):
    sdir = os.path.join(tmp_dir, "filter_state")
    os.makedirs(sdir, mode=0o700, exist_ok=True)
    future = int(time.time() * 1000) + 3600000
    with open(os.path.join(sdir, "logins"), "w") as f:
        f.write(f"unfin\t\t\t0\t0\tverif123\n")
        f.write(f"good\ttok-good\tref-good\t{future}\t0\t\n")
    with open(os.path.join(sdir, "order"), "w") as f:
        f.write("unfin\nacp1\ngood\n")
    with open(os.path.join(sdir, "auth.json"), "w") as f:
        json.dump({"acp1": {"type": "acp", "provider": "antigravity-acp"}}, f)

    env = {"AUTH_ROUTER_STATE_DIR": sdir}
    r1 = json.loads(run_cmd(bin_path, ["--direct", "token", "anthropic", "claude-opus-5-5", "--json"], env=env).stdout)
    assert r1["ok"] is True and r1["login_id"] == "good" and r1["access"] == "tok-good", r1

    r2 = run_cmd(bin_path, ["--direct", "token", "antigravity-acp", "gemini-4-neon", "--json"], env=env, check=False)
    assert r2.returncode != 0, f"acp entry must not be selected by token: {r2.stdout}"

    r3 = json.loads(
        run_cmd(
            bin_path,
            ["--direct", "route", "antigravity-acp:gemini-4-neon", "anthropic:claude-opus-5-5", "--json"],
            env=env,
        ).stdout
    )
    assert r3["ok"] is True and r3["provider"] == "anthropic" and r3["login_id"] == "good", r3
    print("PASS unfinished login + acp filtering")


def test_daemon_rss_ceiling(bin_path, tmp_dir):
    sdir = os.path.join(tmp_dir, "rss_state")
    os.makedirs(sdir, mode=0o700, exist_ok=True)
    sock = os.path.join(tmp_dir, "rss.sock")
    env = {"AUTH_ROUTER_STATE_DIR": sdir}

    for i in range(8):
        run_cmd(bin_path, ["--direct", "add", "antigravity-cli", f"agy{i}", f"sk-agy-{i}"], env=env)
        run_cmd(bin_path, ["--direct", "add", "anthropic", f"ant{i}", f"sk-ant-{i}"], env=env)
        run_cmd(bin_path, ["--direct", "add", "deepseek", f"ds{i}", f"sk-ds-{i}"], env=env)

    denv = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "AUTH_ROUTER_STATE_DIR": sdir,
    }
    proc = subprocess.Popen(
        [bin_path, "daemon", "--socket", sock, "--state-dir", sdir, "--no-bg-refresh"],
        env=denv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        wait_for_daemon(bin_path, sock, denv)
        req = {
            "v": 1,
            "op": "route",
            "routes": [
                {"rank": 0, "provider": "antigravity-cli", "model": "gemini-4-neon"},
                {"rank": 1, "provider": "anthropic", "model": "claude-opus-5-5"},
                {"rank": 2, "provider": "deepseek", "model": "deepseek-chat"},
            ],
        }
        for _ in range(25):
            r = unix_rpc_raw(sock, json.dumps(req))
            assert r["ok"] is True and r["http_status"] == 200
        vm_rss_kib, vm_hwm_kib = read_proc_rss_kib(proc.pid)
        print(f"REPORT daemon_rss={vm_rss_kib} KiB ({vm_rss_kib / 1024.0:.2f} MiB) peak_vmhwm={vm_hwm_kib} KiB ({vm_hwm_kib / 1024.0:.2f} MiB)")
        assert vm_rss_kib < 20 * 1024, f"daemon VmRSS too high: {vm_rss_kib} KiB"
        assert vm_hwm_kib < 20 * 1024, f"daemon VmHWM too high: {vm_hwm_kib} KiB"
        proc.send_signal(signal.SIGTERM)
        assert proc.wait(timeout=5) == 0
        print("PASS daemon RSS ceiling (< 20 MiB)")
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()


def test_cross_provider_routing_and_chunking(bin_path, tmp_dir):
    sdir = os.path.join(tmp_dir, "route_state")
    os.makedirs(sdir, mode=0o700, exist_ok=True)
    env = {"AUTH_ROUTER_STATE_DIR": sdir}

    run_cmd(bin_path, ["--direct", "add", "antigravity-cli", "agy1", "sk-agy-1"], env=env)
    run_cmd(bin_path, ["--direct", "add", "anthropic", "ant1", "sk-ant-1"], env=env)
    run_cmd(bin_path, ["--direct", "add", "openai-codex", "cod1", "sk-cod-1"], env=env)
    run_cmd(bin_path, ["--direct", "add", "deepseek", "ds1", "sk-ds-1"], env=env)

    chain = [
        "antigravity-cli:gemini-4-neon",
        "anthropic:claude-opus-5-5",
        "openai-codex:gpt-5",
        "deepseek:deepseek-chat",
    ]

    r1 = json.loads(run_cmd(bin_path, ["--direct", "route"] + chain + ["--json"], env=env).stdout)
    assert r1["http_status"] == 200
    assert r1["provider"] == "antigravity-cli"
    assert r1["model"] == "gemini-4-neon"
    assert r1["login_id"] == "agy1"
    assert r1["route_rank"] == 0
    assert r1["is_fallback"] is False
    assert r1["primary_retry_ms"] == 0

    adv = json.loads(
        run_cmd(
            bin_path,
            ["--direct", "route"] + chain + ["--exclude-provider", "antigravity-cli", "--json"],
            env=env,
        ).stdout
    )
    assert adv["http_status"] == 200
    assert adv["provider"] == "anthropic"
    assert adv["model"] == "claude-opus-5-5"
    assert adv["is_fallback"] is False

    run_cmd(bin_path, ["--direct", "cool", "antigravity-cli:agy1", "gemini-4-neon", "32m17s"], env=env)
    r2 = json.loads(run_cmd(bin_path, ["--direct", "route"] + chain + ["--json"], env=env).stdout)
    assert r2["http_status"] == 200
    assert r2["provider"] == "anthropic"
    assert r2["model"] == "claude-opus-5-5"
    assert r2["route_rank"] == 1
    assert r2["is_fallback"] is True
    assert 1900000 <= r2["primary_retry_ms"] <= 1937000, r2

    future_ms = int(time.time() * 1000) + 2000000
    r3 = json.loads(
        run_cmd(bin_path, ["--direct", "route"] + chain + ["--now-ms", str(future_ms), "--json"], env=env).stdout
    )
    assert r3["http_status"] == 200
    assert r3["provider"] == "antigravity-cli"
    assert r3["is_fallback"] is False
    assert r3["primary_retry_ms"] == 0

    p_over = run_cmd(bin_path, ["--direct", "token", "a" * 129, "m"], env=env, check=False)
    assert p_over.returncode != 0 and "too long" in p_over.stderr

    sdir2 = os.path.join(tmp_dir, "chunk_state")
    os.makedirs(sdir2, mode=0o700, exist_ok=True)
    env2 = {"AUTH_ROUTER_STATE_DIR": sdir2}
    for i in range(8):
        run_cmd(bin_path, ["--direct", "add", "deepseek", f"d{i}", f"sk-d{i}"], env=env2)
    run_cmd(bin_path, ["--direct", "order"] + [f"d{i}" for i in range(8)], env=env2)
    for i in range(5):
        run_cmd(bin_path, ["--direct", "cool", f"deepseek:d{i}", "deepseek-chat", "1h5m"], env=env2)
    rc = json.loads(run_cmd(bin_path, ["--direct", "token", "deepseek", "deepseek-chat", "--json"], env=env2).stdout)
    assert rc["http_status"] == 200 and rc["login_id"] == "d5"

    run_cmd(bin_path, ["--direct", "top", "d7"], env=env2)
    rc2 = json.loads(run_cmd(bin_path, ["--direct", "token", "deepseek", "deepseek-chat", "--json"], env=env2).stdout)
    assert rc2["http_status"] == 200 and rc2["login_id"] == "d7"

    run_cmd(bin_path, ["--direct", "rotate", "deepseek"], env=env2)
    rc3 = json.loads(run_cmd(bin_path, ["--direct", "token", "deepseek", "deepseek-chat", "--json"], env=env2).stdout)
    assert rc3["http_status"] == 200 and rc3["login_id"] == "d5"
    print("PASS cross-provider routing + advisor exclude + cooldown sweep + 8-login pool")


def test_crest_auth_compat(bin_path, tmp_dir):
    sdir = os.path.join(tmp_dir, "compat_state")
    os.makedirs(sdir, mode=0o700, exist_ok=True)
    future = int(time.time() * 1000) + 3600000
    with open(os.path.join(sdir, "logins"), "w") as f:
        f.write(f"work\ttok-work\tref-work\t{future}\t0\t\n")
        f.write(f"personal\ttok-pers\tref-pers\t{future}\t0\t\n")
    with open(os.path.join(sdir, "order"), "w") as f:
        f.write("personal\nwork\n")
    with open(os.path.join(sdir, "auth.json"), "w") as f:
        json.dump({"deepseek": {"type": "api_key", "provider": "deepseek", "key": "sk-compat-9999"}}, f)

    env = {"CREST_AUTH_HOME": sdir}
    tok = run_cmd(bin_path, ["--direct", "token", "anthropic", "claude-opus-5-5"], env=env).stdout.strip()
    assert tok == "tok-pers"
    lst = json.loads(run_cmd(bin_path, ["--direct", "json", "list"], env=env).stdout)
    assert lst["ok"] is True and lst["count"] == 3
    run_cmd(bin_path, ["--direct", "remove", "personal"], env=env)
    tok2 = run_cmd(bin_path, ["--direct", "token", "anthropic", "claude-opus-5-5"], env=env).stdout.strip()
    assert tok2 == "tok-work"
    assert stat.S_IMODE(os.stat(os.path.join(sdir, "logins")).st_mode) == 0o600
    print("PASS crest-auth state format and CLI compatibility")


def test_sizes(bin_path, closure_size_file):
    bin_bytes = os.stat(bin_path).st_size
    bin_mib = bin_bytes / (1024.0 * 1024.0)
    print(f"REPORT binary_size={bin_bytes} bytes ({bin_mib:.2f} MiB)")
    if closure_size_file and os.path.exists(closure_size_file):
        with open(closure_size_file) as f:
            closure_bytes = int(f.read().strip())
        closure_mib = closure_bytes / (1024.0 * 1024.0)
        old_crest_mib = 88.2
        c_curl_mib = 66.1
        print(
            f"REPORT closure_size={closure_bytes} bytes ({closure_mib:.1f} MiB) "
            f"vs crest-auth ({old_crest_mib:.1f} MiB, -{(1.0 - closure_mib / old_crest_mib) * 100:.1f}%) "
            f"vs C+curl ({c_curl_mib:.1f} MiB, -{(1.0 - closure_mib / c_curl_mib) * 100:.1f}%)"
        )
        assert closure_mib < c_curl_mib, f"closure {closure_mib:.1f} MiB not smaller than C+curl {c_curl_mib} MiB"
    print("PASS binary + closure size report")



def test_oauth_proactive_and_preexpiry_and_ua(bin_path, tmp_dir):
    crt, key = gen_self_signed_cert(tmp_dir, "oa_cert")
    srv, port, st = start_https_token_server(crt, key, delay_s=0.0, chunked=False)
    try:
        sdir = os.path.join(tmp_dir, "oa_direct_state")
        os.makedirs(sdir, mode=0o700, exist_ok=True)
        near_exp = int(time.time() * 1000) + 30000
        with open(os.path.join(sdir, "auth.json"), "w") as f:
            json.dump(
                {
                    "xai1": {
                        "type": "oauth",
                        "provider": "xai",
                        "access": "old-oa-direct",
                        "refresh": "ref-oa-direct",
                        "expires": near_exp,
                    }
                },
                f,
            )
        env_d = {
            "AUTH_ROUTER_STATE_DIR": sdir,
            "XAI_OAUTH_TOKEN_URL": f"https://localhost:{port}/token",
            "AUTH_ROUTER_CA_FILE": crt,
        }
        r_dir = json.loads(
            run_cmd(bin_path, ["--direct", "token", "xai", "grok-3", "--json"], env=env_d).stdout
        )
        assert r_dir["ok"] is True and r_dir["access"] == "fresh-tok-1", r_dir
        assert st["count"] == 1
        assert st["ua_headers"][-1] == ["auth-router/0.1"], st["ua_headers"]

        with open(os.path.join(sdir, "logins"), "w") as f:
            f.write(f"ua_login\told-tok\tref-ua\t{near_exp}\t0\t\n")
        env_ua = dict(env_d)
        env_ua["CREST_AUTH_TOKEN_URL"] = f"https://localhost:{port}/token"
        r_ua = json.loads(
            run_cmd(bin_path, ["--direct", "token", "anthropic", "claude-opus-5-5", "--json"], env=env_ua).stdout
        )
        assert r_ua["ok"] is True and r_ua["access"] == "fresh-tok-2", r_ua
        assert len(st["ua_headers"][-1]) == 1 and st["ua_headers"][-1][0].startswith("claude-cli/"), st["ua_headers"]

        sdir2 = os.path.join(tmp_dir, "oa_daemon_state")
        os.makedirs(sdir2, mode=0o700, exist_ok=True)
        sock = os.path.join(tmp_dir, "oa_daemon.sock")
        near_exp2 = int(time.time() * 1000) + 30000
        with open(os.path.join(sdir2, "auth.json"), "w") as f:
            json.dump(
                {
                    "xai2": {
                        "type": "oauth",
                        "provider": "xai",
                        "access": "old-oa-daemon",
                        "refresh": "ref-oa-daemon",
                        "expires": near_exp2,
                    }
                },
                f,
            )
        denv = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "AUTH_ROUTER_STATE_DIR": sdir2,
            "XAI_OAUTH_TOKEN_URL": f"https://localhost:{port}/token",
            "AUTH_ROUTER_CA_FILE": crt,
        }
        proc = subprocess.Popen(
            [bin_path, "daemon", "--socket", sock, "--state-dir", sdir2, "--no-bg-refresh"],
            env=denv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            for _ in range(50):
                if os.path.exists(sock):
                    break
                time.sleep(0.05)
            r_dm = unix_rpc_raw(sock, json.dumps({"v": 1, "op": "token", "provider": "xai", "model": "grok-3"}))
            assert r_dm["ok"] is True and r_dm["access"] == "fresh-tok-3", r_dm
            assert st["count"] == 3
        finally:
            proc.send_signal(signal.SIGTERM)
            proc.wait(timeout=5)

        sdir3 = os.path.join(tmp_dir, "oa_bg_state")
        os.makedirs(sdir3, mode=0o700, exist_ok=True)
        sock3 = os.path.join(tmp_dir, "oa_bg.sock")
        near_exp3 = int(time.time() * 1000) + 90000
        with open(os.path.join(sdir3, "auth.json"), "w") as f:
            json.dump(
                {
                    "xai3": {
                        "type": "oauth",
                        "provider": "xai",
                        "access": "old-oa-bg",
                        "refresh": "ref-oa-bg",
                        "expires": near_exp3,
                    }
                },
                f,
            )
        denv3 = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "AUTH_ROUTER_STATE_DIR": sdir3,
            "XAI_OAUTH_TOKEN_URL": f"https://localhost:{port}/token",
            "AUTH_ROUTER_CA_FILE": crt,
            "AUTH_ROUTER_BG_CHECK_MS": "100",
            "AUTH_ROUTER_BG_LEAD_MS": "120000",
        }
        proc3 = subprocess.Popen(
            [bin_path, "daemon", "--socket", sock3, "--state-dir", sdir3],
            env=denv3,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            for _ in range(50):
                if os.path.exists(sock3):
                    break
                time.sleep(0.05)
            refreshed = False
            for _ in range(40):
                with open(os.path.join(sdir3, "auth.json")) as f:
                    data = json.load(f)
                if data["xai3"]["access"] == "fresh-tok-4":
                    refreshed = True
                    break
                time.sleep(0.1)
            assert refreshed, "oauth proactive bg refresh did not update auth.json"
            time.sleep(0.4)
            assert st["count"] == 4, f"oauth bg refresh fork-looped: count={st['count']}"
        finally:
            proc3.send_signal(signal.SIGTERM)
            proc3.wait(timeout=5)
        print("PASS oauth pre-expiry + proactive bg refresh + single User-Agent header")
    finally:
        srv.shutdown()
        srv.server_close()


def test_unavail_and_order_validation(bin_path, tmp_dir):
    sdir = os.path.join(tmp_dir, "unavail_order_state")
    os.makedirs(sdir, mode=0o700, exist_ok=True)
    sock = os.path.join(tmp_dir, "unavail_order.sock")
    env = {"AUTH_ROUTER_STATE_DIR": sdir}
    run_cmd(bin_path, ["--direct", "add", "deepseek", "d1", "sk-d1"], env=env)
    run_cmd(bin_path, ["--direct", "add", "deepseek", "d2", "sk-d2"], env=env)
    run_cmd(bin_path, ["--direct", "add", "openai", "o1", "sk-o1"], env=env)

    denv = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "AUTH_ROUTER_STATE_DIR": sdir}
    proc = subprocess.Popen(
        [bin_path, "daemon", "--socket", sock, "--state-dir", sdir, "--no-bg-refresh"],
        env=denv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        for _ in range(50):
            if os.path.exists(sock):
                break
            time.sleep(0.05)

        r_ord = unix_rpc_raw(sock, json.dumps({"v": 1, "op": "order", "names": ["d1", "d2", "o1"]}))
        assert r_ord["ok"] is True, r_ord

        r_u = unix_rpc_raw(sock, json.dumps({"v": 1, "op": "unavail", "id": "deepseek:d1", "model": "deepseek-chat"}))
        assert r_u["ok"] is True and r_u["marked"] is True, r_u

        r_rt = unix_rpc_raw(
            sock,
            json.dumps({
                "v": 1,
                "op": "route",
                "routes": [
                    {"provider": "deepseek", "model": "deepseek-chat"},
                    {"provider": "openai", "model": "gpt-5"},
                ],
            }),
        )
        assert r_rt["ok"] is True and r_rt["http_status"] == 200 and r_rt["login_id"] == "d2", r_rt

        r_u2 = unix_rpc_raw(sock, json.dumps({"v": 1, "op": "unavail", "id": "deepseek:d2", "model": "deepseek-chat"}))
        assert r_u2["ok"] is True and r_u2["marked"] is True, r_u2

        r_rt2 = unix_rpc_raw(
            sock,
            json.dumps({
                "v": 1,
                "op": "route",
                "routes": [
                    {"provider": "deepseek", "model": "deepseek-chat"},
                    {"provider": "openai", "model": "gpt-5"},
                ],
            }),
        )
        assert r_rt2["ok"] is True and r_rt2["provider"] == "openai" and r_rt2["login_id"] == "o1", r_rt2

        for bad_req in [
            {"v": 1, "op": "order", "names": ["nonexistent"]},
            {"v": 1, "op": "order", "names": ["d1", "d1"]},
            {"v": 1, "op": "order", "names": ["d1\nd2"]},
            {"v": 1, "op": "order", "names": [""]},
            {"v": 1, "op": "top", "name": "nonexistent"},
            {"v": 1, "op": "top", "name": "d1\n"},
        ]:
            rb = unix_rpc_raw(sock, json.dumps(bad_req))
            assert rb["ok"] is False, f"expected rejection for {bad_req}, got {rb}"

        with open(os.path.join(sdir, "order"), "w") as f:
            f.write("stale_deleted_cred\nd2\nd1\n")
        r_rt3 = unix_rpc_raw(
            sock,
            json.dumps({"v": 1, "op": "token", "provider": "openai", "model": "gpt-5"}),
        )
        assert r_rt3["ok"] is True and r_rt3["login_id"] == "o1", r_rt3
        print("PASS unavail daemon op + order/top validation + stale order tolerance")
    finally:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=5)


def test_restricted_now_ms_cool_validation_and_slow_reader(bin_path, tmp_dir):
    sdir = os.path.join(tmp_dir, "sec_state")
    os.makedirs(sdir, mode=0o700, exist_ok=True)
    sock = os.path.join(tmp_dir, "sec.sock")
    rsock = os.path.join(tmp_dir, "sec-r.sock")
    env = {"AUTH_ROUTER_STATE_DIR": sdir}
    run_cmd(bin_path, ["--direct", "add", "deepseek", "d1", "sk-d1"], env=env)
    run_cmd(bin_path, ["--direct", "add", "deepseek", "d2", "sk-d2"], env=env)
    run_cmd(bin_path, ["--direct", "order", "d1", "d2"], env=env)
    run_cmd(bin_path, ["--direct", "cool", "deepseek:d1", "deepseek-chat", "30m"], env=env)

    denv = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "AUTH_ROUTER_STATE_DIR": sdir,
        "AUTH_ROUTER_CLIENT_IDLE_MS": "400",
    }
    proc = subprocess.Popen(
        [
            bin_path,
            "daemon",
            "--socket",
            sock,
            "--restricted-socket",
            rsock,
            "--state-dir",
            sdir,
            "--no-bg-refresh",
        ],
        env=denv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        for _ in range(50):
            if os.path.exists(sock) and os.path.exists(rsock):
                break
            time.sleep(0.05)

        future_ms = int(time.time() * 1000) + 2000000
        req_route = {
            "v": 1,
            "op": "route",
            "routes": [{"provider": "deepseek", "model": "deepseek-chat"}],
            "now_ms": future_ms,
        }
        rp = unix_rpc_raw(sock, json.dumps(req_route))
        assert rp["ok"] is True and rp["login_id"] == "d1", rp

        rr = unix_rpc_raw(rsock, json.dumps(req_route))
        assert rr["ok"] is True and rr["login_id"] == "d2", rr

        for bad_cool in [
            {"v": 1, "op": "cool", "id": "deepseek:d1\tmodel", "model": "m", "duration": "60s"},
            {"v": 1, "op": "cool", "id": "deepseek:d1\nfoo", "model": "m", "duration": "60s"},
            {"v": 1, "op": "cool", "id": "deepseek:d1", "model": "m", "duration": "NaN s"},
            {"v": 1, "op": "cool", "id": "deepseek:d1", "model": "m", "duration": "inf s"},
            {"v": 1, "op": "cool", "id": "deepseek:d1", "model": "m", "duration": "1e300 s"},
            {"v": 1, "op": "cool", "id": "deepseek:d1", "model": "m", "duration": "30d"},
            {"v": 1, "op": "cool", "id": "deepseek:d1", "model": "m", "cooldown_ms": 100000000000},
            {"v": 1, "op": "cool", "id": "deepseek:d1", "model": "m", "cooldown_ms": -100},
        ]:
            rc = unix_rpc_raw(rsock, json.dumps(bad_cool))
            assert rc["ok"] is False, f"expected cool rejection for {bad_cool}, got {rc}"

        slow = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        slow.settimeout(2)
        slow.connect(sock)
        slow.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        payload = (json.dumps({"v": 1, "op": "list"}) + "\n").encode() * 64
        slow.sendall(payload)
        time.sleep(0.9)
        evicted = False
        try:
            while True:
                data = slow.recv(4096)
                if not data:
                    evicted = True
                    break
        except (ConnectionResetError, BrokenPipeError, OSError):
            evicted = True
        slow.close()
        assert evicted, "slow-reader client was not evicted after idle timeout"

        r_ping = unix_rpc_raw(sock, json.dumps({"v": 1, "op": "ping"}))
        assert r_ping["ok"] is True
        print("PASS restricted now_ms ignored + cool validation + slow-reader eviction")
    finally:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=5)


def test_sigterm_inflight_and_pipelined_refresh(bin_path, tmp_dir):
    crt, key = gen_self_signed_cert(tmp_dir, "pipe_cert")
    srv_fast, port_fast, _ = start_https_token_server(crt, key, delay_s=0.25, chunked=False)
    sdir = os.path.join(tmp_dir, "pipe_state")
    os.makedirs(sdir, mode=0o700, exist_ok=True)
    sock = os.path.join(tmp_dir, "pipe.sock")
    past = int(time.time() * 1000) - 60000
    with open(os.path.join(sdir, "logins"), "w") as f:
        f.write(f"p1\told-p1\tref-p1\t{past}\t0\t\n")
    denv = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "AUTH_ROUTER_STATE_DIR": sdir,
        "CREST_AUTH_TOKEN_URL": f"https://localhost:{port_fast}/token",
        "AUTH_ROUTER_CA_FILE": crt,
    }
    proc = subprocess.Popen(
        [bin_path, "daemon", "--socket", sock, "--state-dir", sdir, "--no-bg-refresh"],
        env=denv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        for _ in range(50):
            if os.path.exists(sock):
                break
            time.sleep(0.05)
        sc = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sc.settimeout(5)
        sc.connect(sock)
        req1 = json.dumps({"v": 1, "op": "token", "provider": "anthropic", "model": "claude-opus-5-5"})
        req2 = json.dumps({"v": 1, "op": "ping"})
        sc.sendall((req1 + "\n" + req2 + "\n").encode())
        sc.shutdown(socket.SHUT_WR)
        buf = b""
        while True:
            chunk = sc.recv(4096)
            if not chunk:
                break
            buf += chunk
        sc.close()
        lines = [json.loads(ln) for ln in buf.decode().splitlines() if ln.strip()]
        assert len(lines) == 2, f"expected 2 pipelined responses, got {lines}"
        assert lines[0]["ok"] is True and lines[0]["access"] == "fresh-tok-1", lines[0]
        assert lines[1]["ok"] is True and "pid" in lines[1], lines[1]
    finally:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=5)
        srv_fast.shutdown()
        srv_fast.server_close()

    srv_slow, port_slow, _ = start_https_token_server(crt, key, delay_s=8.0, chunked=False)
    sdir2 = os.path.join(tmp_dir, "term_state")
    os.makedirs(sdir2, mode=0o700, exist_ok=True)
    sock2 = os.path.join(tmp_dir, "term.sock")
    with open(os.path.join(sdir2, "logins"), "w") as f:
        f.write(f"s1\told-s1\tref-s1\t{past}\t0\t\n")
    denv2 = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "AUTH_ROUTER_STATE_DIR": sdir2,
        "CREST_AUTH_TOKEN_URL": f"https://localhost:{port_slow}/token",
        "AUTH_ROUTER_CA_FILE": crt,
    }
    proc2 = subprocess.Popen(
        [bin_path, "daemon", "--socket", sock2, "--state-dir", sdir2, "--no-bg-refresh"],
        env=denv2,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        for _ in range(50):
            if os.path.exists(sock2):
                break
            time.sleep(0.05)
        st_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        st_sock.settimeout(5)
        st_sock.connect(sock2)
        st_sock.sendall(
            (json.dumps({"v": 1, "op": "token", "provider": "anthropic", "model": "claude-opus-5-5"}) + "\n").encode()
        )
        time.sleep(0.25)
        t0 = time.monotonic()
        proc2.send_signal(signal.SIGTERM)
        rc = proc2.wait(timeout=3)
        elapsed = time.monotonic() - t0
        st_sock.close()
        assert rc == 0, f"expected clean SIGTERM exit 0, got {rc}"
        assert elapsed < 2.0, f"SIGTERM hung with in-flight worker: {elapsed:.2f}s"
        print(f"PASS pipelined refresh + prompt SIGTERM with in-flight worker ({elapsed:.2f}s)")
    finally:
        if proc2.poll() is None:
            proc2.kill()
            proc2.wait()
        srv_slow.shutdown()
        srv_slow.server_close()


def main():
    bin_path = sys.argv[1]
    closure_size_file = sys.argv[2] if len(sys.argv) > 2 else None
    test_ldd(bin_path)
    test_sizes(bin_path, closure_size_file)
    with tempfile.TemporaryDirectory(prefix="auth-router-e2e-") as tmp:
        test_tls_and_chunked(bin_path, tmp)
        test_http_tls_adversarial(bin_path, tmp)
        test_daemon_full(bin_path, tmp)
        test_aba_and_half_close(bin_path, tmp)
        test_proactive_bg_refresh(bin_path, tmp)
        test_unfinished_and_acp_filtering(bin_path, tmp)
        test_daemon_rss_ceiling(bin_path, tmp)
        test_cross_provider_routing_and_chunking(bin_path, tmp)
        test_crest_auth_compat(bin_path, tmp)
        test_oauth_proactive_and_preexpiry_and_ua(bin_path, tmp)
        test_unavail_and_order_validation(bin_path, tmp)
        test_restricted_now_ms_cool_validation_and_slow_reader(bin_path, tmp)
        test_sigterm_inflight_and_pipelined_refresh(bin_path, tmp)
    print("ALL E2E PASSED")


if __name__ == "__main__":
    main()
