import concurrent.futures
import fcntl
import http.server
import json
import os
import pty
import select
import signal
import socket
import ssl
import stat
import struct
import subprocess
import sys
import tempfile
import termios
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


def gen_self_signed_cert(tmp_dir, name, cn="localhost", san="DNS:localhost,IP:127.0.0.1", key_args=None):
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
    kargs = key_args if key_args is not None else ["-newkey", "rsa:2048"]
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            *kargs,
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


def start_https_token_server(crt, key, delay_s=0.0, chunked=False, tls_version=None):
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
    if tls_version is not None:
        ctx.minimum_version = tls_version
        ctx.maximum_version = tls_version
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


def test_static_binary(bin_path):
    pd = subprocess.run(["readelf", "-d", bin_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
    needed = [ln.strip() for ln in pd.stdout.splitlines() if "(NEEDED)" in ln]
    assert not needed, f"binary has dynamic NEEDED entries: {needed}"

    pl = subprocess.run(["readelf", "-l", bin_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
    interp = [ln.strip() for ln in pl.stdout.splitlines() if "INTERP" in ln]
    assert not interp, f"binary has PT_INTERP header: {interp}"

    pldd = subprocess.run(["ldd", bin_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    combined = (pldd.stdout + "\n" + pldd.stderr).lower()
    assert "not a dynamic executable" in combined or "statically linked" in combined, combined
    print("PASS fully static binary (0 DT_NEEDED, no PT_INTERP)")


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
    finally:
        srv.shutdown()
        srv.server_close()

    ec_crt, ec_key = gen_self_signed_cert(
        tmp_dir, "ca_ec", key_args=["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1"]
    )
    cases = [
        ("rsa_tls12", crt1, key1, ssl.TLSVersion.TLSv1_2),
        ("rsa_tls13", crt1, key1, ssl.TLSVersion.TLSv1_3),
        ("ec_tls12", ec_crt, ec_key, ssl.TLSVersion.TLSv1_2),
        ("ec_tls13", ec_crt, ec_key, ssl.TLSVersion.TLSv1_3),
    ]
    for cname, ccrt, ckey, tver in cases:
        csrv, cport, cst = start_https_token_server(ccrt, ckey, delay_s=0.0, chunked=False, tls_version=tver)
        try:
            csdir = os.path.join(tmp_dir, f"tls_{cname}")
            os.makedirs(csdir, mode=0o700, exist_ok=True)
            with open(os.path.join(csdir, "logins"), "w") as f:
                f.write("main\told-tok\tref-tok\t1000\t0\t\n")
            p_untrusted = run_cmd(
                bin_path,
                ["--direct", "token", "anthropic", "claude-opus-5-5", "--json"],
                env={
                    "AUTH_ROUTER_STATE_DIR": csdir,
                    "CREST_AUTH_TOKEN_URL": f"https://localhost:{cport}/token",
                    "SSL_CERT_FILE": crt2,
                },
                check=False,
            )
            assert p_untrusted.returncode != 0, f"{cname}: untrusted cert must fail"
            assert "certificate verification failed" in p_untrusted.stderr.lower(), f"{cname}: {p_untrusted.stderr}"
            p_good = run_cmd(
                bin_path,
                ["--direct", "token", "anthropic", "claude-opus-5-5", "--json"],
                env={
                    "AUTH_ROUTER_STATE_DIR": csdir,
                    "CREST_AUTH_TOKEN_URL": f"https://localhost:{cport}/token",
                    "SSL_CERT_FILE": ccrt,
                },
            )
            cdata = json.loads(p_good.stdout)
            assert cdata["ok"] is True and cdata["access"] == "fresh-tok-1", cdata
            assert cst["count"] == 1
        finally:
            csrv.shutdown()
            csrv.server_close()

    print("PASS tls 1.2 + tls 1.3 (RSA + ECDSA) + chunked HTTPS + untrusted cert rejection")


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


def test_sizes(bin_path, closure_size_file, store_paths_file):
    bin_bytes = os.stat(bin_path).st_size
    bin_mib = bin_bytes / (1024.0 * 1024.0)
    print(f"REPORT binary_size={bin_bytes} bytes ({bin_mib:.2f} MiB)")
    if closure_size_file and os.path.exists(closure_size_file):
        with open(closure_size_file) as f:
            closure_bytes = int(f.read().strip())
        closure_mib = closure_bytes / (1024.0 * 1024.0)
        old_crest_mib = 88.2
        c_curl_mib = 66.1
        glibc_static_mbedtls_mib = 37.5
        print(
            f"REPORT closure_size={closure_bytes} bytes ({closure_mib:.2f} MiB) "
            f"vs glibc ({glibc_static_mbedtls_mib:.1f} MiB, -{(1.0 - closure_mib / glibc_static_mbedtls_mib) * 100:.1f}%) "
            f"vs crest-auth ({old_crest_mib:.1f} MiB, -{(1.0 - closure_mib / old_crest_mib) * 100:.1f}%) "
            f"vs C+curl ({c_curl_mib:.1f} MiB, -{(1.0 - closure_mib / c_curl_mib) * 100:.1f}%)"
        )
        assert closure_mib < 2.0, f"closure {closure_mib:.2f} MiB exceeds 2.0 MiB ceiling"
    if store_paths_file and os.path.exists(store_paths_file):
        with open(store_paths_file) as f:
            paths = [ln.strip() for ln in f if ln.strip()]
        print(f"REPORT store_paths={len(paths)}")
        assert len(paths) == 1, f"expected exactly 1 runtime store path, got {len(paths)}: {paths}"
    print("PASS binary + closure size + single store-path check")



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



def test_order_lock_atomic_rmw(bin_path, tmp_dir):
    sdir = os.path.join(tmp_dir, "order_lock_state")
    os.makedirs(sdir, mode=0o700, exist_ok=True)
    env = {"AUTH_ROUTER_STATE_DIR": sdir}
    run_cmd(bin_path, ["--direct", "add", "deepseek", "d1", "sk-d1"], env=env)
    run_cmd(bin_path, ["--direct", "add", "deepseek", "d2", "sk-d2"], env=env)
    run_cmd(bin_path, ["--direct", "add", "deepseek", "d3", "sk-d3"], env=env)
    run_cmd(bin_path, ["--direct", "order", "d1", "d2", "d3"], env=env)

    lock_path = os.path.join(sdir, "order.lock")
    order_path = os.path.join(sdir, "order")
    lfd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(lfd, fcntl.LOCK_EX)
        clean_env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "AUTH_ROUTER_STATE_DIR": sdir}
        p = subprocess.Popen(
            [bin_path, "--direct", "top", "d3"],
            env=clean_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        time.sleep(0.15)
        assert p.poll() is None, "top did not wait for order.lock"
        with open(order_path, "w") as f:
            f.write("d2\nd1\nd3\n")
        fcntl.flock(lfd, fcntl.LOCK_UN)
        out, err = p.communicate(timeout=5)
        assert p.returncode == 0, f"top failed: {err}"
    finally:
        os.close(lfd)

    with open(order_path) as f:
        lines = [ln.strip() for ln in f.read().splitlines() if ln.strip()]
    assert lines == ["d3", "d2", "d1"], f"order RMW lost concurrent update: {lines}"
    print("PASS atomic /order.lock read-modify-write")



def test_concurrent_direct_oauth_refresh_serialization(bin_path, tmp_dir):
    crt, key = gen_self_signed_cert(tmp_dir, "direct_oa")
    srv, port, state = start_https_token_server(crt, key, delay_s=0.4, chunked=False)
    sdir = os.path.join(tmp_dir, "direct_oa_serial")
    os.makedirs(sdir, mode=0o700, exist_ok=True)
    past = int(time.time() * 1000) - 60_000
    auth_json = {
        "xai-main": {
            "provider": "xai",
            "type": "oauth",
            "access": "old-xai",
            "refresh": "ref-xai",
            "expires": past,
            "project": "proj-x",
            "account_id": "acct-x",
        }
    }
    with open(os.path.join(sdir, "auth.json"), "w") as f:
        json.dump(auth_json, f)
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "AUTH_ROUTER_STATE_DIR": sdir,
        "XAI_OAUTH_TOKEN_URL": f"https://localhost:{port}/token",
        "AUTH_ROUTER_CA_FILE": crt,
    }
    try:
        p1 = subprocess.Popen(
            [bin_path, "--direct", "token", "xai", "--json"],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        p2 = subprocess.Popen(
            [bin_path, "--direct", "token", "xai", "--json"],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        out1, err1 = p1.communicate(timeout=10)
        out2, err2 = p2.communicate(timeout=10)
        assert p1.returncode == 0, f"p1 failed: {err1}"
        assert p2.returncode == 0, f"p2 failed: {err2}"
        r1 = json.loads(out1)
        r2 = json.loads(out2)
        assert r1["access"] == "fresh-tok-1", r1
        assert r2["access"] == "fresh-tok-1", r2
        assert r1["project"] == "proj-x" and r1["account_id"] == "acct-x", r1
        assert r2["project"] == "proj-x" and r2["account_id"] == "acct-x", r2
        assert state["count"] == 1, f"expected exactly 1 refresh POST, got {state['count']}"
        print("PASS concurrent --direct OAuth refresh serialization (1 POST)")
    finally:
        srv.shutdown()
        srv.server_close()


def test_crest_auth_dropin_compat(bin_path, tmp_dir):
    crest_path = os.path.join(os.path.dirname(bin_path), "crest-auth")
    assert os.path.islink(crest_path), f"missing crest-auth symlink at {crest_path}"
    assert os.path.realpath(crest_path) == os.path.realpath(bin_path)

    sdir = os.path.join(tmp_dir, "dropin_compat")
    os.makedirs(sdir, mode=0o700, exist_ok=True)
    future = int(time.time() * 1000) + 3_600_000
    with open(os.path.join(sdir, "logins"), "w") as f:
        f.write(f"personal\tacc-personal\tref-personal\t{future}\t0\t\n")
    auth_json = {
        "codex1": {
            "provider": "openai-codex",
            "type": "oauth",
            "access": "oa-codex-tok",
            "refresh": "oa-codex-ref",
            "expires": future,
            "extra": {
                "project": "p-123",
                "account_id": "acc-456",
                "plan": "pro",
            },
        },
        "ds1": {
            "provider": "deepseek",
            "type": "api_key",
            "key": "sk-ds-secret",
        },
        "acp1": {
            "provider": "antigravity-acp",
            "type": "acp",
        },
    }
    with open(os.path.join(sdir, "auth.json"), "w") as f:
        json.dump(auth_json, f)
    env = {"AUTH_ROUTER_STATE_DIR": sdir}

    r_list = json.loads(run_cmd(crest_path, ["--direct", "json", "list"], env=env).stdout)
    logins = r_list["logins"]
    by_name = {x["name"]: x for x in logins}
    assert set(by_name.keys()) == {"personal", "codex1", "ds1"}, logins
    assert by_name["personal"]["kind"] == "login" and by_name["personal"]["state"] == "ok", by_name["personal"]
    assert by_name["codex1"]["kind"] == "oauth" and by_name["codex1"]["state"] == "ok", by_name["codex1"]
    assert by_name["ds1"]["kind"] == "key" and by_name["ds1"]["state"] == "ok", by_name["ds1"]
    cred_names = {x["name"] for x in r_list["credentials"]}
    assert "acp1" in cred_names, r_list["credentials"]

    r_oa = json.loads(run_cmd(crest_path, ["--direct", "json", "token", "openai-codex"], env=env).stdout)
    assert r_oa["login"] == "codex1" and r_oa["login_id"] == "codex1", r_oa
    assert r_oa["access"] == "oa-codex-tok", r_oa
    assert r_oa["project"] == "p-123" and r_oa["account_id"] == "acc-456" and r_oa["plan"] == "pro", r_oa
    assert "error" not in r_oa, r_oa

    r_key = json.loads(run_cmd(crest_path, ["--direct", "json", "token", "deepseek"], env=env).stdout)
    assert r_key["login"] == "ds1" and r_key["login_id"] == "ds1", r_key
    assert r_key["key"] == "sk-ds-secret" and r_key["api_key"] == "sk-ds-secret", r_key
    assert "error" not in r_key, r_key

    r_c200 = json.loads(
        run_cmd(crest_path, ["--direct", "json", "cool", "personal", "claude-sonnet-4", "200"], env=env).stdout
    )
    assert r_c200["id"] == "anthropic:personal", r_c200
    assert r_c200["limited"] is False and r_c200["retry"] is False, r_c200

    r_c429 = json.loads(
        run_cmd(
            crest_path,
            ["--direct", "json", "cool", "personal", "claude-sonnet-4", "429", "retry-after=30"],
            env=env,
        ).stdout
    )
    assert r_c429["id"] == "anthropic:personal", r_c429
    assert r_c429["limited"] is True and r_c429["retry"] is True, r_c429

    p_cool = run_cmd(crest_path, ["--direct", "json", "token", "anthropic", "claude-sonnet-4"], env=env)
    assert p_cool.returncode == 0, p_cool.stderr
    r_cool = json.loads(p_cool.stdout)
    assert "error" in r_cool and r_cool["retry"] > 0 and r_cool["retry"] <= 35, r_cool
    assert r_cool["status"] == 429, r_cool

    r_c1 = json.loads(run_cmd(crest_path, ["--direct", "json", "cool", "ds1"], env=env).stdout)
    assert r_c1["id"] == "deepseek:ds1", r_c1
    assert r_c1["limited"] is True and r_c1["retry"] is True, r_c1
    p_ds = run_cmd(crest_path, ["--direct", "json", "token", "deepseek"], env=env)
    assert p_ds.returncode == 0
    r_ds = json.loads(p_ds.stdout)
    assert "error" in r_ds and r_ds["retry"] > 0, r_ds

    print("PASS crest-auth symlink + drop-in JSON list/token/cool compatibility")


def test_forked_tls13_children(bin_path, tmp_dir):
    crt, key = gen_self_signed_cert(
        tmp_dir, "fork_tls13_ec", key_args=["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1"]
    )
    srv, port, st = start_https_token_server(
        crt, key, delay_s=0.15, chunked=False, tls_version=ssl.TLSVersion.TLSv1_3
    )
    sdir = os.path.join(tmp_dir, "fork_tls13_state")
    os.makedirs(sdir, mode=0o700, exist_ok=True)
    sock = os.path.join(tmp_dir, "fork_tls13.sock")
    with open(os.path.join(sdir, "logins"), "w") as f:
        f.write("acct1\told-1\tref-1\t1000\t0\t\n")
    with open(os.path.join(sdir, "auth.json"), "w") as f:
        json.dump(
            {
                "xai1": {
                    "type": "oauth",
                    "provider": "xai",
                    "access": "old-xai",
                    "refresh": "ref-xai",
                    "expires": 1000,
                }
            },
            f,
        )

    denv = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "AUTH_ROUTER_STATE_DIR": sdir,
        "CREST_AUTH_TOKEN_URL": f"https://localhost:{port}/token",
        "XAI_OAUTH_TOKEN_URL": f"https://localhost:{port}/token",
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
        ping = wait_for_daemon(bin_path, sock, denv)
        assert ping["ok"] is True

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
            f1 = ex.submit(
                run_cmd,
                bin_path,
                ["--socket", sock, "token", "anthropic", "claude-opus-5-5", "--json"],
                denv,
            )
            f2 = ex.submit(
                run_cmd,
                bin_path,
                ["--socket", sock, "token", "xai", "grok-4", "--json"],
                denv,
            )
            r1 = json.loads(f1.result().stdout)
            r2 = json.loads(f2.result().stdout)

        assert r1["ok"] is True and r1["credential_id"] == "anthropic:acct1", r1
        assert r2["ok"] is True and r2["credential_id"] == "xai:xai1", r2
        assert {r1["access"], r2["access"]} == {"fresh-tok-1", "fresh-tok-2"}, (r1, r2)
        assert st["count"] == 2, st
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        srv.shutdown()
        srv.server_close()

    print("PASS forked daemon TLS 1.3 children")

def test_sha1_root_ca_chain(bin_path, tmp_dir):
    root_key = os.path.join(tmp_dir, "sha1_root.key")
    root_crt = os.path.join(tmp_dir, "sha1_root.crt")
    root_cfg = os.path.join(tmp_dir, "sha1_root.cnf")
    leaf_key = os.path.join(tmp_dir, "sha1_leaf.key")
    leaf_csr = os.path.join(tmp_dir, "sha1_leaf.csr")
    leaf_crt = os.path.join(tmp_dir, "sha1_leaf.crt")
    leaf_ext = os.path.join(tmp_dir, "sha1_leaf.ext")
    with open(root_cfg, "w") as f:
        f.write(
            "[req]\n"
            "distinguished_name=dn\n"
            "x509_extensions=v3_ca\n"
            "prompt=no\n"
            "[dn]\n"
            "CN=Legacy SHA1 Root CA\n"
            "[v3_ca]\n"
            "basicConstraints=critical,CA:TRUE\n"
            "keyUsage=critical,keyCertSign,cRLSign\n"
        )
    subprocess.run(
        [
            "openssl", "req", "-x509", "-sha1",
            "-newkey", "rsa:2048",
            "-keyout", root_key, "-out", root_crt,
            "-days", "2", "-nodes", "-config", root_cfg,
        ],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        [
            "openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
            "-keyout", leaf_key, "-out", leaf_csr, "-subj", "/CN=localhost",
        ],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    with open(leaf_ext, "w") as f:
        f.write(
            "basicConstraints=CA:FALSE\n"
            "subjectAltName=DNS:localhost,IP:127.0.0.1\n"
            "keyUsage=digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\n"
        )
    subprocess.run(
        [
            "openssl", "x509", "-req", "-sha256",
            "-in", leaf_csr, "-CA", root_crt, "-CAkey", root_key,
            "-CAcreateserial", "-out", leaf_crt, "-days", "2", "-extfile", leaf_ext,
        ],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )

    srv, port, st = start_https_token_server(
        leaf_crt, leaf_key, delay_s=0.0, chunked=False, tls_version=ssl.TLSVersion.TLSv1_3
    )
    sdir = os.path.join(tmp_dir, "sha1_root_state")
    os.makedirs(sdir, mode=0o700, exist_ok=True)
    with open(os.path.join(sdir, "logins"), "w") as f:
        f.write("acct1\told-1\tref-1\t1000\t0\t\n")
    try:
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "AUTH_ROUTER_STATE_DIR": sdir,
            "CREST_AUTH_TOKEN_URL": f"https://localhost:{port}/token",
            "AUTH_ROUTER_CA_FILE": root_crt,
        }
        p = run_cmd(bin_path, ["--direct", "token", "anthropic", "claude-opus-5-5", "--json"], env)
        res = json.loads(p.stdout)
        assert res["ok"] is True and res["access"] == "fresh-tok-1", res
        assert st["count"] == 1, st
    finally:
        srv.shutdown()
        srv.server_close()

    print("PASS SHA-1 root CA + SHA-256 leaf chain verification")


def start_quota_server(crt, key):
    state = {"hits": {}, "lock": threading.Lock(), "slow_vercel": False, "token_posts": 0, "headers": {}}

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def reply(self, code, payload, extra=None):
            body = json.dumps(payload).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def count(self, key):
            with state["lock"]:
                state["hits"][key] = state["hits"].get(key, 0) + 1
                state["headers"][key] = dict(self.headers.items())

        def do_GET(self):
            auth = self.headers.get("Authorization", "")
            if self.path == "/api/oauth/usage":
                tok = auth.removeprefix("Bearer ")
                self.count("anthropic:" + tok)
                if self.headers.get("anthropic-beta") != "oauth-2025-04-20":
                    return self.reply(400, {"error": "missing beta"})
                if tok == "tok-b":
                    return self.reply(429, {"error": "slow down"}, {"Retry-After": "120"})
                if tok in ("tok-a", "fresh-tok-1"):
                    return self.reply(200, {
                        "five_hour": {"utilization": 12.4, "resets_at": "2099-01-01T05:00:00.250000+00:00"},
                        "seven_day": {"utilization": "40", "resets_at": "2099-01-07T00:00:00Z"},
                        "seven_day_sonnet": {"utilization": 7, "resets_at": 4070908800},
                        "seven_day_opus": None,
                        "limits": [{"kind": "weekly_scoped", "percent": 55, "resets_at": "2099-01-07T00:00:00Z", "scope": {"model": {"display_name": "Fable"}}}],
                        "extra_usage": {"is_enabled": True, "utilization": 65.2, "used_credits": 136923.0, "monthly_limit": 210000, "currency": "USD", "decimal_places": 2},
                        "subscription_type": "max",
                    })
                return self.reply(401, {"error": "bad token"})
            if self.path == "/backend-api/wham/usage":
                self.count("codex")
                if auth != "Bearer cx-tok" or self.headers.get("chatgpt-account-id") != "acct-1":
                    return self.reply(403, {"error": "denied"})
                return self.reply(200, {
                    "plan_type": "plus",
                    "rate_limit": {
                        "primary_window": {"used_percent": 40, "limit_window_seconds": 18000, "reset_at": 4070908800},
                        "secondary_window": {"used_percent": 7, "limit_window_seconds": 604800, "reset_after_seconds": 3600},
                    },
                    "spend_control": {"reached": False, "individual_limit": {"unit": "credit", "limit": "30000", "used": "21800.5", "used_percent": 73, "reset_at": 4070908800}},
                })
            if self.path == "/v1/credits":
                self.count("vercel")
                if state["slow_vercel"]:
                    time.sleep(4)
                if auth != "Bearer vck-secret-123" or self.headers.get("ai-gateway-auth-method") != "api-key":
                    return self.reply(401, {"error": "denied"})
                return self.reply(200, {"balance": "12.5", "total_used": "3"})
            self.reply(404, {})

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            _ = self.rfile.read(length) if length > 0 else b""
            if self.path == "/token":
                with state["lock"]:
                    state["token_posts"] += 1
                    n = state["token_posts"]
                return self.reply(200, {"access_token": f"fresh-tok-{n}", "refresh_token": f"fresh-ref-{n}", "expires_in": 3600})
            if self.path == "/v1internal:retrieveUserQuota":
                self.count("agy")
                if self.headers.get("Authorization") != "Bearer agy-access-tok":
                    return self.reply(401, {"error": "denied"})
                return self.reply(200, {"buckets": [
                    {"modelId": "gemini-4-carbon-low", "remainingFraction": 0.75, "resetTime": "2099-01-01T00:00:00Z"},
                    {"modelId": "gemini-4-carbon-high", "remainingFraction": 0.5, "resetTime": "2099-01-02T00:00:00Z"},
                    {"modelId": "gemini-4-neon", "resetTime": "2099-01-03T00:00:00Z"},
                    {"modelId": "internal-feature", "remainingFraction": 1},
                ]})
            self.reply(404, {})

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=crt, keyfile=key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, srv.server_address[1], state


def test_quota_and_atop(bin_path, tmp_dir):
    crt, key = gen_self_signed_cert(tmp_dir, "qcert")
    srv, port, st = start_quota_server(crt, key)
    sdir = os.path.join(tmp_dir, "quota_state")
    os.makedirs(os.path.join(sdir, "antigravity", "gem"), mode=0o700, exist_ok=True)
    future = int(time.time() * 1000) + 3600000
    with open(os.path.join(sdir, "logins"), "w") as f:
        f.write(f"alpha\ttok-a\tref-a\t{future}\t0\t\n")
        f.write(f"beta\ttok-b\tref-b\t{future}\t0\t\n")
        f.write("gamma\texpired-tok\tref-gamma\t1000\t0\t\n")
        f.write("unfin\t\t\t0\t0\tverif\n")
    with open(os.path.join(sdir, "auth.json"), "w") as f:
        json.dump({
            "openai-codex": {"type": "oauth", "provider": "openai-codex", "access": "cx-tok", "refresh": "cx-ref", "expires": future, "extra": {"account_id": "acct-1"}},
            "vercel-ai-gateway": {"type": "api_key", "key": "vck-secret-123"},
            "gem": {"type": "acp", "provider": "antigravity-acp"},
            "deepseek": {"type": "api_key", "provider": "deepseek", "key": "sk-deep-777"},
        }, f)
    with open(os.path.join(sdir, "antigravity", "gem", "crest-login.json"), "w") as f:
        json.dump({"version": 2, "provider": "antigravity-cli", "email": "gem@example.com"}, f)
    agy = os.path.join(tmp_dir, "agy")
    for sub, email, tok in (("aaa", "other@example.com", "agy-wrong-tok"), ("bbb", "gem@example.com", "agy-access-tok")):
        d = os.path.join(agy, "gem", sub, "antigravity-cli")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "antigravity-oauth-token"), "w") as f:
            json.dump({"token": {"access_token": tok, "refresh_token": "agy-ref", "token_type": "Bearer", "expiry": "2099-01-01T00:00:00.000Z"}, "auth_method": "consumer", "id_token_email": email}, f)

    base = f"https://localhost:{port}"
    denv = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "AUTH_ROUTER_STATE_DIR": sdir,
        "AUTH_ROUTER_CA_FILE": crt,
        "CREST_AUTH_TOKEN_URL": f"{base}/token",
        "AUTH_ROUTER_ANTHROPIC_USAGE_URL": f"{base}/api/oauth/usage",
        "CODEX_BASE_URL": f"{base}/backend-api/codex",
        "AUTH_ROUTER_VERCEL_BASE": base,
        "GOOGLE_ANTIGRAVITY_URL": base,
        "AUTH_ROUTER_AGY_ROOT": agy,
        "AUTH_ROUTER_QUOTA_MIN_MS": "0",
        "AUTH_ROUTER_QUOTA_TIMEOUT_MS": "1500",
    }
    sock = os.path.join(tmp_dir, "quota.sock")
    rsock = os.path.join(tmp_dir, "quota-r.sock")
    proc = subprocess.Popen(
        [bin_path, "daemon", "--socket", sock, "--restricted-socket", rsock, "--state-dir", sdir, "--no-bg-refresh"],
        env=denv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        wait_for_daemon(bin_path, sock, denv)
        out = run_cmd(bin_path, ["--socket", sock, "quota", "--json"], env=denv).stdout
        for secret in ("tok-a", "tok-b", "ref-", "cx-tok", "cx-ref", "vck-secret-123", "agy-access-tok", "agy-ref", "fresh-tok", "sk-deep"):
            assert secret not in out, f"quota output leaked {secret}"
        q = json.loads(out)
        assert q["ok"] is True, q
        rows = {r["id"]: r for r in q["accounts"]}
        assert len(rows) == 8, sorted(rows)
        a = rows["anthropic:alpha"]
        wins = {w["label"]: w for w in a["windows"]}
        assert a["status"] == "ok" and a["plan"] == "max", a
        assert wins["5h"]["used"] == 12 and wins["5h"]["resets_ms"] == 4070926800250, wins["5h"]
        assert wins["7d"]["used"] == 40 and wins["7d"]["resets_ms"] == 4071427200000, wins["7d"]
        assert wins["7d sonnet"]["used"] == 7 and wins["7d sonnet"]["resets_ms"] == 4070908800000
        assert wins["7d Fable"]["used"] == 55 and "7d opus" not in wins
        assert wins["monthly"]["used"] == 65 and a["note"] == "USD 1369.23/2100.00", a
        b = rows["anthropic:beta"]
        assert b["status"] == "error" and b["error"] == "HTTP 429 (rate limited), retry after 120s" and b["retry_after_s"] == 120, b
        assert b["windows"] == [] and b["next_ms"] - b["fetched_ms"] >= 120000, b
        g = rows["anthropic:gamma"]
        assert g["status"] == "ok" and st["token_posts"] == 1, (g, st["token_posts"])
        with open(os.path.join(sdir, "logins")) as f:
            assert "fresh-ref-1" in f.read(), "refreshed login must be persisted through the store"
        u = rows["anthropic:unfin"]
        assert u["status"] == "error" and "never finished" in u["error"], u
        c = rows["openai-codex"]
        cw = {w["label"]: w for w in c["windows"]}
        assert c["status"] == "ok" and c["plan"] == "plus", c
        assert cw["5h"]["used"] == 40 and cw["5h"]["resets_ms"] == 4070908800000, cw
        assert cw["7d"]["used"] == 7 and abs(cw["7d"]["resets_ms"] - (q["now_ms"] + 3600000)) < 60000, cw
        assert cw["spend"]["used"] == 73 and c["note"] == "21800/30000 credits", c
        hdr = st["headers"]["codex"]
        assert hdr.get("originator") == "pi" and hdr.get("chatgpt-account-id") == "acct-1"
        v = rows["vercel-ai-gateway"]
        assert v["status"] == "ok" and v["balance"] == "12.50" and v["total_used"] == "3.00", v
        gm = rows["antigravity-acp:gem"]
        gw = {w["label"]: w for w in gm["windows"]}
        assert gm["status"] == "ok" and set(gw) == {"gemini-4-carbon", "gemini-4-neon"}, gm
        assert gw["gemini-4-carbon"]["used"] == 50 and gw["gemini-4-carbon"]["resets_ms"] == 4070908800000, gw
        assert gw["gemini-4-neon"]["used"] == 100, gw
        ds = rows["deepseek"]
        assert ds["status"] == "unsupported", ds

        b_hits = st["hits"]["anthropic:tok-b"]
        q2 = json.loads(run_cmd(bin_path, ["--socket", sock, "quota", "--json"], env=denv).stdout)
        rows2 = {r["id"]: r for r in q2["accounts"]}
        assert st["hits"]["anthropic:tok-b"] == b_hits, "retry-after must hold the 429 account back"
        assert rows2["anthropic:beta"].get("cached") is True and rows2["anthropic:beta"]["status"] == "error"
        assert rows2["deepseek"].get("cached") is True
        assert st["hits"]["codex"] == 2 and not rows2["openai-codex"].get("cached")

        denied = unix_rpc_raw(rsock, json.dumps({"v": 1, "op": "quota"}))
        assert denied["ok"] is False and "restricted" in denied["error"], denied

        st["slow_vercel"] = True
        box = {}

        def slow_call():
            t0 = time.time()
            box["out"] = run_cmd(bin_path, ["--socket", sock, "quota", "--json"], env=denv).stdout
            box["elapsed"] = time.time() - t0

        th = threading.Thread(target=slow_call)
        th.start()
        time.sleep(0.3)
        t0 = time.time()
        ping = unix_rpc_raw(sock, json.dumps({"v": 1, "op": "ping"}))
        assert ping["ok"] is True and time.time() - t0 < 1.0, "daemon must stay responsive during a quota round"
        th.join(timeout=20)
        q3 = json.loads(box["out"])
        rows3 = {r["id"]: r for r in q3["accounts"]}
        assert box["elapsed"] < 3.5, f"slow provider stalled the view: {box['elapsed']:.2f}s"
        assert rows3["vercel-ai-gateway"]["status"] == "error" and "timed out" in rows3["vercel-ai-gateway"]["error"], rows3["vercel-ai-gateway"]
        assert rows3["anthropic:alpha"]["status"] == "ok" and rows3["openai-codex"]["status"] == "ok"
        time.sleep(4)
        st["slow_vercel"] = False

        atop = os.path.join(os.path.dirname(bin_path), "atop")
        assert os.path.islink(atop) and os.readlink(atop) == "auth-router", "atop must be a symlink to auth-router"
        t0 = time.time()
        table = run_cmd(atop, ["--socket", sock], env=denv).stdout
        assert time.time() - t0 < 5
        assert "\x1b" not in table, "piped atop must not emit terminal escapes"
        lines = table.splitlines()
        assert lines[0].split()[:3] == ["PROVIDER", "ACCOUNT", "WINDOW"], lines[0]
        alpha = next(l for l in lines if " alpha " in l)
        assert "5h" in alpha and "12%" in alpha and "#---------" in alpha, alpha
        beta = next(l for l in lines if " beta " in l)
        assert "error" in beta and "HTTP 429" in beta, beta
        assert any("balance $12.50" in l for l in lines), table
        assert any("gemini-4-neon" in l and "100%" in l and "##########" in l for l in lines), table
        for secret in ("tok-a", "cx-tok", "vck-secret-123", "agy-access-tok"):
            assert secret not in table
        aj = json.loads(run_cmd(atop, ["--socket", sock, "--json"], env=denv).stdout)
        assert aj["ok"] is True and len(aj["accounts"]) == 8

        st["slow_vercel"] = True
        dt0 = time.time()
        dq = json.loads(run_cmd(bin_path, ["--state-dir", sdir, "--direct", "quota", "--json"], env=denv).stdout)
        assert time.time() - dt0 < 3.5, "direct mode must not wait on an abandoned probe"
        assert {r["id"]: r for r in dq["accounts"]}["vercel-ai-gateway"]["status"] == "error"
        st["slow_vercel"] = False

        tenv = dict(denv, TERM="xterm-256color", XDG_STATE_HOME=os.path.join(tmp_dir, "quota_xdg"))
        tv = AtopPty(atop, ["--direct"], tenv, 120, 40)
        ready = lambda s: "vercel" in s.text() and "fetching" not in s.text()
        assert tv.pump(ready, timeout=20), tv.scr.text()
        a0, b0 = st["hits"]["anthropic:tok-a"], st["hits"]["anthropic:tok-b"]
        os.write(tv.master, b"r")
        assert tv.pump(lambda s: st["hits"]["anthropic:tok-a"] > a0 and ready(s), timeout=20), "r must refetch in direct mode"
        assert st["hits"]["anthropic:tok-b"] == b0, "direct-mode atop must keep Retry-After across refreshes"
        os.write(tv.master, b"q")
        tv.finish()
        assert tv.proc.returncode == 0
        print("PASS quota op + atop table + parsers + retry-after cache + refresh lock + timeout isolation + restricted denial")
    finally:
        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        srv.shutdown()
        srv.server_close()


ATOP_NOW = 1795224400000
ATOP_ALT_ON = "\x1b[?1049h"
ATOP_ALT_OFF = "\x1b[?1049l"


def atop_fake_quota():
    n = ATOP_NOW
    h, d = 3600000, 86400000
    gem = [("claude-opus-5-5", 0, n + 5 * h), ("claude-sonnet-5-5", 0, n + 5 * h)]
    for m in ("2.5-flash", "2.5-flash-lite", "2.5-flash-thinking", "2.5-pro", "3-flash", "3.1-flash-image",
              "3.1-flash-lite", "3.5-flash-lite", "3.8-flash", "4-argon", "4-carbon", "4-hydrogen",
              "4-hydrogen-sonar", "4-neon"):
        gem.append(("gemini-" + m, 100, n + 5 * d + 2 * h))
    gem.append(("gpt-oss-120b", 12, n + 5 * h))

    def acct(i, prov, name, kind, wins, **extra):
        row = {"id": i, "name": name, "provider": prov, "kind": kind,
               "windows": [dict({"label": l, "used": u}, **({"resets_ms": r} if r else {})) for l, u, r in wins],
               "status": "ok", "fetched_ms": n - 60000, "next_ms": n + 60000, "fails": 0}
        row.update(extra)
        return row

    return {"v": 1, "ok": True, "now_ms": n, "accounts": [
        acct("antigravity-acp:gemini", "antigravity-acp", "gemini", "acp", gem),
        acct("anthropic:personal", "anthropic", "personal", "login",
             [("5h", 16, n + 4 * h + 34 * 60000), ("7d", 64, n + 4 * d), ("7d Fable", 0, n + 4 * d)], plan="max"),
        acct("anthropic:anthropic", "anthropic", "anthropic", "login",
             [("5h", 0, 0), ("7d", 17, n + 3 * d + 18 * h), ("7d Fable", 0, n + 3 * d + 18 * h)]),
        acct("anthropic:CU-enterprise", "anthropic", "CU-enterprise", "login", [("monthly", 65, 0)],
             note="USD 1369.23/2100.00"),
        {"id": "anthropic:beta", "name": "beta", "provider": "anthropic", "kind": "login", "status": "error",
         "error": "HTTP 429 (rate limited), retry after 120s", "retry_after_s": 120, "windows": [],
         "fetched_ms": n - 240000, "next_ms": n + 60000, "fails": 1},
        acct("openai-codex", "openai-codex", "openai-codex", "oauth", [("spend", 73, n + 9 * d + 22 * h)],
             note="21801/30000 credits", plan="business"),
        dict(acct("vercel-ai-gateway", "vercel-ai-gateway", "vercel-ai-gateway", "api_key", []),
             balance="244.78", total_used="41295.29"),
    ]}


def atop_seed_history(path):
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    last = ATOP_NOW - 600000
    series = {
        ("anthropic:personal", "5h"): [min(100, (i * 7) % 60) for i in range(40)],
        ("anthropic:personal", "7d"): [30 + i for i in range(34)],
        ("anthropic:anthropic", "7d"): [5 + (i % 12) for i in range(50)],
        ("anthropic:CU-enterprise", "monthly"): [40 + i // 2 for i in range(48)],
        ("anthropic:CU-enterprise", "$left"): [126000 - i * 1100 for i in range(48)],
        ("openai-codex", "spend"): [50 + i // 3 for i in range(66)],
        ("vercel-ai-gateway", "$balance"): [30000 - i * 120 for i in range(46)],
        ("antigravity-acp:gemini", "claude-opus-5-5"): [0] * 20 + [30, 60, 90, 100, 100, 0, 0],
        ("antigravity-acp:gemini", "gpt-oss-120b"): [i % 20 for i in range(30)],
    }
    with open(path, "w") as f:
        f.write("atop-history 1\n")
        for (i, l), v in series.items():
            f.write(f"{i}\t{l}\t{last}\t{','.join(map(str, v))}\n")


def start_fake_quota_daemon(sock_path, payload):
    state = {"quota": 0}
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(sock_path)
    srv.listen(8)
    body = payload if isinstance(payload, bytes) else (json.dumps(payload) + "\n").encode()

    def serve():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            with c:
                buf = b""
                while b"\n" not in buf:
                    chunk = c.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                try:
                    req = json.loads(buf.split(b"\n")[0] or b"{}")
                except ValueError:
                    req = {}
                if req.get("op") == "quota":
                    state["quota"] += 1
                    c.sendall(body)
                else:
                    c.sendall(b'{"v":1,"ok":false,"error":"unsupported"}\n')

    threading.Thread(target=serve, daemon=True).start()
    return srv, state


class VtScreen:
    def __init__(self, w, h):
        self.raw = ""
        self.snaps = []
        self.resize(w, h)

    def resize(self, w, h):
        self.w, self.h = w, h
        self.grid = [[" "] * w for _ in range(h)]
        self.x = self.y = 0

    def put(self, ch):
        if 0 <= self.y < self.h and 0 <= self.x < self.w:
            self.grid[self.y][self.x] = ch
        self.x += 1

    def csi(self, params, final):
        if final == "H":
            parts = [int(p) if p.isdigit() else 1 for p in (params.split(";") if params else [])] + [1, 1]
            self.y, self.x = parts[0] - 1, parts[1] - 1
        elif final == "J" and params == "2":
            self.grid = [[" "] * self.w for _ in range(self.h)]
        elif final in "hl" and params == "?1049":
            if final == "l":
                self.snaps.append(self.text())
            self.grid = [[" "] * self.w for _ in range(self.h)]

    def feed(self, data):
        self.raw += data
        i = 0
        while i < len(data):
            c = data[i]
            if c == "\x1b" and i + 1 < len(data) and data[i + 1] == "[":
                j = i + 2
                while j < len(data) and not ("\x40" <= data[j] <= "\x7e"):
                    j += 1
                if j >= len(data):
                    break
                self.csi(data[i + 2:j], data[j])
                i = j + 1
                continue
            if c == "\x1b":
                i += 2
                continue
            if c == "\r":
                self.x = 0
            elif c == "\n":
                self.y += 1
            elif c >= " ":
                self.put(c)
            i += 1

    def text(self):
        return "\n".join("".join(r).rstrip() for r in self.grid) + "\n"


class AtopPty:
    def __init__(self, atop, args, env, w, h):
        self.master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", h, w, 0, 0))
        self.proc = subprocess.Popen([atop] + args, stdin=slave, stdout=slave, stderr=slave, env=env,
                                     close_fds=True, start_new_session=True)
        os.close(slave)
        self.scr = VtScreen(w, h)
        self.dec = __import__("codecs").getincrementaldecoder("utf-8")("replace")
        self.pending = ""

    def pump(self, pred, timeout=10.0, quiet=0.4):
        end = time.time() + timeout
        last = time.time()
        while time.time() < end:
            r, _, _ = select.select([self.master], [], [], 0.05)
            if r:
                try:
                    data = os.read(self.master, 65536)
                except OSError:
                    data = b""
                if not data:
                    return pred(self.scr)
                self.pending += self.dec.decode(data)
                cut = self.pending.rfind("\x1b")
                tail = ""
                if cut >= 0 and not any("\x40" <= ch <= "\x7e" for ch in self.pending[cut + 2:]):
                    self.pending, tail = self.pending[:cut], self.pending[cut:]
                self.scr.feed(self.pending)
                self.pending = tail
                last = time.time()
            elif pred(self.scr) and time.time() - last >= quiet:
                return True
        return pred(self.scr)

    def key(self, k, pred, what):
        os.write(self.master, k.encode())
        assert self.pump(pred), f"atop did not react to {k!r}: {what}\n{self.scr.text()}"

    def resize(self, w, h):
        fcntl.ioctl(self.master, termios.TIOCSWINSZ, struct.pack("HHHH", h, w, 0, 0))
        self.scr.resize(w, h)
        os.kill(self.proc.pid, signal.SIGWINCH)

    def finish(self, timeout=5):
        self.proc.wait(timeout=timeout)
        self.pump(lambda s: True, timeout=0.3, quiet=0.1)
        attrs = termios.tcgetattr(self.master)
        os.close(self.master)
        return attrs


def atop_golden(name, text):
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), name)
    out_dir = os.environ.get("ATOP_GOLDEN_OUT")
    if out_dir:
        with open(os.path.join(out_dir, name), "w") as f:
            f.write(text)
        return
    with open(path) as f:
        want = f.read()
    if want != text:
        import difflib
        diff = "".join(difflib.unified_diff(want.splitlines(True), text.splitlines(True), "golden/" + name, "got"))
        raise AssertionError(f"atop snapshot {name} differs:\n{diff}")


def test_atop_tty(bin_path, tmp_dir):
    atop = os.path.join(os.path.dirname(bin_path), "atop")
    sock = os.path.join(tmp_dir, "atop-fake.sock")
    payload = atop_fake_quota()
    srv, st = start_fake_quota_daemon(sock, payload)
    xdg = os.path.join(tmp_dir, "atop-xdg")
    hist = os.path.join(xdg, "atop", "history")
    atop_seed_history(hist)
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "TERM": "xterm-256color", "TZ": "UTC",
           "XDG_STATE_HOME": xdg, "LANG": "C.UTF-8"}
    args = ["--socket", sock, "--now-ms", str(ATOP_NOW)]
    try:
        piped = run_cmd(atop, args, env=env).stdout
        atop_golden("atop-piped.txt", piped)
        assert "\x1b" not in piped
        with open(hist) as f:
            seeded = f.read()
        assert st["quota"] == 1

        has_data = lambda s: "vercel" in s.text() and "fetching" not in s.text()
        t = AtopPty(atop, args, env, 80, 24)
        assert t.pump(has_data), "atop never drew data at 80x24:\n" + t.scr.text()
        assert t.scr.raw.startswith(ATOP_ALT_ON), repr(t.scr.raw[:40])
        atop_golden("atop-80x24.txt", t.scr.text())
        before = len(t.scr.raw)
        t.pump(lambda s: True, timeout=1.5, quiet=1.2)
        assert len(t.scr.raw) == before, f"idle frame repainted: {t.scr.raw[before:]!r}"
        t.resize(200, 50)
        assert t.pump(has_data), "atop never redrew at 200x50:\n" + t.scr.text()
        atop_golden("atop-200x50.txt", t.scr.text())
        t.key("v", lambda s: "cols" in s.text().splitlines()[0] and "╮╭" in s.text(), "toggle multi-column")
        t.key("v", lambda s: "cols" not in s.text().splitlines()[0] and "╮╭" not in s.text(), "toggle vertical")
        t.key("e", lambda s: "gemini-2.5-pro" in s.text() and "gemini-4-neon +13" not in s.text(), "expand pools")
        t.key("e", lambda s: "gemini-2.5-pro" not in s.text() and "gemini-4-neon +13" in s.text(), "collapse pools")
        t.key("1", lambda s: "gemini-4-neon" not in s.text() and "claude-opus-5-5" in s.text() and "hidden" in s.text(), "hide panel 1")
        t.key("1", lambda s: "gemini-4-neon" in s.text() and "hidden" not in s.text(), "show panel 1")
        t.key("h", lambda s: "refresh interval" in s.text(), "help")
        t.key("h", lambda s: "refresh interval" not in s.text(), "close help")
        t.key("+", lambda s: " 2m " in s.text().splitlines()[0], "slower refresh")
        t.key("r", lambda s: st["quota"] == 3, "refresh now")
        t.key("q", lambda s: True, "quit")
        attrs = t.finish()
        assert t.proc.returncode == 0, t.proc.returncode
        assert t.scr.raw.endswith(ATOP_ALT_OFF), repr(t.scr.raw[-40:])
        assert attrs[3] & termios.ECHO and attrs[3] & termios.ICANON, "terminal modes not restored"
        assert ";38;5;" in t.scr.raw and ";38;2;" not in t.scr.raw
        for ch in ("\u256d", "\u2570", "\u25a0", "\u00b9", "\u2074"):
            assert ch in t.scr.raw, f"missing {ch!r}"
        assert any(0x2801 <= ord(ch) <= 0x28ff for ch in t.scr.raw), "no braille sparkline drawn"

        with open(hist) as f:
            recorded = f.read()
        assert len(recorded) < 16384 and recorded.startswith("atop-history 1\n"), len(recorded)
        rows = {tuple(l.split("\t")[:2]): l.split("\t") for l in recorded.splitlines()[1:]}
        assert rows[("anthropic:personal", "5h")][2] == str(ATOP_NOW - 60000)
        assert rows[("anthropic:personal", "5h")][3].endswith(",16") and rows[("anthropic:personal", "5h")][3].count(",") == 40
        assert rows[("vercel-ai-gateway", "$balance")][3].endswith(",24478")
        assert rows[("anthropic:anthropic", "5h")][3] == "0"
        assert ("anthropic:beta", "5h") not in rows
        assert recorded != seeded

        nc = dict(env, NO_COLOR="1", COLORTERM="truecolor")
        t2 = AtopPty(atop, args, nc, 80, 24)
        assert t2.pump(has_data), t2.scr.text()
        os.kill(t2.proc.pid, signal.SIGTERM)
        attrs = t2.finish()
        assert t2.proc.returncode == -signal.SIGTERM, t2.proc.returncode
        assert t2.scr.raw.endswith(ATOP_ALT_OFF), repr(t2.scr.raw[-40:])
        assert attrs[3] & termios.ECHO, "SIGTERM left the terminal raw"
        assert ";38;" not in t2.scr.raw, "NO_COLOR output carried colour"
        assert "\u25a0\u00b7\u00b7" in t2.scr.snaps[-1] and "\x1b[0;1" in t2.scr.raw and "\x1b[0;2" in t2.scr.raw
        with open(hist) as f:
            assert f.read() == recorded, "re-reading the same daemon reading must not add samples"
        assert st["quota"] == 4, st

        evil = atop_fake_quota()
        evil["accounts"][2]["windows"][1]["label"] = "EVIL\u001b]52;c;aGk=\u0007\u001b[2J\u2705\u064b@@OVERLONG@@\u4e2dX"
        evil["accounts"][2]["name"] = "anthr\u0301opic"
        raw = (json.dumps(evil, ensure_ascii=False) + "\n").encode().replace(b"@@OVERLONG@@", b"\xc1\x9b[2J\xe0\x80\x9b")
        esock = os.path.join(tmp_dir, "atop-evil.sock")
        esrv, _ = start_fake_quota_daemon(esock, raw)
        try:
            t3 = AtopPty(atop, ["--socket", esock, "--now-ms", str(ATOP_NOW)], env, 80, 24)
            assert t3.pump(lambda s: "EVIL" in s.text() and "fetching" not in s.text()), t3.scr.text()
            screen = t3.scr.text()
            os.write(t3.master, b"q")
            t3.finish()
            body = t3.scr.raw.replace("\x1b[0m\x1b[H\x1b[2J", "")
            assert "\x1b]" not in body and "\x07" not in body and "\x1b[2J" not in body, "provider text reached the terminal as escapes"
            row = next(l for l in screen.splitlines() if "EVIL" in l)
            assert "\u2705" not in screen and "\u4e2d" not in screen and "\u0301" not in screen, row
            for l in screen.splitlines():
                assert len(l) <= 80, l
                if l.startswith("\u2502"):
                    assert len(l) == 80 and l[79] == "\u2502", f"box border shifted: {l!r}"
        finally:
            esrv.close()
        print("PASS atop tty: 80x24 + 200x50 snapshots, SIGWINCH, keys, history, NO_COLOR, terminal restore, hostile text")
    finally:
        srv.close()


def main():
    bin_path = sys.argv[1]
    closure_size_file = sys.argv[2] if len(sys.argv) > 2 else None
    store_paths_file = sys.argv[3] if len(sys.argv) > 3 else None
    test_static_binary(bin_path)
    test_sizes(bin_path, closure_size_file, store_paths_file)
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
        test_order_lock_atomic_rmw(bin_path, tmp)
        test_concurrent_direct_oauth_refresh_serialization(bin_path, tmp)
        test_crest_auth_dropin_compat(bin_path, tmp)
        test_forked_tls13_children(bin_path, tmp)
        test_sha1_root_ca_chain(bin_path, tmp)
        test_quota_and_atop(bin_path, tmp)
        test_atop_tty(bin_path, tmp)
    print("ALL E2E PASSED")


if __name__ == "__main__":
    main()
