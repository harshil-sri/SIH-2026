#!/usr/bin/env python3
"""SIH26145 — Diode emulation, TRANSPORT LAYER.

Software analogue of a hardware data diode: the sender process contains only a
sendto() code path, the receiver process only a recvfrom() code path. There is
no return channel anywhere in this program — unidirectionality holds even if
iptables rules were removed.

Two roles (run under their respective netns):

  send:  ip netns exec ns-source python relay.py send --in-port 10500
         Binds 127.0.0.1:<in-port> INSIDE ns-source. Traffic generators
         (benign or attack) push datagrams here; each is forwarded verbatim
         as a UDP packet to the monitor address. Send-only.

  recv:  ip netns exec ns-monitor python relay.py recv --out data/diode/received.bin
         Binds 0.0.0.0:9999 inside ns-monitor. Receives and writes frames to
         <out> ('-' = stdout, so the unprivileged parent shell owns the file).
         Stats to stderr every second. Receive-only.

Well-formed streams use this relay; raw/malformed crafted packets are injected
by attacks/*.py via scapy send() (also forward-only by construction).
"""
import argparse
import socket
import sys
import time

MONITOR_IP = "10.200.0.2"
MONITOR_PORT = 9999


def role_send(in_port: int, chunk_delay: float) -> None:
    """Listen locally, forward every datagram toward the monitor. Send-only."""
    fwd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    local = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    local.bind(("127.0.0.1", in_port))
    print(f"[relay-send] listening on 127.0.0.1:{in_port} -> "
          f"{MONITOR_IP}:{MONITOR_PORT} (sendto only)", flush=True)
    n = 0
    while True:
        payload, _ = local.recvfrom(65535)
        fwd.sendto(payload, (MONITOR_IP, MONITOR_PORT))
        n += 1
        if n % 100 == 0:
            print(f"[relay-send] forwarded {n}", flush=True)
        if chunk_delay:
            time.sleep(chunk_delay)


def role_recv(out_path: str | None, max_seconds: float, max_pkts: int) -> None:
    """Receive forward traffic, append raw frames to out_path (or stdout if
    out_path == '-'; lets an unprivileged parent shell own the file). Recv-only.
    Exits after max_seconds (>0) or max_pkts (>0), whichever comes first."""
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 << 20)
    rx.bind(("0.0.0.0", MONITOR_PORT))
    dest = "stdout" if out_path in (None, "-") else out_path
    print(f"[relay-recv] bound 0.0.0.0:{MONITOR_PORT}, writing to {dest}", flush=True)
    fh = sys.stdout.buffer if dest == "stdout" else open(out_path, "ab")  # noqa: SIM115
    n = b = 0
    t0 = time.time()
    while True:
        if max_seconds > 0 and time.time() - t0 >= max_seconds:
            break
        if max_pkts > 0 and n >= max_pkts:
            break
        rx.settimeout(max(0.05, max_seconds - (time.time() - t0)) if max_seconds > 0 else 5.0)
        try:
            data, addr = rx.recvfrom(65535)
        except socket.timeout:
            continue
        fh.write(data)
        fh.flush()
        n += 1
        b += len(data)
        if time.time() - t0 >= 1.0:
            print(f"[relay-recv] {n} pkts ({b} bytes) last={addr[0]}", flush=True)
            n_total, b_total = n, b  # noqa: F841
            t0 = time.time()
    print(f"[relay-recv] done: {n} pkts ({b} bytes) this window", flush=True)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="role", required=True)
    s = sub.add_parser("send")
    s.add_argument("--in-port", type=int, default=10500)
    s.add_argument("--chunk-delay", type=float, default=0.0)
    r = sub.add_parser("recv")
    r.add_argument("--out", default="-")
    r.add_argument("--max-seconds", type=float, default=0.0, help="exit after N seconds (0=never)")
    r.add_argument("--max-pkts", type=int, default=0, help="exit after N packets (0=never)")
    args = p.parse_args()

    if args.role == "send":
        role_send(args.in_port, args.chunk_delay)
    else:
        role_recv(args.out, args.max_seconds, args.max_pkts)
    return 0


if __name__ == "__main__":
    sys.exit(main())
