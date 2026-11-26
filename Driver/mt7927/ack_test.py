#!/usr/bin/env python3
"""Single-device test: does the adapter ACK frames addressed to the monitor MAC?

It injects an Open System Authentication request to the AP, using the monitor
interface's MAC as the source, and captures the AP's Authentication reply
(addressed to that MAC).

  * Hardware ACKs   -> the AP sends each reply once (Retry bit clear).
  * No ACK          -> the AP retransmits the same sequence number several
                       times with the Retry bit set.

Only management frames are injected (one auth request per round).  Run it
against your own AP.

    sudo ./ack_test.py mon0 <AP BSSID> [--rounds 20]

The interface must already be in monitor mode on the AP's channel
(test-active-monitor.sh does this).
"""
import argparse
import os
import select
import socket
import struct
import sys
import time

ETH_P_ALL = 0x0003

# Minimal radiotap header: version 0, pad, len 8, no present fields.
RADIOTAP_TX = b"\x00\x00\x08\x00\x00\x00\x00\x00"

FC_AUTH = 0x00B0            # type mgmt (0), subtype auth (11)
FC_FLAG_RETRY = 0x08


def mac_bytes(mac: str) -> bytes:
    parts = mac.split(":")
    if len(parts) != 6:
        raise ValueError(f"bad MAC: {mac}")
    return bytes(int(p, 16) for p in parts)


def mac_str(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def iface_mac(iface: str) -> bytes:
    with open(f"/sys/class/net/{iface}/address") as f:
        return mac_bytes(f.read().strip())


def build_auth(bssid: bytes, src: bytes, seq: int) -> bytes:
    hdr = struct.pack("<HH", FC_AUTH, 0x013A)          # fc, duration 314us
    hdr += bssid + src + bssid
    hdr += struct.pack("<H", (seq & 0xFFF) << 4)
    body = struct.pack("<HHH", 0, 1, 0)                # open system, seq 1, ok
    return RADIOTAP_TX + hdr + body


def parse(pkt: bytes):
    """Return (fc, flags, addr1, addr2, seq) of an 802.11 frame or None."""
    if len(pkt) < 4:
        return None
    rt_len = struct.unpack_from("<H", pkt, 2)[0]
    frame = pkt[rt_len:]
    if len(frame) < 24:
        return None
    fc_byte0, flags = frame[0], frame[1]
    addr1, addr2 = frame[4:10], frame[10:16]
    seq = struct.unpack_from("<H", frame, 22)[0] >> 4
    return fc_byte0, flags, addr1, addr2, seq


def run(iface: str, bssid: bytes, rounds: int, wait: float, src: bytes):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                         socket.htons(ETH_P_ALL))
    sock.bind((iface, 0))
    sock.setblocking(False)

    replies = {}            # AP seq -> list of retry flags
    for i in range(rounds):
        sock.send(build_auth(bssid, src, 0x100 + i))
        deadline = time.monotonic() + wait
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                break
            r, _, _ = select.select([sock], [], [], left)
            if not r:
                break
            try:
                pkt = sock.recv(4096)
            except BlockingIOError:
                continue
            p = parse(pkt)
            if not p:
                continue
            fc0, flags, a1, a2, seq = p
            if fc0 == FC_AUTH and a1 == src and a2 == bssid:
                replies.setdefault(seq, []).append(bool(flags & FC_FLAG_RETRY))
        sys.stdout.write(".")
        sys.stdout.flush()
    print()
    return replies


def report(replies, rounds):
    if not replies:
        print("RESULT: no auth replies seen from the AP.")
        print("  Check channel/BSSID, that RX works (test-active-monitor.sh rx),")
        print("  and that injection works on this interface.")
        return 2

    copies = [len(v) for v in replies.values()]
    retried = sum(1 for v in replies.values() if any(v))
    avg = sum(copies) / len(copies)
    print(f"auth replies: {len(replies)} distinct of {rounds} requests")
    print(f"copies per reply: avg {avg:.2f}, max {max(copies)}")
    print(f"replies with Retry bit: {retried}/{len(replies)}")
    if retried == 0 and avg <= 1.2:
        print("RESULT: ACKED - the adapter ACKs frames to the monitor MAC")
        return 0
    if retried >= len(replies) * 0.8:
        print("RESULT: NOT ACKED - the AP keeps retransmitting")
        return 1
    print("RESULT: MIXED - some replies retried; check RF conditions and rerun")
    return 3


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("iface")
    ap.add_argument("bssid")
    ap.add_argument("--rounds", type=int, default=20)
    ap.add_argument("--wait", type=float, default=0.5,
                    help="seconds to collect replies after each request")
    ap.add_argument("--src", help="source MAC (default: interface MAC)")
    args = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("run as root")
    src = mac_bytes(args.src) if args.src else iface_mac(args.iface)
    bssid = mac_bytes(args.bssid)
    print(f"iface {args.iface}  src {mac_str(src)}  AP {mac_str(bssid)}")
    replies = run(args.iface, bssid, args.rounds, args.wait, src)
    sys.exit(report(replies, args.rounds))


if __name__ == "__main__":
    main()
