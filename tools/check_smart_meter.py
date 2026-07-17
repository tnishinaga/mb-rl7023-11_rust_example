#!/usr/bin/env python3
# Assisted-by: Codex:GPT-5.6 Luna

"""Check an ECHONET Lite smart meter through the TCP/Wi-SUN bridge."""

import argparse
import socket
import sys


def build_request(tid: int) -> bytes:
    return bytes(
        [
            0x10,
            0x81,
            tid >> 8,
            tid & 0xFF,
            0x05,
            0xFF,
            0x01,
            0x02,
            0x88,
            0x01,
            0x62,
            0x01,
            0xE7,
            0x00,
        ]
    )


def parse_response(data: bytes, tid: int) -> int:
    if len(data) < 18:
        raise ValueError(f"response is too short ({len(data)} bytes)")
    if data[:2] != b"\x10\x81":
        raise ValueError("invalid ECHONET Lite header")
    if int.from_bytes(data[2:4], "big") != tid:
        raise ValueError("transaction ID does not match")
    if data[10] != 0x72:
        raise ValueError(f"unexpected ESV 0x{data[10]:02x} (expected Get_Res 0x72)")
    if data[11] < 1 or data[12] != 0xE7:
        raise ValueError("instantaneous-power property (EPC 0xE7) is absent")

    pdc = data[13]
    if pdc == 0 or len(data) < 14 + pdc:
        raise ValueError(f"invalid PDC {pdc}")
    return int.from_bytes(data[14 : 14 + pdc], "big", signed=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="192.168.200.200")
    parser.add_argument("--port", default=3610, type=int)
    parser.add_argument("--timeout", default=30.0, type=float)
    args = parser.parse_args()

    tid = 1
    request = build_request(tid)
    print(f"connecting to {args.host}:{args.port}")
    with socket.create_connection((args.host, args.port), timeout=args.timeout) as connection:
        connection.settimeout(args.timeout)
        connection.sendall(request)
        print(f"sent:     {request.hex(' ')}")
        response = connection.recv(1280)

    if not response:
        raise RuntimeError("the bridge closed the connection without a response")
    print(f"received: {response.hex(' ')}")
    watts = parse_response(response, tid)
    print(f"OK: smart meter instantaneous power = {watts} W")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, ValueError) as error:
        print(f"FAILED: {error}", file=sys.stderr)
        sys.exit(1)
