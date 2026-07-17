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


def echonet_frame_length(data: bytes):
    """Return one Format 1 ECHONET Lite frame's length, if complete.

    The bridge carries UDP datagrams over a TCP stream, so one ``recv`` may
    contain a partial frame or several frames.  Format 1 has enough PDC
    information to determine each frame boundary.
    """
    if len(data) < 2:
        return None
    if data[:2] != b"\x10\x81":
        raise ValueError("invalid ECHONET Lite header")
    if len(data) < 12:
        return None

    # EDATA: SEOJ(3), DEOJ(3), ESV(1), OPC(1), then EPC/PDC/EDT entries.
    offset = 12
    for _ in range(data[11]):
        if len(data) < offset + 2:
            return None
        pdc = data[offset + 1]
        offset += 2
        if len(data) < offset + pdc:
            return None
        offset += pdc
    return offset


def read_echonet_frames(connection):
    """Yield complete ECHONET Lite frames from the TCP byte stream."""
    pending = bytearray()
    while True:
        chunk = connection.recv(1280)
        if not chunk:
            if pending:
                raise RuntimeError(
                    f"the bridge closed with an incomplete frame ({len(pending)} bytes)"
                )
            raise RuntimeError("the bridge closed the connection without a response")
        pending.extend(chunk)

        while pending:
            length = echonet_frame_length(pending)
            if length is None:
                break
            frame = bytes(pending[:length])
            del pending[:length]
            yield frame


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

        # The smart meter may send an unsolicited INF (for example the
        # instance-list notification with TID=0) before the Get_Res.  Keep
        # reading until the response for our transaction arrives.
        for response in read_echonet_frames(connection):
            print(f"received: {response.hex(' ')}")
            response_tid = int.from_bytes(response[2:4], "big")
            if response_tid != tid:
                print(
                    f"skipping unrelated frame (TID={response_tid}, expected {tid})"
                )
                continue
            watts = parse_response(response, tid)
            break
        else:
            raise RuntimeError(
                "the bridge closed the connection without a matching response"
            )

    print(f"OK: smart meter instantaneous power = {watts} W")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, ValueError) as error:
        print(f"FAILED: {error}", file=sys.stderr)
        sys.exit(1)
