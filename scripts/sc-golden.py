#!/usr/bin/env python3
"""sc-golden.py — emit the BVLC-SC golden vectors that pin internal/bacnet/sc.

The bytes are produced by bacpypes3 (the independent oracle) and are
cross-checked field-by-field against bacnet-stack's
src/bacnet/datalink/bsc/bvlc-sc.c (the live SC peer). Compare the output with
the tables in internal/bacnet/sc/sc_test.go (TestHeaderGolden).

    .venv/bin/python scripts/sc-golden.py

bacpypes3's sc package imports ``websockets`` even for the pure codec, so the
oracle needs it installed alongside the pinned peer. Exit 77 when the oracle is
not provisioned, matching the rest of the suite.
"""
import sys
from uuid import UUID

try:
    from bacpypes3.pdu import VirtualAddress
    from bacpypes3.sc.bvll import (
        Result,
        EncapsulatedNPDU,
        AddressResolution,
        AddressResolutionACK,
        Advertisement,
        AdvertisementSolicitation,
        ConnectRequest,
        ConnectAccept,
        DisconnectRequest,
        DisconnectACK,
        HeartbeatRequest,
        HeartbeatACK,
        ProprietaryMessage,
        HeaderOption,
        ProprietaryHeaderOption,
    )
except ModuleNotFoundError as exc:
    print(
        f"oracle unavailable ({exc}); run: make peers && .venv/bin/pip install websockets",
        file=sys.stderr,
    )
    sys.exit(77)


def vmac(h):
    return VirtualAddress(bytes.fromhex(h))


def emit(name, pdu):
    print(f"{name:26} {pdu.encode().pduData.hex()}")


def main():
    o = vmac("010203040506")
    d = vmac("0a0b0c0d0e0f")
    u = UUID("00112233-4455-6677-8899-aabbccddeeff")
    npdu = bytes.fromhex("0104000501")

    def with_addrs(pdu, mid):
        pdu.bvlcMessageID = mid
        pdu.bvlcOriginatingVirtualAddress = o
        pdu.bvlcDestinationVirtualAddress = d
        return pdu

    emit("result-ack", with_addrs(Result(result_function=0x06, result_code=0), 0x1234))
    emit(
        "result-nak",
        with_addrs(
            Result(
                result_function=0x06,
                result_code=1,
                error_header_marker=0,
                error_class=5,
                error_code=29,
                error_details="bad",
            ),
            0x1234,
        ),
    )
    emit("encapsulated-npdu", with_addrs(EncapsulatedNPDU(npdu), 1))
    emit("address-resolution", with_addrs(AddressResolution(), 2))
    emit("address-resolution-ack", with_addrs(AddressResolutionACK("wss://hub:47808/x"), 3))
    emit("advertisement", with_addrs(Advertisement(1, 0, 1497, 1440), 4))
    emit("advertisement-solicitation", with_addrs(AdvertisementSolicitation(), 5))
    emit("connect-request", with_addrs(ConnectRequest(o, u, 1497, 1440), 6))
    emit("connect-accept", with_addrs(ConnectAccept(d, u, 1497, 1440), 7))
    emit("disconnect-request", with_addrs(DisconnectRequest(), 8))

    ack = DisconnectACK()
    ack.bvlcMessageID = 9
    emit("disconnect-ack", ack)
    hb = HeartbeatRequest()
    hb.bvlcMessageID = 10
    emit("heartbeat-request", hb)
    hb = HeartbeatACK()
    hb.bvlcMessageID = 11
    emit("heartbeat-ack", hb)
    emit("proprietary", with_addrs(ProprietaryMessage(999, 7, bytes.fromhex("aabb")), 12))

    enc = with_addrs(EncapsulatedNPDU(npdu), 13)
    enc.bvlcDataOptions = [HeaderOption(option_type=1, must_understand=True)]
    emit("encapsulated-secure-path", enc)

    enc = with_addrs(EncapsulatedNPDU(npdu), 14)
    enc.bvlcDestinationOptions = [
        ProprietaryHeaderOption(
            bytes.fromhex("dead"),
            vendor_identifier=999,
            proprietary_option_type=2,
            must_understand=True,
        )
    ]
    emit("encapsulated-proprietary-option", enc)

    enc = EncapsulatedNPDU(npdu)
    enc.bvlcMessageID = 15
    emit("encapsulated-no-addresses", enc)


if __name__ == "__main__":
    main()
