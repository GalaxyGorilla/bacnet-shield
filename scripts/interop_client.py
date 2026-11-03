#!/usr/bin/env python3
"""Interop client for the bacnet-shield suite.

Drives one operation through the proxy against the fake device and exits 0
only when the observed behavior matches what the policy promises. Operations
and target come from the environment so SimpleArgumentParser's own arguments
stay reserved for the local bind address:

    BACNET_TARGET   proxy address, e.g. 127.0.0.1:47811
    BACNET_OP       read | write | write-denied | whois | cov | read-long
    BACNET_OID      object identifier, default analog-value,1
    BACNET_PROP     property identifier, default present-value
    BACNET_VALUE    value for write/cov, default 2.5
    BACNET_EXPECT   expected value for read, or length for read-long
"""

import asyncio
import os
import sys

from bacpypes3.argparse import SimpleArgumentParser
from bacpypes3.apdu import (
    ErrorPDU,
    ErrorRejectAbortNack,
    ReadPropertyRequest,
    WritePropertyRequest,
)
from bacpypes3.app import Application
from bacpypes3.basetypes import ErrorClass, ErrorCode, PropertyIdentifier
from bacpypes3.pdu import Address
from bacpypes3.primitivedata import CharacterString, ObjectIdentifier, Real, TagList

FAIL = 1


def _fail(msg: str) -> int:
    print(f"FAIL: {msg}", file=sys.stderr)
    return FAIL


def _real(value) -> float:
    """Unwrap a ReadProperty value into a float.

    bacpypes3 hands back an Any whose tag list may include the context-3
    opening/closing tags around the actual application REAL. Keep only the
    application tags before decoding; the interop objects are analog values,
    so REAL is the expected datatype.
    """
    inner = [t for t in value.tagList if t.tag_class == 0]
    return float(Real.decode(TagList(inner)))


def _string(value) -> str:
    """Unwrap a ReadProperty value into its character-string text."""
    inner = [t for t in value.tagList if t.tag_class == 0]
    return str(CharacterString.decode(TagList(inner)))


async def _request(app: Application, req):
    """Return the ACK, or the Error/Reject/Abort the proxy answered with.

    bacpypes3 raises these as exceptions rather than returning them, so the
    harness normalizes both paths and the checks below stay explicit.
    """
    try:
        return await app.request(req)
    except ErrorRejectAbortNack as exc:
        return exc


async def run(app: Application, target: Address) -> int:
    op = os.environ.get("BACNET_OP", "read")
    oid = ObjectIdentifier(os.environ.get("BACNET_OID", "analog-value,1"))
    prop = PropertyIdentifier(os.environ.get("BACNET_PROP", "present-value"))

    if op == "read":
        req = ReadPropertyRequest(
            objectIdentifier=oid,
            propertyIdentifier=prop,
            destination=target,
        )
        resp = await _request(app, req)
        if isinstance(resp, ErrorRejectAbortNack):
            return _fail(f"read returned {resp!r}")
        value = _real(resp.propertyValue)
        print(f"read {oid} {prop} = {value}")
        expect = os.environ.get("BACNET_EXPECT") or None
        if expect is not None and value != float(expect):
            return _fail(f"read back {value}, want {expect}")
        return 0

    if op in ("write", "write-denied"):
        value = Real(float(os.environ.get("BACNET_VALUE", "2.5")))
        req = WritePropertyRequest(
            objectIdentifier=oid,
            propertyIdentifier=prop,
            propertyValue=value,
            destination=target,
        )
        resp = await _request(app, req)
        if op == "write":
            if isinstance(resp, ErrorRejectAbortNack):
                return _fail(f"write returned {resp!r}")
            print(f"write {oid} {prop} = {value} acknowledged")
            return 0
        # write-denied: the proxy must answer with class security (4) and
        # code write-access-denied (40) itself.
        if not isinstance(resp, ErrorPDU):
            return _fail(f"denied write returned {resp!r}, want an Error PDU")
        if resp.errorClass != ErrorClass.security or resp.errorCode != ErrorCode.writeAccessDenied:
            return _fail(
                f"denied write error class={resp.errorClass} code={resp.errorCode}, "
                "want class security (4) code writeAccessDenied (40)"
            )
        print(f"write denied: class={resp.errorClass} code={resp.errorCode}")
        return 0

    if op == "read-long":
        # Advertise a small receive size so the device must segment its answer,
        # then read a property larger than one APDU. The proxy has to relay
        # every segment and carry the client's SegmentACKs back to the device;
        # a proxy that only forwarded the first segment would never complete.
        app.device_object.maxApduLengthAccepted = 50
        req = ReadPropertyRequest(
            objectIdentifier=oid,
            propertyIdentifier=prop,
            destination=target,
        )
        resp = await _request(app, req)
        if isinstance(resp, ErrorRejectAbortNack):
            return _fail(f"long read returned {resp!r}")
        text = _string(resp.propertyValue)
        want = int(os.environ.get("BACNET_EXPECT", "120"))
        if len(text) != want:
            return _fail(f"long read length {len(text)}, want {want}")
        print(f"long read {oid} {prop} = {len(text)} chars across segments")
        return 0

    if op == "write-long":
        # Advertise a small receive size so a large value must be sent as a
        # segmented confirmed request. The proxy is the server for the
        # segment transfer: it ACKs each segment, reassembles the APDU,
        # authorizes the whole write, and forwards it to the device. A proxy
        # that only inspected the first segment would miss a target hidden
        # in a later one.
        app.device_object.maxApduLengthAccepted = 50
        text = os.environ.get("BACNET_TEXT") or ("segmented-write-" * 16)
        req = WritePropertyRequest(
            objectIdentifier=oid,
            propertyIdentifier=prop,
            propertyValue=CharacterString(text),
            destination=target,
        )
        resp = await _request(app, req)
        if isinstance(resp, ErrorRejectAbortNack):
            return _fail(f"long write returned {resp!r}")
        print(f"long write {oid} {prop} = {len(text)} chars across segments")
        return 0

    if op == "whois":
        i_ams = await app.who_is(address=target, timeout=3)
        if not i_ams:
            return _fail("Who-Is through the proxy got no I-Am")
        for i_am in i_ams:
            print(f"i-am {i_am.iAmDeviceIdentifier} from {i_am.pduSource}")
        return 0

    if op in ("cov", "cov-confirmed"):
        # Subscribe to the monitored object, change it, and wait for the
        # notification to come back through the proxy. Unconfirmed
        # notifications keep the exchange one-way past the device; the
        # confirmed variant makes the device initiate a confirmed request
        # (and, with the fixture's long description, a segmented one) that
        # the proxy must relay and answer with the client's ACK.
        value = float(os.environ.get("BACNET_VALUE", "2.5"))
        confirmed = op == "cov-confirmed"
        if confirmed:
            app.device_object.maxApduLengthAccepted = 50
        async with app.change_of_value(
            target,
            oid,
            subscriber_process_identifier=1,
            issue_confirmed_notifications=confirmed,
            lifetime=60,
        ) as scm:
            req = WritePropertyRequest(
                objectIdentifier=oid,
                propertyIdentifier=prop,
                propertyValue=Real(value),
                destination=target,
            )
            resp = await _request(app, req)
            if isinstance(resp, ErrorRejectAbortNack):
                return _fail(f"cov trigger write returned {resp!r}")
            # A subscription delivers an initial notification carrying the
            # value from before the write, so drain until the changed value
            # arrives (or the deadline passes).
            loop = asyncio.get_event_loop()
            deadline = loop.time() + 8.0
            got_value = None
            desc_len = 0
            desc_prop = PropertyIdentifier("description")
            while True:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    break
                try:
                    pv = await asyncio.wait_for(scm.get(), timeout=remaining)
                except asyncio.TimeoutError:
                    break
                if pv.propertyIdentifier == desc_prop:
                    desc_len = len(_string(pv.value))
                    continue
                if pv.propertyIdentifier != prop:
                    # A notification for an analog value may carry more than
                    # one property (status-flags alongside present-value);
                    # only the monitored property is the one under test.
                    continue
                got_value = _real(pv.value)
                # The confirmed variant deliberately reports the 120-char
                # description; with a 50-byte client APDU the device cannot
                # fit that in one APDU, so receiving it proves the proxy
                # relayed a segmented device-initiated request.
                if got_value == value and (not confirmed or desc_len >= 120):
                    print(f"{op} {oid} {prop} = {got_value} (description {desc_len} chars)")
                    return 0
        return _fail(f"no {op} notification with the changed value {value}")

    return _fail(f"unknown BACNET_OP {op!r}")


async def main() -> int:
    parser = SimpleArgumentParser(description="bacnet-shield interop client")
    args = parser.parse_args()
    app = Application.from_args(args)
    target = Address(os.environ["BACNET_TARGET"])
    return await run(app, target)


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))