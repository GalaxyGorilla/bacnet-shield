#!/usr/bin/env python3
"""Interop client for the bacnet-shield suite.

Drives one operation through the proxy against the fake device and exits 0
only when the observed behavior matches what the policy promises. Operations
and target come from the environment so SimpleArgumentParser's own arguments
stay reserved for the local bind address:

    BACNET_TARGET   proxy address, e.g. 127.0.0.1:47811
    BACNET_OP       read | write | write-denied | whois | cov
    BACNET_OID      object identifier, default analog-value,1
    BACNET_PROP     property identifier, default present-value
    BACNET_VALUE    value for write/cov, default 2.5
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
from bacpypes3.primitivedata import ObjectIdentifier, Real, TagList

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

    if op == "whois":
        i_ams = await app.who_is(address=target, timeout=3)
        if not i_ams:
            return _fail("Who-Is through the proxy got no I-Am")
        for i_am in i_ams:
            print(f"i-am {i_am.iAmDeviceIdentifier} from {i_am.pduSource}")
        return 0

    if op == "cov":
        # Subscribe to the monitored object, change it, and wait for the
        # notification to come back through the proxy. Unconfirmed
        # notifications keep the exchange one-way past the device, which is
        # what a real COV consumer uses.
        value = float(os.environ.get("BACNET_VALUE", "2.5"))
        async with app.change_of_value(
            target,
            oid,
            subscriber_process_identifier=1,
            issue_confirmed_notifications=False,
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
            while True:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    break
                try:
                    pv = await asyncio.wait_for(scm.get(), timeout=remaining)
                except asyncio.TimeoutError:
                    break
                if pv.propertyIdentifier != prop:
                    # A notification for an analog value may carry more than
                    # one property (status-flags alongside present-value);
                    # only the monitored property is the one under test.
                    continue
                got = _real(pv.value)
                if got == value:
                    print(f"cov {oid} {prop} = {got}")
                    return 0
        return _fail(f"no COV notification with the changed value {value}")

    return _fail(f"unknown BACNET_OP {op!r}")


async def main() -> int:
    parser = SimpleArgumentParser(description="bacnet-shield interop client")
    args = parser.parse_args()
    app = Application.from_args(args)
    target = Address(os.environ["BACNET_TARGET"])
    return await run(app, target)


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))