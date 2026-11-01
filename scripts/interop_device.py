#!/usr/bin/env python3
"""Fake BACnet/IP device for the bacnet-shield interop suite.

It is a real bacpypes3 application: a device object plus two analog-value
objects. It answers Who-Is with I-Am, ReadProperty with the stored value, and
WriteProperty by storing the new value. The gateway under test sits between
this device and the interop client, so nothing here knows about the proxy.

Usage:
    interop_device.py --address 127.0.0.1:47810 --instance 1001 --name Interop
"""

import asyncio
import sys

from bacpypes3.argparse import SimpleArgumentParser
from bacpypes3.app import Application
from bacpypes3.local.analog import AnalogValueObject

# Longer than one 50-byte APDU, so a client that advertises a small
# max-apdu-length forces the device to send a segmented ComplexACK. The proxy
# must relay every segment and carry the client's SegmentACKs back.
DESCRIPTION = "segmented " * 12


class CovAnalogValueObject(AnalogValueObject):
    """An analog value that reports COV on a write, like a real device.

    bacpypes3's local ``Object.write_property`` writes through
    ``super().__setattr__`` and so skips the property monitors that drive
    COV detection: a WriteProperty changes the value but never produces a
    notification. A real device notifies on a change, and the proxy's
    subscriber routing is exactly what the interop is meant to exercise, so
    route the ordinary (non-array, non-priority) write through ``__setattr__``
    where the monitors run. This is a fixture adjustment, not a proxy
    adaptation; the wire on both sides stays standard.
    """

    async def write_property(self, attr, value, index=None, priority=None):
        if isinstance(attr, int):
            attr = self._property_identifier_class(attr).attr
        if index is None and priority is None:
            setattr(self, attr, value)
            return
        await super().write_property(attr, value, index, priority)


async def main() -> int:
    parser = SimpleArgumentParser(description="bacnet-shield interop device")
    args = parser.parse_args()
    app = Application.from_args(args)

    app.add_object(
        CovAnalogValueObject(
            objectIdentifier=("analog-value", 1),
            objectName="AV-1",
            presentValue=1.0,
            covIncrement=0.0,
            description=DESCRIPTION,
        )
    )
    app.add_object(
        CovAnalogValueObject(
            objectIdentifier=("analog-value", 2),
            objectName="AV-2",
            presentValue=2.0,
            covIncrement=0.0,
        )
    )

    # The harness waits for this line before it starts the gateway, so the
    # device socket is bound before any request can arrive.
    print("READY", flush=True)

    try:
        await asyncio.Future()
    except asyncio.CancelledError:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
