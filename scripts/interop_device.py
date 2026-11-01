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


async def main() -> int:
    parser = SimpleArgumentParser(description="bacnet-shield interop device")
    args = parser.parse_args()
    app = Application.from_args(args)

    app.add_object(
        AnalogValueObject(
            objectIdentifier=("analog-value", 1),
            objectName="AV-1",
            presentValue=1.0,
        )
    )
    app.add_object(
        AnalogValueObject(
            objectIdentifier=("analog-value", 2),
            objectName="AV-2",
            presentValue=2.0,
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
