# examples/

Copy-paste deployment walkthroughs for every bacnet-shield shape.

**New here?** Start with [gateway.md](gateway.md) — the primary retrofit
deployment (one box in front of one legacy device). It includes a two-minute
BACnet background section, so no prior BACnet knowledge is needed.

| Walkthrough | Use this when |
|---|---|
| [gateway.md](gateway.md) | You have one legacy BACnet/IP device and want it protected — the standard retrofit deployment |
| [access-control.md](access-control.md) | You need to decide who may connect, how hard they may poll, and which writes may pass |
| [sc.md](sc.md) | Your clients speak BACnet/SC, or a site hub already exists, and you want the secure leg in front of the same device |
| [operations.md](operations.md) | The box is deployed — day-2: install as a service, commission, monitor, reload the policy in place, troubleshoot |

The reference documents live next to the source:
[README](../README.md) for the full surface, [SECURITY.md](../SECURITY.md) for
the threat model and trust boundaries, [TESTING.md](../TESTING.md) for the test
layers and release gates, [CONFORMANCE.md](../CONFORMANCE.md) for what the
independent BACnet stacks found, and [AGENTS.md](../AGENTS.md) for the
architecture and wire-level invariants.
