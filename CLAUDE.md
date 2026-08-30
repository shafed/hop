# hop

VPN utility over Xray-core: TUN device, node set, automatic switching on liveness.

## refs/ — read, never copy

Copying from the GPL-3.0 sources relicenses the whole product.

- **Never copy:** sing-box, sing-tun, nekoray, hiddify-app, hiddify-core.
- **May copy:** wireguard-go (MIT), Xray-core (MPL-2.0), gvisor.dev/gvisor (Apache-2.0).

Take netstack from `gvisor.dev/gvisor`, not `sing-tun/gtcpip` — that is a GPL-3.0
fork. Do not edit or build `refs/`; it lives outside git.

## SPEC.md is not the source of truth

Measure before deriving anything from a claim about how a mechanism or syscall
behaves. Where measurement and spec disagree, measurement wins: correct the spec,
record the measurement in `implementation-notes.md`. §6.8 once asserted that
`SO_BINDTODEVICE` requires `CAP_NET_RAW`, and an architecture choice rested on
that false fact.

If the implementation must still deviate: take the conservative option, record it
under "Deviations" in `implementation-notes.md`, continue.

## Every "the mechanism exists" test ships with a negative control

Break the mechanism on purpose and require red. A green test is indistinguishable
from a vacuous one, and no gate command can tell them apart.

A green control is not proof the test is vacuous — it may mean the wrong mechanism
was disabled. The §6.8 outbound binding, for one, has two switchable sites:
`outbound.Selector.Control` for the agent's own sockets, and `sockopt.Interface`
in `internal/engine/dialer.go` for Xray's dial to the node. Look for the second
site before concluding either way.

## Gate

Commands and the known, deliberately-unfixed noise: `HANDOFF.json` → `gate`. One
source only; a copy here would drift from what passes actually run.

## Subagents

Running passes as subagents in separate worktrees is expected, and choosing the
model per task is expected with it — a heavier model where the pass has to make an
architectural decision, a lighter one for local mechanical work. Divide zones
per-file and hand out registry numbers before the passes start:
`HANDOFF.json` → `parallel_passes_trap`.
