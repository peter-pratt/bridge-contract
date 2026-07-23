# wBDX contract (Phase H)

The EVM side of the Beldex Sovereign Bridge: a signer-gated, domain-separated,
replay-guarded, fixed-window-capped upgradeable ERC-20 whose **mint authority is the
`Pevm` masternode-committee key** (secp256k1 / CGGMP21), verified by `ecrecover`.

This is a **standalone Foundry project** (moved out of the Beldex monorepo). The design
lives in the Beldex repo at `bridge/docs/IMPLEMENTATION.md` §12 (Phase H); the off-chain
signer it must agree with byte-for-byte is `bridge/signer/src/watch.rs` in that same repo.
This README is the build/test entry point.

## Layout

```
src/WrappedBDX.sol        the contract (H.1–H.6)
test/WrappedBDX.t.sol     full Foundry suite (the Phase H definition-of-done)
script/Deploy.s.sol       UUPS proxy deploy (per-chain params via env / E.3 registry)
```

## Setup

Run from this project root. Foundry + OpenZeppelin are not vendored — they install into
`lib/` (`forge-std` is already present). From the project directory:

```bash
forge install OpenZeppelin/openzeppelin-contracts-upgradeable --no-commit
forge install OpenZeppelin/openzeppelin-contracts --no-commit   # non-upgradeable utils (ECDSA, ERC1967Proxy)
forge build
forge test -vvv
```

Pinned to **OpenZeppelin v5** and **solc 0.8.24** (`foundry.toml`).

## The one byte-level invariant that matters

The mint digest is
`keccak256(abi.encode(MINT_TAG, block.chainid, address(this), to, amount, beldexTxid))`
and must match the Rust signer's `watch.rs::MintEvent::mint_preimage` **exactly**.

`MINT_TAG = keccak256("BELDEX_BRIDGE_MINT_V1")`. The Rust signer hardcodes the same
precomputed 32 bytes (`watch.rs::MINT_TAG`) and guards them with a keccak drift test;
the contract computes `keccak256(...)` directly. `test_MintTag_isKeccakOfDomainString`
pins the value (and cross-checks the signer's exact bytes), and every mint test signs the
digest exactly as the signer would, so a drift in field order, chain-id binding, or tag
value fails the suite.

Likewise `redeemToNative` emits `RedeemToNative(address indexed from, uint256 amount,
bytes beldexAddress)` — the exact event `evm_watcher.rs` decodes (`from` indexed;
`abi.encode(amount, beldexAddress)` in the data).

## Operational notes

- **`admin` must be a `TimelockController` + multisig**, never an EOA, never a committee
  signer. It manages the signer set, pause, caps, and upgrades — it can stop the bleeding
  and rotate signers, but it can never mint. `script/DeployWithTimelock.s.sol` wires this
  production shape (governance multisig = timelock proposer, open executor, min delay), and
  `test/WrappedBDXTimelock.t.sol` (Phase G.2) proves the flow: direct admin calls revert,
  every admin action must be scheduled and wait out the delay, and the bond-before-caps
  guard + UUPS upgrade both flow through the timelock.
- **Rotation is self-authorizing** (H.6): the outgoing committee signs in the incoming
  one (`rotateSigner`), a challenge window elapses, then anyone `activateRotation`s.
  `vetoRotation` (a freeze trigger) blocks activation on a watcher-detected mismatch.
  `breakGlassSetSigner` is the admin fallback only when no valid hand-off lands.
- **Caps are per fixed calendar window** (`β=1`) and cannot be raised above
  `bondBackingCapLimit` — encoding "raise the bond before the caps" on-chain.
- **9 decimals** so 1 wBDX unit == 1 atomic BDX.

External audit required before mainnet (S13).
