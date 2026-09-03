#!/usr/bin/env bash
# 01-deploy.sh — stand up a local anvil, deploy WrappedBDX behind its ERC1967
# proxy with the devnet committee's Pevm address as initialSigner, and emit the
# REAL ABI-encoded mint preimage for the committee to threshold-sign.
#
# Run from the bridge-contract repo root:
#     runlog ./devnet/01-deploy.sh
#
# Output: devnet/mint.env  (sourced by 02-mint.sh)

set -euo pipefail
export PATH="$HOME/.foundry/bin:$PATH"
cd "$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p devnet

# ── inputs ───────────────────────────────────────────────────────────────────
# The wBDX signer address = the CURRENT committee's Pevm group address (derive it from
# the live shares with sign-pevm.sh, or read the `wBDX signer :` line of any Pevm run).
# Accepted as SIGNER_ADDR or INITIAL_SIGNER (the docs use both). There is deliberately
# NO default: a silently-stale baked-in address deploys a contract the committee cannot
# sign for, and the deploy's own sanity check then "passes" against the wrong value.
SIGNER_ADDR="${SIGNER_ADDR:-${INITIAL_SIGNER:-}}"
if [ -z "$SIGNER_ADDR" ]; then
  echo "!! set SIGNER_ADDR (or INITIAL_SIGNER) to the committee's Pevm address, e.g.:" >&2
  echo "     SIGNER_ADDR=0x<pevm addr> ./devnet/01-deploy.sh" >&2
  echo "   Get it from the current shares:" >&2
  echo "     cd ~/Desktop/beldex/beldex/dkg-tss/beldex/utils/local-devnet" >&2
  echo "     runlog ./sign-pevm.sh raw 0x\$(printf 'ab%.0s' {1..32})   # read 'wBDX signer : 0x…'" >&2
  exit 1
fi

# anvil dev account #0 — deployer + admin + mint recipient.
DEPLOYER_KEY="${DEPLOYER_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"
DEPLOYER="${DEPLOYER:-0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266}"
RPC="${RPC:-http://127.0.0.1:8545}"

# wBDX has 9 decimals (matches BDX atomic units).
AMOUNT="${AMOUNT:-12345000000}"                    # 12.345 BDX
PER_TX_MAX="${PER_TX_MAX:-1000000000000}"          # 1,000 BDX
WINDOW_MINT_CAP="${WINDOW_MINT_CAP:-10000000000000}"       # 10,000 BDX / window
BOND_BACKING_CAP_LIMIT="${BOND_BACKING_CAP_LIMIT:-100000000000000}"  # 100,000 BDX
EPOCH_SECONDS="${EPOCH_SECONDS:-86400}"
ROTATE_TIMELOCK="${ROTATE_TIMELOCK:-3600}"
TO="${TO:-$DEPLOYER}"
# Stand-in for the Beldex deposit txid that backs this mint (the replay key).
BELDEX_TXID="${BELDEX_TXID:-0x00000000000000000000000000000000000000000000000000000000decafbad}"

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

for b in anvil cast forge; do
  command -v "$b" >/dev/null || { echo "missing $b — is foundry on PATH? (~/.foundry/bin)"; exit 1; }
done

# ── 1. anvil ─────────────────────────────────────────────────────────────────
say "anvil"
if cast chain-id --rpc-url "$RPC" >/dev/null 2>&1; then
  echo "already up at $RPC"
else
  nohup anvil --host 127.0.0.1 --port 8545 --chain-id 31337 \
    > devnet/anvil.log 2>&1 &
  echo $! > devnet/anvil.pid
  for _ in $(seq 1 40); do
    cast chain-id --rpc-url "$RPC" >/dev/null 2>&1 && break
    sleep 0.25
  done
  cast chain-id --rpc-url "$RPC" >/dev/null 2>&1 || { echo "anvil did not come up; see devnet/anvil.log"; exit 1; }
  echo "started (pid $(cat devnet/anvil.pid)), log devnet/anvil.log"
fi
CHAIN_ID="$(cast chain-id --rpc-url "$RPC")"
echo "chain id: $CHAIN_ID"

# `forge create` requires --broadcast on newer foundry and rejects it on older.
BC=""
forge create --help 2>&1 | grep -q -- '--broadcast' && BC="--broadcast"

# `forge create --json` pretty-prints, so flatten before matching.
deployed() {
  printf '%s' "$1" | tr -d ' \t\n' | sed -n 's/.*"deployedTo":"\([^"]*\)".*/\1/p'
}

# ── 2. implementation ────────────────────────────────────────────────────────
say "deploy WrappedBDX implementation"
IMPL_JSON="$(forge create src/WrappedBDX.sol:WrappedBDX \
  --rpc-url "$RPC" --private-key "$DEPLOYER_KEY" $BC --json)"
IMPL="$(deployed "$IMPL_JSON")"
[ -n "$IMPL" ] || { echo "could not parse impl address from: $IMPL_JSON"; exit 1; }
echo "impl:  $IMPL"

# ── 3. proxy (initialize in the same tx) ─────────────────────────────────────
say "deploy ERC1967Proxy + initialize"
INIT="$(cast calldata \
  'initialize(address,address,uint256,uint256,uint256,uint256,uint256)' \
  "$DEPLOYER" "$SIGNER_ADDR" "$WINDOW_MINT_CAP" "$PER_TX_MAX" \
  "$BOND_BACKING_CAP_LIMIT" "$EPOCH_SECONDS" "$ROTATE_TIMELOCK")"
PROXY_JSON="$(forge create \
  lib/openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol:ERC1967Proxy \
  --rpc-url "$RPC" --private-key "$DEPLOYER_KEY" $BC --json \
  --constructor-args "$IMPL" "$INIT")"
PROXY="$(deployed "$PROXY_JSON")"
[ -n "$PROXY" ] || { echo "could not parse proxy address from: $PROXY_JSON"; exit 1; }
echo "proxy: $PROXY"

# ── 4. sanity-read the live state ────────────────────────────────────────────
say "on-chain state"
MINT_TAG="$(cast call "$PROXY" 'MINT_TAG()(bytes32)' --rpc-url "$RPC")"
CUR_SIGNER="$(cast call "$PROXY" 'currentSigner()(address)' --rpc-url "$RPC")"
printf 'name        : %s\n' "$(cast call "$PROXY" 'name()(string)' --rpc-url "$RPC")"
printf 'decimals    : %s\n' "$(cast call "$PROXY" 'decimals()(uint8)' --rpc-url "$RPC")"
printf 'MINT_TAG    : %s\n' "$MINT_TAG"
printf 'currentSigner: %s\n' "$CUR_SIGNER"
if [ "$(echo "$CUR_SIGNER" | tr 'A-Z' 'a-z')" != "$(echo "$SIGNER_ADDR" | tr 'A-Z' 'a-z')" ]; then
  echo "!! currentSigner != the committee Pevm address"; exit 1
fi

# ── 5. the real mint preimage ────────────────────────────────────────────────
# Byte-for-byte what WrappedBDX.mint() keccaks:
#   abi.encode(MINT_TAG, block.chainid, address(this), to, amount, beldexTxid, outputIndex)
# Seven static words. OUT_INDEX is which gateway output of the Beldex tx this mint
# discharges (H-2): a tx may pay the gateway up to 15 times, each its own deposit.
OUT_INDEX="${OUT_INDEX:-0}"
say "mint preimage"
PREIMAGE="$(cast abi-encode \
  'f(bytes32,uint256,address,address,uint256,bytes32,uint32)' \
  "$MINT_TAG" "$CHAIN_ID" "$PROXY" "$TO" "$AMOUNT" "$BELDEX_TXID" "$OUT_INDEX")"
DIGEST="$(cast keccak "$PREIMAGE")"
printf 'to          : %s\n' "$TO"
printf 'amount      : %s atomic units (%s wBDX @ 9 decimals)\n' "$AMOUNT" "$(awk -v a="$AMOUNT" 'BEGIN{printf "%.9f", a/1000000000}')"
printf 'beldexTxid  : %s\n' "$BELDEX_TXID"
printf 'preimage    : %s\n' "$PREIMAGE"
printf 'digest      : %s\n' "$DIGEST"

cat > devnet/mint.env <<EOF
# generated by devnet/01-deploy.sh
RPC=$RPC
CHAIN_ID=$CHAIN_ID
IMPL=$IMPL
PROXY=$PROXY
SIGNER_ADDR=$SIGNER_ADDR
DEPLOYER=$DEPLOYER
DEPLOYER_KEY=$DEPLOYER_KEY
TO=$TO
AMOUNT=$AMOUNT
BELDEX_TXID=$BELDEX_TXID
MINT_TAG=$MINT_TAG
PREIMAGE=$PREIMAGE
DIGEST=$DIGEST
EOF
echo
echo "wrote devnet/mint.env"

cat <<EOF

────────────────────────────────────────────────────────────────────────────
NEXT — threshold-sign this preimage on the devnet committee.
From ~/Desktop/beldex/beldex/dkg-tss/beldex/utils/local-devnet run:

  runlog ./sign-mint.sh $PREIMAGE

(or set BRIDGE_SIGNER_SIGN_PREIMAGE=$PREIMAGE
 in the C.3 sign loop from bridge/signer/README.md, with
 BRIDGE_SIGNER_SIGN_LEG=pevm)

Then come back here and run:

  runlog ./devnet/02-mint.sh
────────────────────────────────────────────────────────────────────────────
EOF
