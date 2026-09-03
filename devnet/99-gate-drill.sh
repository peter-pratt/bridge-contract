#!/usr/bin/env bash
# 99-gate-drill.sh — exercise the H.6.2b activation-liveness gate end-to-end on anvil
# using throwaway keys. Needs NO DKG and NO beldexd devnet: it deploys its own proxy
# so the real committee contract is untouched.
#
#   ./devnet/99-gate-drill.sh
set -euo pipefail
export PATH="$HOME/.foundry/bin:$PATH"
cd "$(cd "$(dirname "$0")/.." && pwd)"

RPC="${RPC:-http://127.0.0.1:8545}"
DEPLOYER_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
DEPLOYER=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
# anvil accounts #1 (outgoing committee) and #2 (incoming committee)
OLD_KEY=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
OLD_ADDR=0x70997970C51812dc3A010C7d01b50e0d17dc79C8
NEW_KEY=0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a
NEW_ADDR=0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
# capture a reverting `cast call`'s output without pipefail killing the script
tryrevert() { local out; out="$(cast call "$@" --rpc-url "$RPC" 2>&1 || true)"; printf '%s' "$out"; }
ok()  { printf '  \033[32m✓\033[0m %s\n' "$*"; }
bad() { printf '  \033[31m✗\033[0m %s\n' "$*"; exit 1; }

cast chain-id --rpc-url "$RPC" >/dev/null 2>&1 || { echo "anvil not up at $RPC — run ./devnet/01-deploy.sh first"; exit 1; }
CHAIN=$(cast chain-id --rpc-url "$RPC")

say "deploy a drill proxy (outgoing committee = $OLD_ADDR)"
IMPL=$(forge create src/WrappedBDX.sol:WrappedBDX --rpc-url "$RPC" --private-key "$DEPLOYER_KEY" --broadcast --json 2>/dev/null | tr -d ' \n' | sed -n 's/.*"deployedTo":"\([^"]*\)".*/\1/p')
INIT=$(cast calldata 'initialize(address,address,uint256,uint256,uint256,uint256,uint256)' \
  "$DEPLOYER" "$OLD_ADDR" 10000000000000 1000000000000 100000000000000 86400 3600)
PROXY=$(forge create lib/openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol:ERC1967Proxy \
  --rpc-url "$RPC" --private-key "$DEPLOYER_KEY" --broadcast --json \
  --constructor-args "$IMPL" "$INIT" 2>/dev/null | tr -d ' \n' | sed -n 's/.*"deployedTo":"\([^"]*\)".*/\1/p')
echo "  proxy $PROXY"
[ "$(cast call $PROXY 'currentSigner()(address)' --rpc-url $RPC)" = "$OLD_ADDR" ] && ok "currentSigner = outgoing" || bad "wrong signer"

say "1. outgoing committee proposes the successor"
RD=$(cast keccak "$(cast abi-encode 'f(bytes32,uint256,address,uint64,address)' \
      "$(cast call $PROXY 'ROTATE_TAG()(bytes32)' --rpc-url $RPC)" "$CHAIN" "$PROXY" 2 "$NEW_ADDR")")
RSIG=$(cast wallet sign --private-key "$OLD_KEY" --no-hash "$RD")
cast send "$PROXY" 'rotateSigner(address,uint64,bytes)' "$NEW_ADDR" 2 "$RSIG" \
  --rpc-url "$RPC" --private-key "$DEPLOYER_KEY" >/dev/null
ok "pendingSigner = $(cast call $PROXY 'pendingSigner()(address)' --rpc-url $RPC)"

say "2. before the window closes, activation must be refused"
case "$(tryrevert "$PROXY" 'activateRotation(bytes)' 0x)" in
  *0x0f1f7e1a*) ok "reverts RotationNotReady (timelock still running)" ;;
  *) bad "expected RotationNotReady" ;;
esac

say "3. cross the challenge window"
cast rpc evm_increaseTime 3601 --rpc-url "$RPC" >/dev/null
cast rpc evm_mine --rpc-url "$RPC" >/dev/null
ok "warped past pendingActivateAt"

say "4. THE GATE: timelock done, no veto — but no incoming proof"
case "$(tryrevert "$PROXY" 'activateRotation(bytes)' 0x)" in
  *revert*) ok "empty proof rejected (old code would have flipped here)" ;;
  *) bad "empty proof accepted!" ;;
esac

AD_WRONG=$(cast keccak "$(cast abi-encode 'f(bytes32,uint256,address,uint64,address)' \
      "$(cast call $PROXY 'ACTIVATE_TAG()(bytes32)' --rpc-url $RPC)" "$CHAIN" "$PROXY" 2 "$NEW_ADDR")")
WSIG=$(cast wallet sign --private-key "$OLD_KEY" --no-hash "$AD_WRONG")
case "$(tryrevert "$PROXY" 'activateRotation(bytes)' "$WSIG")" in
  *0x112a71a4*) ok "OUTGOING key's proof rejected: IncomingNotReady" ;;
  *) bad "wrong-key proof accepted!" ;;
esac

[ "$(cast call $PROXY 'currentSigner()(address)' --rpc-url $RPC)" = "$OLD_ADDR" ] \
  && ok "currentSigner unchanged — bridge still alive on the old key" || bad "signer moved!"

say "5. incoming committee proves liveness — now it flips"
ASIG=$(cast wallet sign --private-key "$NEW_KEY" --no-hash "$AD_WRONG")
cast send "$PROXY" 'activateRotation(bytes)' "$ASIG" \
  --rpc-url "$RPC" --private-key "$DEPLOYER_KEY" >/dev/null
[ "$(cast call $PROXY 'currentSigner()(address)' --rpc-url $RPC)" = "$NEW_ADDR" ] \
  && ok "currentSigner = incoming, keyEpoch = $(cast call $PROXY 'keyEpoch()(uint64)' --rpc-url $RPC)" || bad "flip failed"

say "6. cutover is clean: new key mints, old key rejected"
mintsig() { # $1=key $2=txid
  cast wallet sign --private-key "$1" --no-hash "$(cast keccak "$(cast abi-encode \
    'f(bytes32,uint256,address,address,uint256,bytes32,uint32)' \
    "$(cast call $PROXY 'MINT_TAG()(bytes32)' --rpc-url $RPC)" "$CHAIN" "$PROXY" "$DEPLOYER" 1000000000 "$2" 0)")"
}
T1=0x00000000000000000000000000000000000000000000000000000000000000a1
cast send "$PROXY" 'mint(address,uint256,bytes32,uint32,bytes)' "$DEPLOYER" 1000000000 "$T1" 0 "$(mintsig $NEW_KEY $T1)" \
  --rpc-url "$RPC" --private-key "$DEPLOYER_KEY" >/dev/null
ok "new key minted — balance $(cast call $PROXY 'balanceOf(address)(uint256)' $DEPLOYER --rpc-url $RPC)"

T2=0x00000000000000000000000000000000000000000000000000000000000000a2
case "$(tryrevert "$PROXY" 'mint(address,uint256,bytes32,uint32,bytes)' "$DEPLOYER" 1000000000 "$T2" 0 "$(mintsig $OLD_KEY $T2)")" in
  *0x61330e93*) ok "old key rejected: BadSigner" ;;
  *) bad "old key still mints!" ;;
esac

printf '\n\033[1;32mDRILL PASSED\033[0m — the gate blocked the unproven cutover and allowed the proven one.\n\n'
