#!/usr/bin/env bash
# 03-rotate-prep.sh — build the H.6 rotation preimage the OUTGOING committee must sign.
#
#   ./devnet/03-rotate-prep.sh 0x<successor-pevm-address>
#
# The successor address comes from a *fresh* Pevm DKG (cggmp21 0.6.3 has no key refresh,
# so a membership change means a whole new key). Run that first — see
# utils/local-devnet/sign-rotate.sh's header for the DKG invocation.
#
# Writes devnet/rotate.env and prints the preimage to hand to sign-rotate.sh.

set -euo pipefail
cd "$(dirname "$0")/.."

RPC="${RPC:-http://127.0.0.1:8545}"

if [ ! -f devnet/mint.env ]; then
  echo "!! devnet/mint.env not found — run ./devnet/01-deploy.sh first" >&2
  exit 1
fi
# shellcheck disable=SC1091
. devnet/mint.env

NEW_SIGNER="${1:-${NEW_SIGNER:-}}"
if [ -z "$NEW_SIGNER" ]; then
  echo "usage: $0 0x<successor-pevm-address>" >&2
  echo "       (the address a fresh Pevm DKG produced for the incoming committee)" >&2
  exit 1
fi

# Normalise to lowercase 0x + 40 hex so string comparisons below are meaningful.
NEW_SIGNER="$(printf '%s' "$NEW_SIGNER" | tr 'A-Z' 'a-z')"
case "$NEW_SIGNER" in
  0x[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
  *) echo "!! not a 20-byte hex address: $NEW_SIGNER" >&2; exit 1 ;;
esac

# --- live contract state --------------------------------------------------------------
CUR_SIGNER="$(cast call "$PROXY" 'currentSigner()(address)' --rpc-url "$RPC" | tr 'A-Z' 'a-z')"
CUR_EPOCH="$(cast call "$PROXY" 'keyEpoch()(uint64)' --rpc-url "$RPC")"
# Newer cast appends the type in brackets on some builds; keep only leading digits.
CUR_EPOCH="$(printf '%s' "$CUR_EPOCH" | sed -n 's/^\([0-9][0-9]*\).*/\1/p')"
ROTATE_TAG_ONCHAIN="$(cast call "$PROXY" 'ROTATE_TAG()(bytes32)' --rpc-url "$RPC")"
ACTIVATE_TAG_ONCHAIN="$(cast call "$PROXY" 'ACTIVATE_TAG()(bytes32)' --rpc-url "$RPC")"
TIMELOCK="$(cast call "$PROXY" 'rotateTimelock()(uint256)' --rpc-url "$RPC" | sed -n 's/^\([0-9][0-9]*\).*/\1/p')"

NEW_KEY_EPOCH="${NEW_KEY_EPOCH:-$(( CUR_EPOCH + 1 ))}"

if [ "$NEW_SIGNER" = "$CUR_SIGNER" ]; then
  echo "!! the successor equals the current signer ($CUR_SIGNER)."
  echo "   A rotation to the same key proves nothing. Run a fresh Pevm DKG into a new"
  echo "   share directory and pass THAT address."
  exit 1
fi

# Independent check that the deployed tag is what we think it is. The expected value was
# computed off-tool (pycryptodome keccak-256 of the ASCII domain string), so agreement
# here means the contract, cast, and a third implementation all concur — the same
# cross-check that caught nothing in H.2 but is cheap enough to keep.
EXPECT_TAG=0x1f168494b9c165fdb7617d54f9474d57ca55d8bb4d3f5960fa2e09a81aba1fbd
lower() { printf '%s' "$1" | tr 'A-Z' 'a-z'; }
if [ "$(lower "$ROTATE_TAG_ONCHAIN")" != "$EXPECT_TAG" ]; then
  echo "!! ROTATE_TAG mismatch"
  echo "   on-chain : $ROTATE_TAG_ONCHAIN"
  echo "   expected : $EXPECT_TAG   (keccak256 of \"BELDEX_BRIDGE_ROTATE_V1\")"
  exit 1
fi
# And a third opinion from cast, if this build hashes bare strings as UTF-8.
CAST_TAG="$(lower "$(cast keccak 'BELDEX_BRIDGE_ROTATE_V1' 2>/dev/null || echo skip)")"
if [ "$CAST_TAG" != "skip" ] && [ "$CAST_TAG" != "$EXPECT_TAG" ]; then
  echo "   note: 'cast keccak' disagreed ($CAST_TAG) — likely a hex-vs-utf8 input"
  echo "         convention difference in this foundry build, not a contract problem."
fi

# Same cross-check for the activation tag (H.6.2b liveness proof). If the on-chain tag is
# empty/zero the deployment predates the incoming-signature gate — redeploy the contract.
EXPECT_ACTIVATE_TAG=0xdde1d75143faf59291dd472ba9226a0604d9eb613b71945f059fbc9365d56804
if [ "$(lower "$ACTIVATE_TAG_ONCHAIN")" != "$EXPECT_ACTIVATE_TAG" ]; then
  echo "!! ACTIVATE_TAG mismatch"
  echo "   on-chain : $ACTIVATE_TAG_ONCHAIN"
  echo "   expected : $EXPECT_ACTIVATE_TAG   (keccak256 of \"BELDEX_BRIDGE_ACTIVATE_V1\")"
  echo "   If it reads 0x0…0, this proxy is an OLD build without the activation liveness"
  echo "   gate — redeploy WrappedBDX before rotating."
  exit 1
fi

# --- the preimage ---------------------------------------------------------------------
# Mirrors WrappedBDX.rotateSigner:
#   keccak256(abi.encode(ROTATE_TAG, block.chainid, address(this), newKeyEpoch, newSigner))
# Five static words = 160 bytes. Note the ordering: epoch BEFORE signer (the mint tuple
# puts the address first) — getting this backwards produces a valid-looking signature
# that fails with BadSigner much later.
PREIMAGE="$(cast abi-encode \
  'f(bytes32,uint256,address,uint64,address)' \
  "$ROTATE_TAG_ONCHAIN" "$CHAIN_ID" "$PROXY" "$NEW_KEY_EPOCH" "$NEW_SIGNER")"
DIGEST="$(cast keccak "$PREIMAGE")"

# --- the ACTIVATION preimage (H.6.2b) -------------------------------------------------
# Mirrors WrappedBDX.activateRotation's incoming-liveness digest:
#   keccak256(abi.encode(ACTIVATE_TAG, block.chainid, address(this), pendingKeyEpoch, pendingSigner))
# At prep time pendingKeyEpoch==NEW_KEY_EPOCH and pendingSigner==NEW_SIGNER, so the same
# tuple shape as the rotate preimage — only the tag differs. This is the preimage the
# INCOMING committee (shares-next) signs to prove it can already sign under the new key.
ACTIVATE_PREIMAGE="$(cast abi-encode \
  'f(bytes32,uint256,address,uint64,address)' \
  "$ACTIVATE_TAG_ONCHAIN" "$CHAIN_ID" "$PROXY" "$NEW_KEY_EPOCH" "$NEW_SIGNER")"
ACTIVATE_DIGEST="$(cast keccak "$ACTIVATE_PREIMAGE")"

HEXLEN="$(printf '%s' "${PREIMAGE#0x}" | wc -c | tr -d ' ')"

cat > devnet/rotate.env <<EOF
# generated by 03-rotate-prep.sh — do not edit by hand
PROXY=$PROXY
CHAIN_ID=$CHAIN_ID
RPC=$RPC
ROTATE_TAG=$ROTATE_TAG_ONCHAIN
OUTGOING_SIGNER=$CUR_SIGNER
CUR_KEY_EPOCH=$CUR_EPOCH
NEW_SIGNER=$NEW_SIGNER
NEW_KEY_EPOCH=$NEW_KEY_EPOCH
ROTATE_TIMELOCK=$TIMELOCK
ROTATE_PREIMAGE=$PREIMAGE
ROTATE_DIGEST=$DIGEST
ACTIVATE_TAG=$ACTIVATE_TAG_ONCHAIN
ACTIVATE_PREIMAGE=$ACTIVATE_PREIMAGE
ACTIVATE_DIGEST=$ACTIVATE_DIGEST
EOF

cat <<EOF

  ROTATION PREPARED
  ─────────────────────────────────────────────────────────────────────
  contract        : $PROXY  (chain id $CHAIN_ID)
  outgoing signer : $CUR_SIGNER   (keyEpoch $CUR_EPOCH)
  incoming signer : $NEW_SIGNER   (keyEpoch $NEW_KEY_EPOCH)
  ROTATE_TAG      : $ROTATE_TAG_ONCHAIN  (keccak-verified)
  challenge window: ${TIMELOCK}s
  preimage        : $(( HEXLEN / 2 )) bytes ($HEXLEN hex chars, expect 160 / 320)
  digest          : $DIGEST

  written to devnet/rotate.env

  Next — TWO signatures are needed (H.6.2b):

  1. the OUTGOING committee authorises the hand-off (rotateSigner):

       cd <beldex>/utils/local-devnet
       runlog ./sign-rotate.sh $PREIMAGE

  2. the INCOMING committee proves liveness (activateRotation) — signed with the
     FRESH DKG shares (shares-next), logged to a distinct file so 04 can tell them
     apart:

       SHARE_SUBDIR=shares-next ACTIVATE=1 runlog ./sign-rotate.sh $ACTIVATE_PREIMAGE

  then come back and run:

    ./devnet/04-rotate.sh

EOF

if [ "$HEXLEN" -ne 320 ]; then
  echo "  !! expected 320 hex chars (160 bytes / 5 ABI words) — got $HEXLEN."
  echo "     Check the cast version's handling of the uint64 word."
  exit 1
fi
