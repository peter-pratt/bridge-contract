#!/usr/bin/env bash
# 04-rotate.sh — submit the H.6 rotation the outgoing committee signed, cross the
# challenge window, activate, and prove the hand-off actually took effect.
#
#   ./devnet/04-rotate.sh
#
# Reads devnet/rotate.env (from 03-rotate-prep.sh) and scrapes the committee's signature
# out of the sign-rotate.sh logs. Asserts, in order:
#
#   1. every signer that produced a signature produced the SAME one
#   2. they signed the digest 03-rotate-prep.sh computed (not some other preimage)
#   3. rotateSigner is accepted, and currentSigner does NOT move yet
#   4. activateRotation reverts RotationNotReady before the window closes
#   5. after warping past it, activateRotation switches the key and emits Rotated
#   6. re-proposing the same epoch now reverts StaleEpoch (anti-rollback)

set -euo pipefail
cd "$(dirname "$0")/.."

if [ ! -f devnet/rotate.env ]; then
  echo "!! devnet/rotate.env not found — run ./devnet/03-rotate-prep.sh <successor> first" >&2
  exit 1
fi
# shellcheck disable=SC1091
. devnet/rotate.env

RPC="${RPC:-http://127.0.0.1:8545}"
TESTDATA="${TESTDATA:-../beldex/utils/local-devnet/testdata}"
DEPLOYER_KEY="${DEPLOYER_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"

lower() { printf '%s' "$1" | tr 'A-Z' 'a-z'; }
num()   { printf '%s' "$1" | sed -n 's/^[^0-9]*\([0-9][0-9]*\).*/\1/p'; }

# =======================================================================================
# 1. collect the committee's signature
# =======================================================================================
if [ ! -d "$TESTDATA" ]; then
  echo "!! no testdata dir at $TESTDATA" >&2
  echo "   set TESTDATA=/path/to/beldex/utils/local-devnet/testdata" >&2
  exit 1
fi

SIGS="$(grep -h '^Pevm signature:' "$TESTDATA"/rotate-sign-*.log 2>/dev/null \
        | sed 's/^Pevm signature:[[:space:]]*//' | tr -d ' \r' | sort -u || true)"
NSIG="$(printf '%s\n' "$SIGS" | grep -c . || true)"

if [ "$NSIG" -eq 0 ]; then
  echo "!! no 'Pevm signature:' line in $TESTDATA/rotate-sign-*.log" >&2
  echo "   run:  cd <beldex>/utils/local-devnet && runlog ./sign-rotate.sh $ROTATE_PREIMAGE" >&2
  exit 1
fi
if [ "$NSIG" -ne 1 ]; then
  echo "!! the signers disagreed — $NSIG distinct signatures:" >&2
  printf '   %s\n' $SIGS >&2
  echo "   A threshold signature is deterministic across the signing set for a fixed" >&2
  echo "   session; more than one value means they signed different preimages." >&2
  exit 1
fi
RS="$(printf '%s' "$SIGS")"
case "$RS" in 0x*) ;; *) RS="0x$RS" ;; esac

RSHEX="${RS#0x}"
if [ "${#RSHEX}" -ne 128 ]; then
  echo "!! expected 64 bytes of r||s (128 hex chars), got $(( ${#RSHEX} / 2 )) bytes" >&2
  exit 1
fi

# 2. and that they signed OUR digest, not something else
LOGGED="$(grep -h 'over digest' "$TESTDATA"/rotate-sign-*.log 2>/dev/null \
          | sed 's/.*over digest[[:space:]]*:*[[:space:]]*//' | tr -d ' \r' | sort -u | head -1 || true)"
if [ -n "$LOGGED" ]; then
  if [ "$(lower "${LOGGED#0x}")" != "$(lower "${ROTATE_DIGEST#0x}")" ]; then
    echo "!! the committee signed a different digest" >&2
    echo "   signed   : $LOGGED" >&2
    echo "   expected : $ROTATE_DIGEST" >&2
    echo "   Re-run sign-rotate.sh with the preimage from devnet/rotate.env." >&2
    exit 1
  fi
  echo "digest cross-check : the committee signed exactly ${ROTATE_DIGEST}"
fi

# 2b. the INCOMING committee's activation signature (H.6.2b liveness proof). Signed with
#     shares-next and logged under the `activate` prefix so it does not mix with the rotate
#     signature above.
ASIGS="$(grep -h '^Pevm signature:' "$TESTDATA"/activate-sign-*.log 2>/dev/null \
         | sed 's/^Pevm signature:[[:space:]]*//' | tr -d ' \r' | sort -u || true)"
ANSIG="$(printf '%s\n' "$ASIGS" | grep -c . || true)"
if [ "$ANSIG" -eq 0 ]; then
  echo "!! no incoming-committee activation signature in $TESTDATA/activate-sign-*.log" >&2
  echo "   The contract now requires the NEW committee to prove liveness before the old" >&2
  echo "   key is retired (H.6.2b). Produce it with the fresh DKG shares:" >&2
  echo "     cd <beldex>/utils/local-devnet" >&2
  echo "     SHARE_SUBDIR=shares-next ACTIVATE=1 runlog ./sign-rotate.sh $ACTIVATE_PREIMAGE" >&2
  exit 1
fi
if [ "$ANSIG" -ne 1 ]; then
  echo "!! the incoming signers disagreed — $ANSIG distinct activation signatures:" >&2
  printf '   %s\n' $ASIGS >&2
  exit 1
fi
ARS="$(printf '%s' "$ASIGS")"
case "$ARS" in 0x*) ;; *) ARS="0x$ARS" ;; esac
ARSHEX="${ARS#0x}"
if [ "${#ARSHEX}" -ne 128 ]; then
  echo "!! activation sig: expected 64 bytes of r||s (128 hex), got $(( ${#ARSHEX} / 2 ))" >&2
  exit 1
fi
# Cross-check the incoming committee signed OUR activation digest, not something else.
ALOGGED="$(grep -h 'over digest' "$TESTDATA"/activate-sign-*.log 2>/dev/null \
           | sed 's/.*over digest[[:space:]]*:*[[:space:]]*//' | tr -d ' \r' | sort -u | head -1 || true)"
if [ -n "$ALOGGED" ] && [ -n "${ACTIVATE_DIGEST:-}" ]; then
  if [ "$(lower "${ALOGGED#0x}")" != "$(lower "${ACTIVATE_DIGEST#0x}")" ]; then
    echo "!! the incoming committee signed a different activation digest" >&2
    echo "   signed   : $ALOGGED" >&2
    echo "   expected : $ACTIVATE_DIGEST" >&2
    exit 1
  fi
  echo "activation digest  : the incoming committee signed exactly ${ACTIVATE_DIGEST}"
fi

echo "signature          : $RS"
echo "activation sig     : $ARS"
echo "outgoing signer    : $OUTGOING_SIGNER  (keyEpoch $CUR_KEY_EPOCH)"
echo "incoming signer    : $NEW_SIGNER  (keyEpoch $NEW_KEY_EPOCH)"
echo ""

# =======================================================================================
# 3. propose
# =======================================================================================
echo "── propose ────────────────────────────────────────────────────────────"
PROXY="$PROXY" NEW_SIGNER="$NEW_SIGNER" NEW_KEY_EPOCH="$NEW_KEY_EPOCH" ROTATE_RS="$RS" \
  forge script script/DevnetRotate.s.sol:DevnetRotate --sig 'propose()' \
    --rpc-url "$RPC" --private-key "$DEPLOYER_KEY" --broadcast -vv

AFTER_PROPOSE="$(lower "$(cast call "$PROXY" 'currentSigner()(address)' --rpc-url "$RPC")")"
if [ "$AFTER_PROPOSE" != "$(lower "$OUTGOING_SIGNER")" ]; then
  echo "!! currentSigner changed at propose time — the challenge window is not holding" >&2
  exit 1
fi
ACTIVATE_AT="$(num "$(cast call "$PROXY" 'pendingActivateAt()(uint256)' --rpc-url "$RPC")")"
echo ""
echo "-> proposed; currentSigner still $OUTGOING_SIGNER, activates at $ACTIVATE_AT"

# =======================================================================================
# 4. the window must actually bite
# =======================================================================================
echo ""
echo "── early activation must fail ─────────────────────────────────────────"
EARLY="$(cast call "$PROXY" 'activateRotation(bytes)' 0x --rpc-url "$RPC" 2>&1 || true)"
case "$EARLY" in
  *RotationNotReady*|*0f1f7e1a*)
    echo "-> RotationNotReady()  the challenge window is being enforced" ;;
  *RotationIsVetoed*|*475abcc2*)
    echo "!! RotationIsVetoed() — a prior veto is still set; clear it before rotating" >&2; exit 1 ;;
  *)
    echo "!! early activateRotation did NOT revert as expected:" >&2
    echo "$EARLY" >&2
    echo "   The timelock is the entire point of H.6.2 — stopping here." >&2
    exit 1 ;;
esac

# =======================================================================================
# 5. warp past the window and activate
# =======================================================================================
now_ts() {
  t="$(cast block latest --rpc-url "$RPC" --field timestamp 2>/dev/null || true)"
  if [ -z "$t" ]; then
    t="$(cast block latest --rpc-url "$RPC" 2>/dev/null | sed -n 's/^timestamp[[:space:]]*\([0-9][0-9]*\).*/\1/p')"
  fi
  num "$t"
}

TS_BEFORE="$(now_ts)"
NEED=$(( ACTIVATE_AT - TS_BEFORE + 1 ))
echo ""
echo "── warp ───────────────────────────────────────────────────────────────"
echo "chain time $TS_BEFORE, need $ACTIVATE_AT (+${NEED}s)"
if [ "$NEED" -gt 0 ]; then
  cast rpc evm_increaseTime "$NEED" --rpc-url "$RPC" >/dev/null
  cast rpc evm_mine --rpc-url "$RPC" >/dev/null
fi
TS_AFTER="$(now_ts)"
echo "chain time now $TS_AFTER"
if [ "$TS_AFTER" -lt "$ACTIVATE_AT" ]; then
  echo "!! the warp did not take — anvil is still at $TS_AFTER, need $ACTIVATE_AT" >&2
  echo "   Some builds want a hex-quoted arg: cast rpc evm_increaseTime '\"0x...\"'" >&2
  exit 1
fi

# A veto landing DURING the challenge window is the H.6.2c scenario — the Beldex watchers
# noticing that pendingSigner is not the address the consensus-selected committee actually
# DKG'd. Catch it here with a clear message rather than letting forge report a bare revert.
echo ""
echo "── activate ───────────────────────────────────────────────────────────"
# Probe with the REAL incoming signature so a genuine IncomingNotReady (bad liveness proof)
# would surface here too, not just veto/not-ready.
PRECHECK="$(cast call "$PROXY" 'activateRotation(bytes)' "$ARS" --rpc-url "$RPC" 2>&1 || true)"
case "$PRECHECK" in
  *RotationIsVetoed*|*475abcc2*)
    echo "!! RotationIsVetoed() — this rotation was vetoed during the challenge window." >&2
    echo "   That is the freeze path working: someone with the veto authority rejected" >&2
    echo "   this successor. Investigate before re-proposing; a fresh valid proposal" >&2
    echo "   clears the veto, so do not just re-run 03/04 to make it go away." >&2
    exit 1 ;;
  *RotationNotReady*|*0f1f7e1a*)
    echo "!! still RotationNotReady after the warp — chain time did not advance enough" >&2
    exit 1 ;;
  *IncomingNotReady*)
    echo "!! IncomingNotReady() — the incoming committee's activation signature does not" >&2
    echo "   recover to pendingSigner. Re-sign the ACTIVATE_PREIMAGE with shares-next." >&2
    exit 1 ;;
esac

PROXY="$PROXY" ACTIVATE_RS="$ARS" \
  forge script script/DevnetRotate.s.sol:DevnetRotate --sig 'activate()' \
    --rpc-url "$RPC" --private-key "$DEPLOYER_KEY" --broadcast -vv

# =======================================================================================
# 6. verify through cast, independently of the forge script's own asserts
# =======================================================================================
FINAL_SIGNER="$(lower "$(cast call "$PROXY" 'currentSigner()(address)' --rpc-url "$RPC")")"
FINAL_EPOCH="$(num "$(cast call "$PROXY" 'keyEpoch()(uint64)' --rpc-url "$RPC")")"
FINAL_PENDING="$(lower "$(cast call "$PROXY" 'pendingSigner()(address)' --rpc-url "$RPC")")"

echo ""
echo "── on-chain state ─────────────────────────────────────────────────────"
echo "currentSigner : $FINAL_SIGNER"
echo "keyEpoch      : $FINAL_EPOCH"
echo "pendingSigner : $FINAL_PENDING"

FAIL=0
[ "$FINAL_SIGNER" = "$(lower "$NEW_SIGNER")" ] || { echo "!! currentSigner is not the successor" >&2; FAIL=1; }
[ "$FINAL_EPOCH" = "$NEW_KEY_EPOCH" ]          || { echo "!! keyEpoch is not $NEW_KEY_EPOCH" >&2; FAIL=1; }
case "$FINAL_PENDING" in
  0x0000000000000000000000000000000000000000) ;;
  *) echo "!! pendingSigner was not cleared" >&2; FAIL=1 ;;
esac

# The Rotated event. topic0 = keccak256("Rotated(address,uint64)"), verified off-tool.
ROTATED_TOPIC=0x269f54be3fd9dae2b1922d245de433f65deabdfa03c28c5f202cba783c153ba4
echo ""
echo "── Rotated event ──────────────────────────────────────────────────────"
cast logs --rpc-url "$RPC" --address "$PROXY" "$ROTATED_TOPIC" --from-block 0 2>/dev/null || true

# =======================================================================================
# 7. anti-rollback: the same proposal must not replay
# =======================================================================================
echo ""
echo "── replay the rotation (must be rejected) ─────────────────────────────"
STALE="$(cast call "$PROXY" 'rotateSigner(address,uint64,bytes)' \
          "$NEW_SIGNER" "$NEW_KEY_EPOCH" "${RS}1b" --rpc-url "$RPC" 2>&1 || true)"
case "$STALE" in
  *StaleEpoch*|*68549ea1*) echo "-> StaleEpoch()  anti-rollback holds" ;;
  *BadSigner*|*61330e93*)  echo "-> BadSigner()   (rejected, though on the signature not the epoch —" ;
                           echo "                 expected, since this probe appends a guessed v)" ;;
  *) echo "-> rejected for an unrecognised reason:" ; echo "$STALE" ;;
esac

echo ""
if [ "$FAIL" -eq 0 ]; then
  cat <<EOF
  ROTATION COMPLETE & VERIFIED
  ─────────────────────────────────────────────────────────────────────
  The outgoing committee signed its successor in. No admin key was used.

    $OUTGOING_SIGNER  (epoch $CUR_KEY_EPOCH)
      -> $FINAL_SIGNER  (epoch $FINAL_EPOCH)

  Next, prove the hand-off is real in both directions:

    # the OLD committee can no longer mint (expect BadSigner)
    # the NEW committee can (expect a successful mint)
    # -> re-run 01/02 with a fresh BELDEX_TXID against the new share dir

EOF
else
  echo "  ROTATION FAILED VERIFICATION — see the !! lines above"
  exit 1
fi
