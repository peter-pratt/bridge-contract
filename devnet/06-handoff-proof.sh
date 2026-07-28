#!/usr/bin/env bash
# 06-handoff-proof.sh — prove the H.6 hand-off bit in BOTH directions.
#
#     runlog ./devnet/06-handoff-proof.sh
#
# 04-rotate.sh proved the contract's pointer moved. That is only half the claim. A pointer
# that moved but that the old key can still mint past is not a hand-off, and a pointer that
# moved to a key that cannot mint is a brick. This script closes both:
#
#     retired committee  -> mint() reverts BadSigner()
#     promoted committee -> mint() succeeds, balance moves, Minted fires
#     the same txid again -> Replay()
#
# THE THING THAT MAKES IT A PROOF is that both committees sign the SAME preimage, prepared
# once by 05-mint-prep.sh. Same tag, chain id, contract, recipient, amount, txid, therefore
# the same digest. The only variable is which share tree produced the signature. If the two
# runs signed different messages, "one worked and one didn't" would say nothing about keys.
# Every assertion below re-checks that shared digest before it checks anything else.
#
# The negative leg is a STATIC `cast call`, not a broadcast, for two reasons: nothing about
# a rejected attempt should be able to touch state, and forge's DevnetMint script would
# abort locally on its own `require` (it brute-forces v against currentSigner) before ever
# reaching the contract — proving only that the script noticed, not that the contract did.
# Both recovery ids are tried, so "BadSigner" cannot be an artifact of picking the wrong v.
#
# Env:
#   TESTDATA   where the signer logs live
#   SIG_NEW    override the promoted committee's r||s instead of scraping
#   SIG_OLD    override the retired committee's r||s instead of scraping

set -euo pipefail
export PATH="$HOME/.foundry/bin:$PATH"
cd "$(cd "$(dirname "$0")/.." && pwd)"

[ -f devnet/mint2.env ] || { echo "!! no devnet/mint2.env — run ./devnet/05-mint-prep.sh first" >&2; exit 1; }
# shellcheck disable=SC1091
. devnet/mint2.env

TESTDATA="${TESTDATA:-$HOME/Niyas/projects/beldex/utils/local-devnet/testdata}"
say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
lc()   { printf '%s' "$1" | tr 'A-Z' 'a-z'; }
num()  { printf '%s' "$1" | sed -n 's/^\([0-9][0-9]*\).*/\1/p'; }
fail() { printf '\n\033[1;31m!! %s\033[0m\n' "$*" >&2; exit 1; }

# WrappedBDX's custom errors, as foundry reports them when the ABI is not to hand.
SEL_BADSIGNER=61330e93
SEL_REPLAY=b5a78004
SEL_PERTX=e91f21b6
SEL_WINDOW=7b8118d9

# --- scrape and sanity-check one committee's signature -------------------------------------
# Asserts three things about each run, in the order that makes a failure diagnosable:
# the signers agreed with each other, they signed OUR digest, and the key they signed with
# is the one we think it is. The signer prints the recovered Ethereum address itself, so
# that last check needs no crypto here — and it is what turns the negative leg from
# "some signature was rejected" into "a VALID signature by the retired committee, over
# exactly this digest, was rejected".
scrape() {
  local prefix="$1" want_signer="$2" label="$3" sigs count logdigest logsigner ndig nsig
  ls "$TESTDATA/$prefix-sign-"*.log >/dev/null 2>&1 \
    || fail "no $prefix-sign-*.log in $TESTDATA — the $label signing run has not been done"

  sigs="$(grep -h '^Pevm signature:' "$TESTDATA/$prefix-sign-"*.log 2>/dev/null \
          | sed 's/^Pevm signature:[[:space:]]*//' | tr -d ' \r' | sort -u || true)"
  [ -n "$sigs" ] || fail "no 'Pevm signature:' line in $prefix-sign-*.log — that run failed"
  count="$(printf '%s\n' "$sigs" | grep -c . || true)"
  [ "$count" -eq 1 ] || fail "the $label signers disagree ($count distinct signatures)"

  # `sort -u` WITHOUT a `head -1`, then a count. An earlier draft took the first line of the
  # sorted set, which meant a single node that had signed something else was invisible: the
  # matching value sorted first and the check passed on it. Divergence among nodes is the
  # failure this is here to catch, so the number of distinct values is the thing to assert.
  logdigest="$(grep -h 'over digest' "$TESTDATA/$prefix-sign-"*.log 2>/dev/null \
               | sed 's/.*: *//' | tr -d ' \r' | tr 'A-Z' 'a-z' | sed 's/^0x//' | sort -u || true)"
  ndig="$(printf '%s\n' "$logdigest" | grep -c . || true)"
  if [ "$ndig" -gt 1 ]; then
    fail "the $label logs report $ndig DIFFERENT digests:
$(printf '     0x%s\n' $logdigest)
   At least one node signed a different message. Do not read anything into the result."
  fi
  if [ -n "$logdigest" ] && [ "0x$logdigest" != "$(lc "$DIGEST")" ]; then
    fail "the $label committee signed 0x$logdigest, but the prepared digest is $DIGEST
   Both committees must sign the ONE preimage 05-mint-prep.sh produced, or this
   comparison is between two different messages and proves nothing."
  fi

  logsigner="$(grep -h 'wBDX signer' "$TESTDATA/$prefix-sign-"*.log 2>/dev/null \
               | sed 's/.*: *//' | tr -d ' \r' | tr 'A-Z' 'a-z' | sort -u || true)"
  nsig="$(printf '%s\n' "$logsigner" | grep -c . || true)"
  if [ "$nsig" -gt 1 ]; then
    fail "the $label logs recover to $nsig DIFFERENT addresses:
$(printf '     %s\n' $logsigner)
   The nodes are not holding shares of one key."
  fi
  if [ -n "$logsigner" ] && [ "$logsigner" != "$(lc "$want_signer")" ]; then
    fail "$prefix-sign-*.log recovers to $logsigner, expected the $label key $want_signer
   Wrong share tree: check SHARE_SUBDIR on that run."
  fi

  printf '%s' "$sigs"
}

# --- EIP-2 low-S ---------------------------------------------------------------------------
# The Rust signer emits the raw (r,s) pair; roughly half the time s is above N/2, which OZ's
# ECDSA.recover rejects outright with ECDSAInvalidSignatureS. On the negative leg that would
# be a revert for the WRONG reason — a malformed-signature error dressed up as a rejected
# committee. DevnetMint.s.sol normalises internally for the positive leg; the raw cast call
# has to do it here.
lows() {
  python3 - "$1" <<'PY'
import sys
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
rs = sys.argv[1]
if rs[:2].lower() == '0x':
    rs = rs[2:]
assert len(rs) == 128, "r||s must be 64 bytes, got %d" % (len(rs) // 2)
r, s = rs[:64], int(rs[64:], 16)
if s > N // 2:
    s = N - s
print(r + '%064x' % s)
PY
}
command -v python3 >/dev/null || fail "python3 is needed for the EIP-2 low-S normalisation"

# --- gather ---------------------------------------------------------------------------------
say "signatures"
SIG_NEW="${SIG_NEW:-$(scrape mint     "$LIVE_SIGNER"    'promoted')}"
SIG_OLD="${SIG_OLD:-$(scrape mint-old "$RETIRED_SIGNER" 'retired')}"
SIG_NEW="${SIG_NEW#0x}"; SIG_OLD="${SIG_OLD#0x}"
[ "${#SIG_NEW}" -eq 128 ] || fail "the promoted committee's r||s is ${#SIG_NEW} hex chars, expected 128"
[ "${#SIG_OLD}" -eq 128 ] || fail "the retired committee's r||s is ${#SIG_OLD} hex chars, expected 128"
[ "$(lc "$SIG_NEW")" != "$(lc "$SIG_OLD")" ] \
  || fail "both runs produced the SAME signature — they used the same share tree.
   The retired run needs SHARE_SUBDIR=shares-gen0."

RS_NEW="$(lows "$SIG_NEW")"
RS_OLD="$(lows "$SIG_OLD")"
printf 'promoted (%s)\n  r||s %s\n' "$LIVE_SIGNER" "$SIG_NEW"
printf 'retired  (%s)\n  r||s %s\n' "$RETIRED_SIGNER" "$SIG_OLD"
echo "both signed digest $DIGEST ✓"
echo "both recovered to the key their share tree belongs to ✓"

# --- state before ----------------------------------------------------------------------------
say "state before"
BAL_BEFORE="$(num "$(cast call "$PROXY" 'balanceOf(address)(uint256)' "$TO" --rpc-url "$RPC")")"
SUPPLY_BEFORE="$(num "$(cast call "$PROXY" 'totalSupply()(uint256)' --rpc-url "$RPC")")"
CUR_BEFORE="$(lc "$(cast call "$PROXY" 'currentSigner()(address)' --rpc-url "$RPC")")"
EPOCH_BEFORE="$(num "$(cast call "$PROXY" 'keyEpoch()(uint64)' --rpc-url "$RPC")")"
printf 'balanceOf(%s) = %s\ntotalSupply = %s\ncurrentSigner = %s (keyEpoch %s)\n' \
  "$TO" "$BAL_BEFORE" "$SUPPLY_BEFORE" "$CUR_BEFORE" "$EPOCH_BEFORE"
[ "$CUR_BEFORE" = "$(lc "$LIVE_SIGNER")" ] \
  || fail "currentSigner moved to $CUR_BEFORE since 05-mint-prep.sh ran — re-run it"

# --- leg A: the retired committee must NOT be able to mint ------------------------------------
# Static call. Both recovery ids, because v is not part of a threshold signature — it is
# brute-forced by whoever assembles the 65 bytes, so "it failed" only means something if it
# failed for every v it could have been.
say "leg A — retired committee ($RETIRED_SIGNER) attempts the mint"
for V in 1b 1c; do
  OUT="$(cast call "$PROXY" 'mint(address,uint256,bytes32,bytes)' \
          "$TO" "$AMOUNT" "$BELDEX_TXID" "0x${RS_OLD}${V}" --rpc-url "$RPC" 2>&1)" && RC=0 || RC=1
  if [ "$RC" -eq 0 ]; then
    fail "the retired committee's signature was ACCEPTED with v=0x$V.
   The rotation did not actually retire it. Do not ship this."
  fi
  case "$OUT" in
    *BadSigner*|*"$SEL_BADSIGNER"*) printf '  v=0x%s -> BadSigner()  ✓\n' "$V" ;;
    *Replay*|*"$SEL_REPLAY"*)
      fail "v=0x$V reverted Replay(), not BadSigner() — the txid was already spent, so this
   leg never reached the signature check. Prepare a fresh txid with 05-mint-prep.sh." ;;
    *PerTxCap*|*"$SEL_PERTX"*|*WindowCap*|*"$SEL_WINDOW"*)
      fail "v=0x$V reverted on a cap, not on the signature — this leg proves nothing.
   05-mint-prep.sh checks the headroom; re-run it." ;;
    *ECDSAInvalidSignature*)
      fail "v=0x$V was rejected as a MALFORMED signature, not as a wrong signer.
   That is a signature-encoding failure, not the property under test.
$OUT" ;;
    *)
      printf '  v=0x%s -> reverted, but not recognisably BadSigner:\n' "$V"
      printf '%s\n' "$OUT" | head -5
      fail "unrecognised revert on leg A — see above" ;;
  esac
done
echo ""
echo "  The retired key produced a signature that IS valid over this exact digest (the"
echo "  signer's own ecrecover confirmed it above). The contract rejected it anyway."
echo "  That is the hand-off biting, not a broken signature."

# --- leg B: the promoted committee MUST be able to mint ----------------------------------------
say "leg B — promoted committee ($LIVE_SIGNER) mints"
PROXY="$PROXY" TO="$TO" AMOUNT="$AMOUNT" BELDEX_TXID="$BELDEX_TXID" SIG_RS="0x$SIG_NEW" \
  forge script script/DevnetMint.s.sol:DevnetMint \
    --rpc-url "$RPC" --private-key "$DEPLOYER_KEY" --broadcast -vv

# --- independent verification, via cast rather than the script's own requires -------------------
say "verify"
BAL_AFTER="$(num "$(cast call "$PROXY" 'balanceOf(address)(uint256)' "$TO" --rpc-url "$RPC")")"
SUPPLY_AFTER="$(num "$(cast call "$PROXY" 'totalSupply()(uint256)' --rpc-url "$RPC")")"
SPENT="$(cast call "$PROXY" 'processedDeposits(bytes32)(bool)' "$BELDEX_TXID" --rpc-url "$RPC")"
CUR_AFTER="$(lc "$(cast call "$PROXY" 'currentSigner()(address)' --rpc-url "$RPC")")"
EPOCH_AFTER="$(num "$(cast call "$PROXY" 'keyEpoch()(uint64)' --rpc-url "$RPC")")"

printf 'balance  %s -> %s   (delta %s, expected %s)\n' \
  "$BAL_BEFORE" "$BAL_AFTER" "$(( BAL_AFTER - BAL_BEFORE ))" "$AMOUNT"
printf 'supply   %s -> %s\n' "$SUPPLY_BEFORE" "$SUPPLY_AFTER"
printf 'processedDeposits[%s] = %s\n' "$BELDEX_TXID" "$SPENT"
printf 'currentSigner %s (keyEpoch %s)\n' "$CUR_AFTER" "$EPOCH_AFTER"

[ "$(( BAL_AFTER - BAL_BEFORE ))" -eq "$AMOUNT" ] || fail "balance did not move by exactly AMOUNT"
[ "$(( SUPPLY_AFTER - SUPPLY_BEFORE ))" -eq "$AMOUNT" ] || fail "totalSupply did not move by exactly AMOUNT"
[ "$(lc "$SPENT")" = "true" ] || fail "the deposit was not marked processed"
# A mint must not be able to move the key. Cheap, and it would be a serious finding.
[ "$CUR_AFTER" = "$CUR_BEFORE" ] || fail "currentSigner CHANGED across a mint: $CUR_BEFORE -> $CUR_AFTER"
[ "$EPOCH_AFTER" = "$EPOCH_BEFORE" ] || fail "keyEpoch CHANGED across a mint: $EPOCH_BEFORE -> $EPOCH_AFTER"
echo "balance, supply, replay flag ✓ — and the mint moved neither currentSigner nor keyEpoch ✓"

say "Minted event for this txid"
MINTED_LOGS="$(cast logs --from-block 0 --address "$PROXY" \
  "$(cast sig-event 'Minted(address,uint256,bytes32)')" --rpc-url "$RPC" 2>/dev/null || true)"
if printf '%s\n' "$MINTED_LOGS" | grep -qi "${BELDEX_TXID#0x}"; then
  printf '%s\n' "$MINTED_LOGS" | grep -i -B6 -A6 "${BELDEX_TXID#0x}"
  echo "  a Minted log carries this beldexTxid as an indexed topic ✓"
else
  echo "  !! no Minted log mentions ${BELDEX_TXID} — full dump:"
  printf '%s\n' "$MINTED_LOGS"
  fail "the mint reported success but did not emit a Minted event for this txid"
fi

# --- leg C: replay ------------------------------------------------------------------------------
say "leg C — the promoted committee's own signature, replayed"
# v is NOT part of a threshold signature -- exactly one of 0x1b/0x1c is this signature's
# recovery id and the other recovers to an unrelated address, which mint() rejects at the
# signer check BEFORE it ever consults the replay guard. Hardcoding one v makes this leg a
# coin flip: half the time it reports BadSigner and the replay guard is never exercised.
REPLAY_OK=0
for V in 1b 1c; do
  OUT="$(cast call "$PROXY" 'mint(address,uint256,bytes32,bytes)' \
          "$TO" "$AMOUNT" "$BELDEX_TXID" "0x${RS_NEW}${V}" --rpc-url "$RPC" 2>&1)" && RC=0 || RC=1
  if [ "$RC" -eq 0 ]; then
    fail "the replay did NOT revert with v=0x$V -- the same beldexTxid minted twice."
  fi
  case "$OUT" in
    *Replay*|*"$SEL_REPLAY"*)
      printf '  v=0x%s -> Replay()  ✓  the deposit is spent\n' "$V"
      REPLAY_OK=1 ;;
    *BadSigner*|*"$SEL_BADSIGNER"*)
      printf '  v=0x%s -> BadSigner()   (wrong recovery id for this signature, not a finding)\n' "$V" ;;
    *PerTxCap*|*"$SEL_PERTX"*|*WindowCap*|*"$SEL_WINDOW"*)
      fail "the replay reverted on a cap with v=0x$V, not Replay(). The replay guard was never
   reached, so this run says nothing about double-spend protection." ;;
    *)
      printf '%s\n' "$OUT" | head -5
      fail "the replay reverted for an unrecognised reason with v=0x$V" ;;
  esac
done
if [ "$REPLAY_OK" -ne 1 ]; then
  fail "neither v=0x1b nor v=0x1c reached the replay guard -- both were rejected as
   BadSigner. That means the scraped signature does not recover to $LIVE_SIGNER at all,
   which contradicts leg B having just succeeded with it. The signature used here and the
   one the mint script submitted have diverged; do not trust this run."
fi

# --- summary --------------------------------------------------------------------------------------
cat <<EOF

  ╭──────────────────────────────────────────────────────────────────────╮
  │  H.6 HAND-OFF PROVED IN BOTH DIRECTIONS                              │
  ╰──────────────────────────────────────────────────────────────────────╯

  contract     : $PROXY  (chain id $CHAIN_ID, keyEpoch $EPOCH_AFTER)
  one digest   : $DIGEST
  beldex txid  : $BELDEX_TXID

  retired  $RETIRED_SIGNER
      signature valid over the digest, rejected by the contract: BadSigner() for BOTH v
  promoted $LIVE_SIGNER
      minted $AMOUNT to $TO; balance and supply both moved by exactly that
  replay
      the successful signature, resubmitted: Replay()

  The two committees signed the same 192-byte preimage. The only difference between the
  accepted and the rejected attempt is which key signed — which is the whole claim.

EOF
