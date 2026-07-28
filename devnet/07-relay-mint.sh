#!/usr/bin/env bash
# 07-relay-mint.sh — prove the keyless relayer path end to end (Phase I / E.2).
#
#     OUT=devnet/relay.env runlog ./devnet/05-mint-prep.sh 0x<fresh-txid>
#     cd <beldex>/utils/local-devnet && runlog ./sign-pevm.sh mint <preimage>
#     cd <bridge-contract>            && runlog ./devnet/07-relay-mint.sh
#
# WHAT THIS IS FOR. 06-handoff-proof.sh landed its mint through forge script — i.e. WE hand
# built the transaction. That proves the contract accepts a committee signature; it says
# nothing about the relayer, because the relayer was not in the loop. The bridge's liveness
# story ("keyless, permissionless courier; if every relayer vanishes any user broadcasts the
# same call") is a claim about a specific 700-line Rust crate that hand-rolls its own ABI
# encoder. This script is that claim, made falsifiable.
#
# FOUR WAYS A GREEN RUN HERE COULD BE MEANINGLESS, and the guard for each:
#
#   1. The relayer's encoder is only ever checked against itself. `cargo test` in
#      bridge/relayer asserts the calldata layout against hand-written expectations written
#      by the same author under the same assumptions — a shared misreading of the ABI spec
#      passes. So every byte is re-derived here with foundry's INDEPENDENT encoder and
#      compared for exact equality (§4, §6).
#
#   2. "The mint succeeded" while the broadcaster is privileged. If the account paying gas
#      is the deployer, the admin, or an allowlisted signer, the run demonstrates nothing
#      about permissionlessness. §7 asserts the broadcaster is none of those BEFORE it
#      spends anything, and re-reads the receipt's `from` afterwards.
#
#   3. A tamper that does not actually tamper. If a mutated payload happens to produce the
#      same calldata, "it reverted" is about nothing. Every tamper case asserts its calldata
#      DIFFERS from the honest one before it reads the revert (§6).
#
#   4. The right revert for the wrong reason. A tampered payload that reverts Replay(), a
#      cap, or ECDSAInvalidSignature has not exercised the signer check. Each case demands
#      BadSigner() specifically. (This is why the sig tamper flips the LAST byte of s and
#      not a byte of r or v: perturbing r has a ~50% chance of yielding a point with no
#      valid y, which OZ reports as a malformed signature, and perturbing v yields an
#      out-of-range recovery id. A small change to s always recovers cleanly to a DIFFERENT
#      address, which is exactly the rejection this is trying to provoke.)
#
# NOTHING IS BROADCAST UNTIL §7. The tamper matrix and the honest dry run are static
# `cast call`s, so a failure anywhere above leaves the deposit unspent and the whole run
# repeatable without a fresh txid.
#
# Env:
#   RELAY_ENV    prepared env to read            (default devnet/relay.env)
#   RELAYER_DIR  the relayer crate               (default ~/Niyas/projects/beldex/bridge/relayer)
#   TESTDATA     where the signer logs live
#   RELAYER_KEY  the gas-paying EOA              (default anvil account #9)
#   SKIP_CARGO_TEST=1  skip the crate's own unit tests (they are the weakest check here)

set -euo pipefail
export PATH="$HOME/.foundry/bin:$PATH"
cd "$(cd "$(dirname "$0")/.." && pwd)"

RELAY_ENV="${RELAY_ENV:-devnet/relay.env}"
[ -f "$RELAY_ENV" ] || {
  echo "!! no $RELAY_ENV — prepare a fresh deposit first:" >&2
  echo "   OUT=devnet/relay.env ./devnet/05-mint-prep.sh 0x<fresh-32-byte-txid>" >&2
  exit 1; }
# shellcheck disable=SC1091
. "$RELAY_ENV"

RELAYER_DIR="${RELAYER_DIR:-$HOME/Niyas/projects/beldex/bridge/relayer}"
TESTDATA="${TESTDATA:-$HOME/Niyas/projects/beldex/utils/local-devnet/testdata}"
# anvil account #9 — deliberately NOT #0 (the deployer/recipient) and not on any signer list.
RELAYER_KEY="${RELAYER_KEY:-0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6}"

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
lc()   { printf '%s' "$1" | tr 'A-Z' 'a-z'; }
num()  { printf '%s' "$1" | sed -n 's/^\([0-9][0-9]*\).*/\1/p'; }
fail() { printf '\n\033[1;31m!! %s\033[0m\n' "$*" >&2; exit 1; }

SEL_BADSIGNER=61330e93
SEL_REPLAY=b5a78004
SEL_PERTX=e91f21b6
SEL_WINDOW=7b8118d9

WORK="devnet/.relay"
mkdir -p "$WORK"

# =================================================================================== §1 build
say "1 — the relayer crate"

command -v cargo >/dev/null 2>&1 || fail "cargo not on PATH — the relayer is a Rust crate"
[ -d "$RELAYER_DIR" ] || fail "no relayer crate at $RELAYER_DIR (override with RELAYER_DIR=)"

if [ "${SKIP_CARGO_TEST:-}" != "1" ]; then
  # These tests are a drift guard, not a proof: they check the encoder against expectations
  # written alongside it. Run them anyway — a red unit test means the differential below
  # would be comparing against something already known-broken.
  ( cd "$RELAYER_DIR" && cargo test --quiet ) >"$WORK/cargo-test.log" 2>&1 \
    || { tail -30 "$WORK/cargo-test.log" >&2; fail "cargo test failed in $RELAYER_DIR (full log: $WORK/cargo-test.log)"; }
  echo "  cargo test ✓  ($(grep -c 'test result: ok' "$WORK/cargo-test.log" || true) suites green)"
fi

( cd "$RELAYER_DIR" && cargo build --quiet ) >>"$WORK/cargo-test.log" 2>&1 \
  || fail "cargo build failed in $RELAYER_DIR"
RELAYER="$RELAYER_DIR/target/debug/beldex-bridge-relayer"
[ -x "$RELAYER" ] || fail "built, but no binary at $RELAYER"
echo "  binary  : $RELAYER"

# ============================================================================== §2 signature
say "2 — the committee signature"

ls "$TESTDATA/mint-sign-"*.log >/dev/null 2>&1 \
  || fail "no mint-sign-*.log in $TESTDATA — the promoted committee has not signed this preimage.
   cd <beldex>/utils/local-devnet && runlog ./sign-pevm.sh mint $PREIMAGE"

pick() {  # field-regex label -> the single distinct value, or abort
  local pat="$1" label="$2" vals n
  vals="$(grep -h "$pat" "$TESTDATA/mint-sign-"*.log 2>/dev/null \
          | sed 's/.*: *//' | tr -d ' \r' | tr 'A-Z' 'a-z' | sed 's/^0x//' | sort -u || true)"
  n="$(printf '%s\n' "$vals" | grep -c . || true)"
  [ -n "$vals" ] || fail "no '$label' line in mint-sign-*.log — that signing run failed"
  [ "$n" -eq 1 ] || fail "the signers report $n DIFFERENT values for '$label':
$(printf '     %s\n' $vals)
   The nodes did not agree. Do not read anything into this run."
  printf '%s' "$vals"
}

RS_RAW="$(grep -h '^Pevm signature:' "$TESTDATA/mint-sign-"*.log | sed 's/^Pevm signature:[[:space:]]*//' \
          | tr -d ' \r' | tr 'A-Z' 'a-z' | sort -u)"
[ "$(printf '%s\n' "$RS_RAW" | grep -c . || true)" -eq 1 ] || fail "the signers produced more than one signature"
LOGDIGEST="$(pick 'over digest' 'over digest')"
LOGSIGNER="$(pick 'wBDX signer' 'wBDX signer')"
LOGV="$(grep -h 'ecrecover' "$TESTDATA/mint-sign-"*.log | sed 's/.*v=//' | tr -d ') \r' | sort -u)"
[ "$(printf '%s\n' "$LOGV" | grep -c . || true)" -eq 1 ] || fail "the signers report more than one recovery id"

[ "0x$LOGDIGEST" = "$(lc "$DIGEST")" ] || fail "the committee signed 0x$LOGDIGEST but $RELAY_ENV prepared $DIGEST
   The signing run used a different preimage. Re-sign the one in $RELAY_ENV."
[ "0x$LOGSIGNER" = "$(lc "$LIVE_SIGNER")" ] || fail "mint-sign-*.log recovers to 0x$LOGSIGNER, expected $LIVE_SIGNER
   Wrong share tree: check SHARE_SUBDIR on that run."

# EIP-2. The signer claims to low-S normalise; if it did not, flipping s here means the
# recovery id it logged is no longer the right one and must flip with it.
lows() {
  python3 - "$1" <<'PY'
import sys
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
h = sys.argv[1].lower().replace("0x", "")
assert len(h) == 128, "expected 64-byte r||s, got %d hex chars" % len(h)
r, s = h[:64], int(h[64:], 16)
print(r + ("%064x" % (N - s) if s > N // 2 else "%064x" % s))
PY
}
RS="$(lows "$RS_RAW")"
if [ "$RS" != "$RS_RAW" ]; then
  if [ "$LOGV" = "27" ]; then V_DEC=28; else V_DEC=27; fi
  V_PROV="v=$V_DEC, flipped from the logged $LOGV by the low-S normalisation"
  echo "  note: s was above N/2 and has been normalised; recovery id flipped $LOGV -> $V_DEC"
  echo "        (r, s, v) and (r, N-s, v^1) recover the same address; flipping one without"
  echo "        the other is the single easiest way to turn a good signature into BadSigner."
else
  V_DEC="$LOGV"
  V_PROV="v=$V_DEC, as the signer itself derived it"
fi
V_HEX="$(printf '%x' "$V_DEC")"
SIG65="0x${RS}${V_HEX}"

echo "  signer  : $LIVE_SIGNER"
echo "  digest  : $DIGEST  (agrees with $RELAY_ENV ✓)"
echo "  r||s||v : ${RS}${V_HEX}   ($V_PROV)"

# ================================================================================ §3 digest
say "3 — digest differential: relayer vs cast"

DIGOUT="$("$RELAYER" mint-digest \
  --chain-id "$CHAIN_ID" --contract "$PROXY" --to "$TO" --amount "$AMOUNT" --txid "$BELDEX_TXID")" \
  || fail "relayer mint-digest failed"
R_PRE="$(printf '%s' "$DIGOUT" | sed -n 's/^preimage: *\([0-9a-fA-F]*\).*/\1/p' | tr 'A-Z' 'a-z')"
R_DIG="$(printf '%s' "$DIGOUT" | sed -n 's/^digest: *\([0-9a-fA-F]*\).*/\1/p' | tr 'A-Z' 'a-z')"
[ -n "$R_PRE" ] && [ -n "$R_DIG" ] || fail "could not parse mint-digest output:
$DIGOUT"

# $PREIMAGE and $DIGEST came from `cast abi-encode` + `cast keccak` in 05-mint-prep.sh.
# The relayer computes both from its own hand-rolled word packing and its own keccak crate.
[ "0x$R_PRE" = "$(lc "$PREIMAGE")" ] || fail "PREIMAGE MISMATCH — the relayer and cast disagree on the 192-byte preimage
   relayer: 0x$R_PRE
   cast   : $(lc "$PREIMAGE")
   One of the six words is packed differently. The committee would be signing a message
   the contract never recomputes."
[ "0x$R_DIG" = "$(lc "$DIGEST")" ] || fail "DIGEST MISMATCH — same preimage, different keccak:
   relayer: 0x$R_DIG
   cast   : $(lc "$DIGEST")"
echo "  preimage 192 bytes, byte-identical to cast abi-encode ✓"
echo "  digest   byte-identical to cast keccak ✓"
echo "  (that is four independent implementations of this preimage now agreeing:"
echo "   the relayer, the signer's watch.rs, cast, and the contract itself)"

# =============================================================================== §4 prepare
say "4 — prepare: payload -> {chain_id, to, data}"

PROXY_LC="$(lc "$PROXY")"
mkpayload() {  # to amount txid sig
  cat <<EOF
{ "kind": "mint",
  "contract": "$PROXY_LC",
  "chain_id": $CHAIN_ID,
  "to": "$1",
  "amount": "$2",
  "beldex_txid": "$3",
  "sig": "$4" }
EOF
}
mkpayload "$(lc "$TO")" "$AMOUNT" "$(lc "$BELDEX_TXID")" "$SIG65" > "$WORK/payload.json"

PREP="$("$RELAYER" prepare "$WORK/payload.json")" || fail "relayer prepare failed on $WORK/payload.json"
P_CHAIN="$(printf '%s' "$PREP" | sed -n 's/^chain_id: *//p' | tr -d ' \r')"
P_TO="$(printf '%s' "$PREP"    | sed -n 's/^to: *//p'       | tr -d ' \r' | tr 'A-Z' 'a-z')"
DATA="$(printf '%s' "$PREP"    | sed -n 's/^data: *//p'     | tr -d ' \r' | tr 'A-Z' 'a-z')"
[ -n "$DATA" ] || fail "prepare printed no data line:
$PREP"
[ "$P_CHAIN" = "$CHAIN_ID" ] || fail "prepare routed to chain $P_CHAIN, expected $CHAIN_ID"
[ "$P_TO" = "$PROXY_LC" ]    || fail "prepare routed to $P_TO, expected the proxy $PROXY_LC"
echo "  chain_id $P_CHAIN, to $P_TO ✓"
echo "  data     ${#DATA} hex chars"
echo "  payload  $WORK/payload.json"

# ============================================================================= §5 calldata
say "5 — calldata differential: relayer vs cast"

CAST_DATA="$(lc "$(cast calldata 'mint(address,uint256,bytes32,bytes)' \
                    "$TO" "$AMOUNT" "$BELDEX_TXID" "$SIG65")")"
if [ "$DATA" != "$CAST_DATA" ]; then
  printf '%s\n' "$DATA"      | fold -w 64 | head -8 >&2
  echo "   --- vs ---" >&2
  printf '%s\n' "$CAST_DATA" | fold -w 64 | head -8 >&2
  fail "CALLDATA MISMATCH — the relayer's hand-rolled encoder disagrees with foundry's.
   This is the single most likely place for a real bug: the dynamic 'bytes sig' head offset
   and the right-padding of a 65-byte value to 96. Do not broadcast this."
fi
echo "  ${#DATA} hex chars, byte-identical to cast calldata ✓"
echo "  selector 0x${DATA:2:8} = mint(address,uint256,bytes32,bytes) ✓"

# ============================================================================== §6 tampers
say "6 — a relayer can forge nothing"
echo "  (each mutated payload must reach the contract and be rejected at the SIGNER check —"
echo "   not at the replay guard, not at a cap, not as a malformed signature)"

flip_last() { python3 -c '
import sys
h = sys.argv[1].lower().replace("0x","")
b = bytearray.fromhex(h); b[-1] ^= 0x01
print("0x" + b.hex())' "$1"; }

flip_s_tail() { python3 -c '
import sys
h = sys.argv[1].lower().replace("0x","")
b = bytearray.fromhex(h)
assert len(b) == 65, len(b)
b[63] ^= 0x01           # last byte of s: always recovers cleanly to a DIFFERENT address
print("0x" + b.hex())' "$1"; }

tamper() {  # label to amount txid sig
  local label="$1" data out rc
  mkpayload "$2" "$3" "$4" "$5" > "$WORK/tampered.json"
  data="$("$RELAYER" prepare "$WORK/tampered.json" | sed -n 's/^data: *//p' | tr -d ' \r' | tr 'A-Z' 'a-z')" \
    || fail "prepare failed on the $label tamper"
  [ -n "$data" ] || fail "prepare produced no calldata for the $label tamper"
  [ "$data" != "$DATA" ] || fail "the $label tamper produced calldata IDENTICAL to the honest payload.
   The mutation did not reach the encoding, so this case tests nothing."
  out="$(cast call "$PROXY" "$data" --rpc-url "$RPC" 2>&1)" && rc=0 || rc=1
  [ "$rc" -eq 1 ] || fail "the $label tamper was ACCEPTED by the contract.
   A relayer can alter this field and still mint. This is a break, not a test failure."
  case "$out" in
    *BadSigner*|*"$SEL_BADSIGNER"*)
      printf '  %-22s -> BadSigner()  ✓\n' "$label" ;;
    *Replay*|*"$SEL_REPLAY"*)
      fail "the $label tamper reverted Replay(), not BadSigner() — the deposit is already
   spent, so the signer check was never the thing that rejected it. Prepare a fresh txid." ;;
    *PerTxCap*|*"$SEL_PERTX"*|*WindowCap*|*"$SEL_WINDOW"*)
      fail "the $label tamper reverted on a cap, not BadSigner(). Rejected for the wrong
   reason: this run says nothing about whether the signature was checked." ;;
    *ECDSAInvalidSignature*)
      fail "the $label tamper was rejected as a MALFORMED signature, not as a wrong signer.
   The contract never got as far as comparing an address. Adjust the mutation." ;;
    *)
      printf '%s\n' "$out" | head -5 >&2
      fail "the $label tamper reverted for an unrecognised reason" ;;
  esac
}

tamper "recipient (to)"   "$(flip_last "$TO")" "$AMOUNT" "$(lc "$BELDEX_TXID")" "$SIG65"
tamper "amount"           "$(lc "$TO")" "$(( AMOUNT + 1 ))" "$(lc "$BELDEX_TXID")" "$SIG65"
tamper "beldex txid"      "$(lc "$TO")" "$AMOUNT" "$(flip_last "$BELDEX_TXID")" "$SIG65"
tamper "signature"        "$(lc "$TO")" "$AMOUNT" "$(lc "$BELDEX_TXID")" "$(flip_s_tail "$SIG65")"

# The routing fields are not signed and not part of the calldata — the relayer can only
# misdeliver, never forge. Assert that misdelivery is at least visible in `prepare`'s output.
ALT="$(flip_last "$PROXY")"
mkpayload_alt="$(mkpayload "$(lc "$TO")" "$AMOUNT" "$(lc "$BELDEX_TXID")" "$SIG65" \
                 | sed "s|\"contract\": \"$PROXY_LC\"|\"contract\": \"$(lc "$ALT")\"|")"
printf '%s\n' "$mkpayload_alt" > "$WORK/misrouted.json"
MIS_TO="$("$RELAYER" prepare "$WORK/misrouted.json" | sed -n 's/^to: *//p' | tr -d ' \r' | tr 'A-Z' 'a-z')"
[ "$MIS_TO" = "$(lc "$ALT")" ] || fail "prepare ignored the payload's contract field (got $MIS_TO)"
printf '  %-22s -> prepare reports the altered destination, not the real proxy ✓\n' "misrouted contract"
echo "  (a relayer that misroutes sends the call somewhere that cannot mint — visible, not forgeable)"

# =========================================================================== §7 the real run
say "7 — the broadcaster holds no bridge key"

RELAYER_ADDR="$(lc "$(cast wallet address --private-key "$RELAYER_KEY")")"
DEPLOYER_ADDR="$(lc "$(cast wallet address --private-key "$DEPLOYER_KEY")")"
CUR_SIGNER="$(lc "$(cast call "$PROXY" 'currentSigner()(address)' --rpc-url "$RPC")")"
ALLOWED="$(lc "$(cast call "$PROXY" 'isSigner(address)(bool)' "$RELAYER_ADDR" --rpc-url "$RPC")")"

[ "$RELAYER_ADDR" != "$CUR_SIGNER" ]    || fail "the broadcaster IS currentSigner — nothing permissionless is being shown"
[ "$RELAYER_ADDR" != "$DEPLOYER_ADDR" ] || fail "the broadcaster is the deployer — pick a different RELAYER_KEY"
[ "$RELAYER_ADDR" != "$(lc "$TO")" ]    || fail "the broadcaster is the mint recipient — pick a different RELAYER_KEY"
[ "$ALLOWED" = "false" ]                || fail "isSigner[$RELAYER_ADDR] = $ALLOWED — the broadcaster is on the signer allowlist"

echo "  broadcaster   : $RELAYER_ADDR"
echo "  currentSigner : $CUR_SIGNER   (different ✓)"
echo "  deployer      : $DEPLOYER_ADDR   (different ✓)"
echo "  isSigner[broadcaster] = false ✓   — it can pay gas and nothing else"

BAL_BEFORE="$(num "$(cast call "$PROXY" 'balanceOf(address)(uint256)' "$TO" --rpc-url "$RPC")")"
SUP_BEFORE="$(num "$(cast call "$PROXY" 'totalSupply()(uint256)' --rpc-url "$RPC")")"

# Dry run first: a static call that must SUCCEED. If the honest payload cannot mint, that is
# a bug in the relayer path or in the signer's recovery id, and it should surface before any
# gas is spent and before the deposit is consumed.
DRY="$(cast call "$PROXY" "$DATA" --rpc-url "$RPC" 2>&1)" || {
  printf '%s\n' "$DRY" | head -5 >&2
  case "$DRY" in
    *BadSigner*|*"$SEL_BADSIGNER"*)
      fail "the honest relayer calldata reverts BadSigner with v=$V_DEC — the recovery id the
   SIGNER logged is not the one the contract recovers with. That is a signer conformance
   bug (it claims to pre-verify through the contract's exact recovery rule), not a
   relayer bug. Do not paper over it by trying the other v." ;;
    *) fail "the honest relayer calldata reverts before broadcast" ;;
  esac
}
echo "  dry run (static) succeeds ✓ — safe to spend gas"

say "8 — relayer-driven mint"
RCPT="$(cast send "$PROXY" "$DATA" --rpc-url "$RPC" --private-key "$RELAYER_KEY" --json)" \
  || fail "the broadcast failed"
printf '%s\n' "$RCPT" > "$WORK/receipt.json"
eval "$(python3 - "$WORK/receipt.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
print("TX_HASH=%s"   % r.get("transactionHash", ""))
print("TX_FROM=%s"   % str(r.get("from", "")).lower())
print("TX_STATUS=%s" % r.get("status", ""))
PY
)"
[ "$TX_STATUS" = "0x1" ] || fail "the mint transaction reverted on chain (status $TX_STATUS)"
[ "$TX_FROM" = "$RELAYER_ADDR" ] || fail "the receipt says from=$TX_FROM, not the keyless broadcaster $RELAYER_ADDR"
echo "  tx    : $TX_HASH"
echo "  from  : $TX_FROM   (the keyless broadcaster ✓)"

BAL_AFTER="$(num "$(cast call "$PROXY" 'balanceOf(address)(uint256)' "$TO" --rpc-url "$RPC")")"
SUP_AFTER="$(num "$(cast call "$PROXY" 'totalSupply()(uint256)' --rpc-url "$RPC")")"
SPENT="$(lc "$(cast call "$PROXY" 'processedDeposits(bytes32)(bool)' "$BELDEX_TXID" --rpc-url "$RPC")")"
SIGNER_AFTER="$(lc "$(cast call "$PROXY" 'currentSigner()(address)' --rpc-url "$RPC")")"

[ "$(( BAL_AFTER - BAL_BEFORE ))" -eq "$AMOUNT" ] \
  || fail "balance moved by $(( BAL_AFTER - BAL_BEFORE )), expected $AMOUNT"
[ "$(( SUP_AFTER - SUP_BEFORE ))" -eq "$AMOUNT" ] \
  || fail "supply moved by $(( SUP_AFTER - SUP_BEFORE )), expected $AMOUNT"
[ "$SPENT" = "true" ]                 || fail "the deposit was not marked processed"
[ "$SIGNER_AFTER" = "$CUR_SIGNER" ]   || fail "currentSigner moved during a mint — a relayer must never be able to do that"
echo "  balance $BAL_BEFORE -> $BAL_AFTER   (delta $AMOUNT ✓)"
echo "  supply  $SUP_BEFORE -> $SUP_AFTER"
echo "  processedDeposits[$BELDEX_TXID] = true ✓"
echo "  currentSigner unmoved ✓"

say "9 — the same relayer calldata, replayed"
OUT="$(cast call "$PROXY" "$DATA" --rpc-url "$RPC" 2>&1)" && RC=0 || RC=1
[ "$RC" -eq 1 ] || fail "the replay did NOT revert — a relayer could mint this deposit twice"
case "$OUT" in
  *Replay*|*"$SEL_REPLAY"*)       echo "  -> Replay() ✓  a relayer cannot resubmit a spent deposit" ;;
  *BadSigner*|*"$SEL_BADSIGNER"*) fail "reverted BadSigner, not Replay — unreachable if §8 just succeeded with this exact calldata" ;;
  *) printf '%s\n' "$OUT" | head -5 >&2; fail "the replay reverted for an unrecognised reason" ;;
esac

cat <<EOF

  ╭──────────────────────────────────────────────────────────────────────╮
  │  RELAYER PATH PROVED (Phase I / E.2)                                 │
  ╰──────────────────────────────────────────────────────────────────────╯

  contract     : $PROXY  (chain id $CHAIN_ID)
  digest       : $DIGEST
  beldex txid  : $BELDEX_TXID
  broadcaster  : $RELAYER_ADDR   (not the signer, not the deployer, not allowlisted)
  tx           : $TX_HASH

  encoding     the relayer's hand-rolled preimage, digest and calldata are byte-identical
               to foundry's independent encoder
  liveness     the mint landed from a payload file + \`prepare\` + a gas key, with no bridge
               key and no running relayer service anywhere in the path
  trust        every mutation a relayer could make to the payload — recipient, amount,
               txid, signature — was rejected at the signer check, and the one field it
               genuinely controls (destination) only lets it misdeliver, never forge
  replay       the same calldata resubmitted: Replay()

  artifacts    $WORK/payload.json, $WORK/receipt.json

EOF
