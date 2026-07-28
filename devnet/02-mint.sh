#!/usr/bin/env bash
# 02-mint.sh — submit the committee-signed mint to the anvil-deployed WrappedBDX,
# then prove the balance moved and the replay guard bites.
#
#     runlog ./devnet/02-mint.sh [<r||s hex>]
#
# With no argument it scrapes the signature out of the devnet sign logs and
# cross-checks that the committee signed OUR digest, not the demo preimage.

set -euo pipefail
export PATH="$HOME/.foundry/bin:$PATH"
cd "$(cd "$(dirname "$0")/.." && pwd)"

[ -f devnet/mint.env ] || { echo "no devnet/mint.env — run ./devnet/01-deploy.sh first"; exit 1; }
# shellcheck disable=SC1091
. devnet/mint.env

TESTDATA="${TESTDATA:-$HOME/Niyas/projects/beldex/utils/local-devnet/testdata}"
say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
lc()  { printf '%s' "$1" | tr 'A-Z' 'a-z'; }

# ── 1. the signature ─────────────────────────────────────────────────────────
SIG_RS="${1:-}"
if [ -z "$SIG_RS" ]; then
  say "scraping the Pevm signature from $TESTDATA/sign-*.log"
  ls "$TESTDATA"/sign-*.log >/dev/null 2>&1 || { echo "no sign-*.log there — run the sign step first"; exit 1; }
  SIGS="$(grep -h '^Pevm signature:' "$TESTDATA"/sign-*.log 2>/dev/null \
          | sed 's/^Pevm signature:[[:space:]]*//' | sort -u)"
  [ -n "$SIGS" ] || { echo "no 'Pevm signature:' lines found — did the sign run fail?"; exit 1; }
  COUNT="$(printf '%s\n' "$SIGS" | wc -l | tr -d ' ')"
  if [ "$COUNT" != "1" ]; then
    echo "signers disagree ($COUNT distinct signatures):"; printf '  %s\n' $SIGS; exit 1
  fi
  SIG_RS="$SIGS"
  echo "all signers agree on one signature ✓"

  # They must have signed the digest THIS contract will recompute.
  LOG_DIGEST="$(grep -h 'over digest' "$TESTDATA"/sign-*.log 2>/dev/null | sed 's/.*: *//' | sort -u | head -1)"
  if [ -n "$LOG_DIGEST" ] && [ "$(lc "0x${LOG_DIGEST#0x}")" != "$(lc "$DIGEST")" ]; then
    echo "!! the committee signed 0x${LOG_DIGEST#0x}"
    echo "   but the contract digest is $DIGEST"
    echo "   re-run: runlog ./sign-mint.sh $PREIMAGE"
    exit 1
  fi
  echo "signed digest matches the contract digest ✓"
fi
SIG_RS="0x${SIG_RS#0x}"
echo "r||s: $SIG_RS"
[ "${#SIG_RS}" -eq 130 ] || { echo "expected 64 bytes (130 chars incl. 0x), got ${#SIG_RS}"; exit 1; }

# ── 2. mint ──────────────────────────────────────────────────────────────────
say "mint"
PROXY="$PROXY" TO="$TO" AMOUNT="$AMOUNT" BELDEX_TXID="$BELDEX_TXID" SIG_RS="$SIG_RS" \
  forge script script/DevnetMint.s.sol:DevnetMint \
    --rpc-url "$RPC" --private-key "$DEPLOYER_KEY" --broadcast -vv

# ── 3. independent on-chain verification (via cast, not the script) ──────────
say "verify"
printf 'balanceOf(%s)\n  = %s\n' "$TO" "$(cast call "$PROXY" 'balanceOf(address)(uint256)' "$TO" --rpc-url "$RPC")"
printf 'totalSupply       = %s\n' "$(cast call "$PROXY" 'totalSupply()(uint256)' --rpc-url "$RPC")"
printf 'windowMinted      = %s\n' "$(cast call "$PROXY" 'windowMinted()(uint256)' --rpc-url "$RPC")"
printf 'processedDeposits = %s\n' "$(cast call "$PROXY" 'processedDeposits(bytes32)(bool)' "$BELDEX_TXID" --rpc-url "$RPC")"

say "Minted event"
cast logs --from-block 0 --address "$PROXY" \
  "$(cast sig-event 'Minted(address,uint256,bytes32)')" --rpc-url "$RPC" || true

# ── 4. replay guard ──────────────────────────────────────────────────────────
say "replay: resubmitting the same beldexTxid must revert"
REPLAY_OUT="$(cast call "$PROXY" 'mint(address,uint256,bytes32,bytes)' \
  "$TO" "$AMOUNT" "$BELDEX_TXID" "${SIG_RS}1c" --rpc-url "$RPC" 2>&1)" && REPLAY_RC=0 || REPLAY_RC=1
if [ "$REPLAY_RC" -eq 0 ]; then
  echo "!! replay did NOT revert"; exit 1
fi
printf 'reverted ✓\n%s\n' "$REPLAY_OUT" | head -5
# Foundry reports unknown custom errors as bare 4-byte selectors; decode the ones
# WrappedBDX can throw here so the outcome is unambiguous.
case "$REPLAY_OUT" in
  *Replay*|*b5a78004*)    echo "-> Replay()    ✓ the deposit is already spent" ;;
  *BadSigner*|*61330e93*) echo "-> BadSigner() ✗ signature rejected before the replay check was reached" ; exit 1 ;;
  *PerTxCap*|*e91f21b6*)  echo "-> PerTxCap()  ✗ reverted on the per-tx cap, not the replay guard" ; exit 1 ;;
  *WindowCap*|*7b8118d9*) echo "-> WindowCap() ✗ reverted on the window cap, not the replay guard" ; exit 1 ;;
  *)                      echo "-> reverted for an unrecognised reason (see above)" ;;
esac

echo
echo "done — anvil still running (pid $(cat devnet/anvil.pid 2>/dev/null || echo '?'))"
echo "stop it with: kill \$(cat devnet/anvil.pid)"
