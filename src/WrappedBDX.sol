// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import { ERC20Upgradeable } from "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import { PausableUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import { Initializable } from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title WrappedBDX (wBDX) — the EVM side of the Beldex Sovereign Bridge (Phase H).
///
/// A signer-gated, domain-separated, replay-guarded, fixed-window-capped ERC-20 whose
/// **mint authority is the `Pevm` masternode-committee key** (secp256k1 / CGGMP21),
/// verified by `ecrecover`. Deliberately **not** `Ownable`: the party that authorizes
/// mints (the committee **signer**) is separate from the party that manages the signer
/// set and pause (the timelocked **admin**). The admin can stop the bleeding and rotate
/// signers, but can never mint — it cannot steal.
///
/// ## Byte-exact agreement with the off-chain signer (load-bearing)
/// The mint digest is `keccak256(abi.encode(MINT_TAG, block.chainid, address(this), to,
/// amount, beldexTxid, outputIndex))` — seven ABI words. Every field, order, and the tag
/// value match the Rust signer's `watch.rs::MintEvent::mint_preimage` exactly — otherwise
/// `ecrecover` fails. `outputIndex` is part of the signed bytes, not just the replay key:
/// without it one signature would authorize any output of the same transaction.
///
/// **`MINT_TAG = keccak256("BELDEX_BRIDGE_MINT_V1")`** — the signer hardcodes the same
/// precomputed hash (`watch.rs::MINT_TAG`) and guards it with a keccak drift test. The
/// keccak form (vs. a raw right-padded string literal) is the conventional domain-
/// separation approach and is not limited to 32-character tags.
///
/// ## Redeem
/// `redeemToNative` burns wBDX and emits `RedeemToNative(address,uint256,bytes)` — the
/// exact event the E.2 EVM watcher (`evm_watcher.rs`) decodes: `from` indexed, and
/// `abi.encode(amount, beldexAddress)` in the data. The *release* cap that mirrors the
/// mint cap lives on the L1 gateway in consensus (Phase A.3), since releases move locked
/// BDX, not wBDX; the contract bounds a burn only by `perTxMax` for UX.
///
/// ## Decimals
/// 9 decimals to match Beldex `COIN = 10^9`, so 1 wBDX unit == 1 atomic BDX — no
/// 10^9<->10^18 rescaling anywhere in the mint/redeem path.
contract WrappedBDX is Initializable, ERC20Upgradeable, PausableUpgradeable, UUPSUpgradeable {
    // --- Domain-separation tags (keccak256 of the domain string) ---------------------
    /// @dev Must equal the signer's `watch.rs::MINT_TAG` (= keccak256 of the string).
    bytes32 public constant MINT_TAG = keccak256("BELDEX_BRIDGE_MINT_V1");
    /// @dev Rotation hand-off tag; the signer's future rotate-signing must mirror this
    ///      (same keccak convention as MINT_TAG).
    bytes32 public constant ROTATE_TAG = keccak256("BELDEX_BRIDGE_ROTATE_V1");
    /// @dev Activation liveness tag; the **incoming** committee signs this to prove it can
    ///      produce a signature under the new key before the old key is retired (H.6.2b).
    bytes32 public constant ACTIVATE_TAG = keccak256("BELDEX_BRIDGE_ACTIVATE_V1");

    uint8 private constant DECIMALS = 9;

    // --- Committee mint authority ----------------------------------------------------
    /// @notice The active `Pevm` committee key that authorizes mints and signs rotations.
    address public currentSigner;
    /// @notice Monotonic key generation; a rotation may only move it forward (anti-rollback).
    uint64 public keyEpoch;
    /// @notice Admin-managed break-glass signer set (Phase K recovery only, never normal churn).
    mapping(address => bool) public isSigner;

    // --- Rotation challenge window (H.6) ---------------------------------------------
    address public pendingSigner;
    uint64 public pendingKeyEpoch;
    uint256 public pendingActivateAt;
    bool public rotationVetoed;
    /// @notice Challenge-window duration between a valid rotate proposal and activation.
    uint256 public rotateTimelock;

    // --- Replay guard + fixed-calendar-window mint cap (H.2, §7-bis β=1) -------------
    mapping(bytes32 => bool) public processedDeposits;
    /// @notice Calendar window length in seconds (fixed; window resets on the boundary).
    uint256 public epochSeconds;
    uint256 public windowId;
    uint256 public windowMinted;
    uint256 public windowMintCap;
    uint256 public perTxMax;

    // --- Bond-before-caps guard (§7-bis) ---------------------------------------------
    /// @notice Governance-set ceiling reflecting the on-chain `BRIDGE_BOND` backing.
    ///         `setCaps` refuses a `windowMintCap` above this, so caps can never be
    ///         raised before the bond is (the whitepaper's hard ordering rule).
    uint256 public bondBackingCapLimit;

    // --- Admin (a TimelockController + multisig in production) ------------------------
    address public admin;

    /// @notice Rotation proposals governance has rejected, keyed by
    ///         `keccak256(abi.encode(newSigner, newKeyEpoch))`.
    ///
    ///         WHY A MAP AND NOT A FLAG. `rotationVetoed` alone was not binding: the
    ///         rotate digest carries no nonce, so the outgoing committee's signature
    ///         stays valid indefinitely, and `rotateSigner` is a permissionless relay
    ///         that cleared the flag on every fresh proposal. Anyone who saw the
    ///         original transaction could therefore resubmit it and wash out a veto
    ///         governance had deliberately raised. Recording the rejected *proposal*
    ///         makes the veto survive replay: the same `(signer, epoch)` can never be
    ///         staged again, whoever relays it and however long they wait.
    ///
    ///         The legitimate path after a veto is a different signer or a higher
    ///         epoch. `clearVetoedProposal` exists for a veto raised in error.
    mapping(bytes32 => bool) public vetoedProposals;

    // --- Events ----------------------------------------------------------------------
    event Minted(address indexed to, uint256 amount, bytes32 indexed beldexTxid, uint32 outputIndex);
    event RedeemToNative(address indexed from, uint256 amount, bytes beldexAddress);
    event RotationProposed(address indexed newSigner, uint64 newKeyEpoch, uint256 activateAt);
    event Rotated(address indexed newSigner, uint64 newKeyEpoch);
    event RotationVetoed(address indexed pendingSigner, uint64 pendingKeyEpoch);
    event VetoedProposalCleared(address indexed signer, uint64 keyEpoch);
    event BreakGlassSignerSet(address indexed newSigner, uint64 newKeyEpoch);
    event SignerAdded(address indexed signer);
    event SignerRemoved(address indexed signer);
    event CapsSet(uint256 windowMintCap, uint256 perTxMax);
    event BondBackingCapLimitSet(uint256 bondBackingCapLimit);
    event AdminTransferred(address indexed previousAdmin, address indexed newAdmin);
    event Paused_(address indexed by);
    event Unpaused_(address indexed by);

    error NotAdmin();
    error ZeroAddress();
    error BadSigner();
    error Replay();
    error PerTxCap();
    error WindowCap();
    error StaleEpoch();
    error NoPendingRotation();
    error RotationNotReady();
    error RotationIsVetoed();
    error IncomingNotReady();
    error CapAboveBondBacking();
    error BadRedeemAddress();
    error ZeroAmount();

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin();
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @param admin_               Timelocked governance admin (signer-set / pause / upgrade).
    /// @param initialSigner        Genesis `Pevm` committee mint key.
    /// @param windowMintCap_       Per-window mint cap (must be <= bondBackingCapLimit_).
    /// @param perTxMax_            Per-transaction max (mint and redeem).
    /// @param bondBackingCapLimit_ Ceiling reflecting the L1 bond backing (bond-before-caps).
    /// @param epochSeconds_        Fixed calendar-window length (e.g. 86400 for daily).
    /// @param rotateTimelock_      H.6 rotation challenge-window duration.
    function initialize(
        address admin_,
        address initialSigner,
        uint256 windowMintCap_,
        uint256 perTxMax_,
        uint256 bondBackingCapLimit_,
        uint256 epochSeconds_,
        uint256 rotateTimelock_
    ) external initializer {
        if (admin_ == address(0) || initialSigner == address(0)) revert ZeroAddress();
        require(epochSeconds_ > 0, "epochSeconds=0");
        require(windowMintCap_ <= bondBackingCapLimit_, "cap>bond");

        __ERC20_init("Wrapped BDX", "wBDX");
        __Pausable_init();
        // NOTE: OZ upgradeable v5 removed __UUPSUpgradeable_init() -- UUPSUpgradeable
        // is stateless there; inheriting + overriding _authorizeUpgrade is sufficient.

        admin = admin_;
        currentSigner = initialSigner;
        keyEpoch = 1;
        windowMintCap = windowMintCap_;
        perTxMax = perTxMax_;
        bondBackingCapLimit = bondBackingCapLimit_;
        epochSeconds = epochSeconds_;
        rotateTimelock = rotateTimelock_;
        windowId = block.timestamp / epochSeconds_;

        emit AdminTransferred(address(0), admin_);
        emit Rotated(initialSigner, 1);
        emit CapsSet(windowMintCap_, perTxMax_);
        emit BondBackingCapLimitSet(bondBackingCapLimit_);
    }

    function decimals() public pure override returns (uint8) {
        return DECIMALS;
    }

    // =================================================================================
    // Mint (H.2) — committee-signed, domain-separated, replay-guarded, window-capped
    // =================================================================================
    /// @notice Mint `amount` wBDX to `to` against a Beldex deposit, authorized by a
    ///         committee `Pevm` signature over the domain-separated digest.
    ///
    ///         DEPOSIT IDENTITY (H-2). A Beldex transaction may pay the gateway more than
    ///         once — consensus permits `GATEWAY_TX_MAX_OUTPUTS` (15) gateway outputs per
    ///         tx and documents batch deposits as legitimate — and each output carries its
    ///         own memo, hence its own destination. Keying the replay guard on the bare
    ///         `beldexTxid` therefore allowed exactly ONE of them to be minted and stranded
    ///         the rest permanently. The unit of value is the OUTPUT, so the guard is keyed
    ///         on `(beldexTxid, outputIndex)` and `outputIndex` is bound into the digest.
    ///
    ///         `outputIndex` is deliberately NOT range-checked against 15: that is an L1
    ///         consensus constant which can move in a hard fork, and this contract cannot be
    ///         upgraded in lockstep across every chain. The committee signature is the
    ///         authority, and bounding the index would prevent nothing a compromised signer
    ///         could not already do.
    /// @param outputIndex Index of the gateway output within `beldexTxid` (0 for a single-
    ///        output deposit).
    /// @param sig 65-byte secp256k1 signature (r‖s‖v) from the committee key.
    function mint(
        address to,
        uint256 amount,
        bytes32 beldexTxid,
        uint32 outputIndex,
        bytes calldata sig
    )
        external
        whenNotPaused
    {
        bytes32 digest = keccak256(
            abi.encode(MINT_TAG, block.chainid, address(this), to, amount, beldexTxid, outputIndex)
        );
        address recovered = ECDSA.recover(digest, sig);
        if (recovered != currentSigner && !isSigner[recovered]) revert BadSigner();

        // LEGACY KEY (upgrade safety). Deposits minted before this upgrade were recorded
        // under the raw txid. Checking only the new composite key would leave every one of
        // them unmarked and therefore mintable a second time. This check keeps them closed.
        // It is conservative: a pre-upgrade tx stays fully blocked, including outputs that
        // were already stranded. Removable once no pre-upgrade deposit can still arrive.
        if (processedDeposits[beldexTxid]) revert Replay();

        bytes32 depositId = keccak256(abi.encode(beldexTxid, outputIndex));
        if (processedDeposits[depositId]) revert Replay();

        // FIXED calendar window (β=1): reset on the boundary, never a rolling window,
        // so no back-to-back 2× burst across a window edge (§7-bis).
        uint256 w = block.timestamp / epochSeconds;
        if (w != windowId) {
            windowId = w;
            windowMinted = 0;
        }
        if (amount > perTxMax) revert PerTxCap();
        if (windowMinted + amount > windowMintCap) revert WindowCap();

        processedDeposits[depositId] = true;
        windowMinted += amount;
        _mint(to, amount);
        emit Minted(to, amount, beldexTxid, outputIndex);
    }

    // =================================================================================
    // Redeem (H.3) — burn wBDX, emit the watcher-decoded RedeemToNative
    // =================================================================================
    /// @notice Burn `amount` wBDX and request a native BDX release to `beldexAddress`.
    ///         The L1 gateway (Phase A.3) enforces the release cap in consensus; here we
    ///         only bound by `perTxMax` and shape-check the address (semantic validation
    ///         is off-chain). Emits the exact event the E.2 watcher decodes.
    function redeemToNative(uint256 amount, string calldata beldexAddress) external whenNotPaused {
        if (amount == 0) revert ZeroAmount();
        if (amount > perTxMax) revert PerTxCap();
        bytes memory addr = bytes(beldexAddress);
        // Shape-only: reject empty and absurdly long. Burn is irreversible, so err on the
        // permissive side — an unroutable-but-well-formed address is an off-chain concern.
        if (addr.length == 0 || addr.length > 200) revert BadRedeemAddress();

        _burn(msg.sender, amount);
        emit RedeemToNative(msg.sender, amount, addr);
    }

    // =================================================================================
    // Signer rotation (H.6) — self-authorizing committee hand-off
    // =================================================================================
    /// @notice Propose a new committee signer, authorized by the **outgoing** signer.
    ///         Permissionless relay: anyone may submit the outgoing committee's signature.
    ///         Enters a challenge window rather than switching immediately (H.6.2).
    function rotateSigner(address newSigner, uint64 newKeyEpoch, bytes calldata outgoingSig)
        external
        whenNotPaused
    {
        if (newKeyEpoch <= keyEpoch) revert StaleEpoch();
        if (newSigner == address(0)) revert ZeroAddress();
        // A proposal governance already rejected can never be staged again, even by a
        // valid (replayed) outgoing signature (H-3).
        if (vetoedProposals[_proposalId(newSigner, newKeyEpoch)]) revert RotationIsVetoed();

        bytes32 digest =
            keccak256(abi.encode(ROTATE_TAG, block.chainid, address(this), newKeyEpoch, newSigner));
        if (ECDSA.recover(digest, outgoingSig) != currentSigner) revert BadSigner();

        pendingSigner = newSigner;
        pendingKeyEpoch = newKeyEpoch;
        pendingActivateAt = block.timestamp + rotateTimelock;
        // Safe to clear now: `vetoedProposals` is the binding guard, and a rejected
        // (signer, epoch) already reverted above. This flag is only observability, and
        // must be reset or the first veto would block every later rotation forever.
        rotationVetoed = false;
        emit RotationProposed(newSigner, newKeyEpoch, pendingActivateAt);
    }

    /// @dev Identity of a rotation proposal, for the veto ledger.
    function _proposalId(address signer_, uint64 epoch_) internal pure returns (bytes32) {
        return keccak256(abi.encode(signer_, epoch_));
    }

    /// @notice Activate a proposed rotation after its challenge window, if not vetoed.
    ///         Permissionless *relay*: anyone may submit the transaction, but the cutover
    ///         only happens if `incomingSig` proves the **incoming** committee can already
    ///         sign under the new key (H.6.2b liveness proof).
    ///
    ///         WHY the incoming signature is required. The cutover is atomic — old-key mints
    ///         are valid right up to this call and rejected after. If we flipped to a key the
    ///         new committee cannot yet produce (DKG not finished / mesh not live), we would
    ///         open a "no active quorum" window: the old key is retired but the new key can't
    ///         sign, so no deposit can be minted until the new committee comes up. Gating on a
    ///         proof-of-possession from `pendingSigner` makes that window impossible — the flip
    ///         cannot occur until the successor has demonstrably taken office. If the successor
    ///         never proves liveness, activation simply stalls and `breakGlassSetSigner`
    ///         (admin) is the deliberate fallback.
    ///
    ///         The gate is on WHO SIGNED (`pendingSigner`), not on `msg.sender`: the successor
    ///         is a threshold key held by the committee mesh, not necessarily an EOA that can
    ///         send a transaction — so the signature is produced by the committee and relayed
    ///         by anyone.
    /// @param incomingSig 65-byte secp256k1 signature (r‖s‖v) by the *pending* key over the
    ///        domain-separated activation digest.
    ///
    ///         `whenNotPaused` (M-4): pause is the emergency stop, and a cutover moves
    ///         the mint AUTHORITY, not just mint activity. Without this an operator who
    ///         paused on suspicion of compromise had not actually stopped the hand-off.
    ///         Admin repair while paused is unaffected — `breakGlassSetSigner` is
    ///         deliberately not gated.
    function activateRotation(bytes calldata incomingSig) external whenNotPaused {
        if (pendingActivateAt == 0 || block.timestamp < pendingActivateAt) revert RotationNotReady();
        if (rotationVetoed) revert RotationIsVetoed();

        bytes32 digest = keccak256(
            abi.encode(ACTIVATE_TAG, block.chainid, address(this), pendingKeyEpoch, pendingSigner)
        );
        if (ECDSA.recover(digest, incomingSig) != pendingSigner) revert IncomingNotReady();

        currentSigner = pendingSigner;
        keyEpoch = pendingKeyEpoch;
        emit Rotated(currentSigner, keyEpoch);

        delete pendingSigner;
        delete pendingKeyEpoch;
        delete pendingActivateAt;
    }

    /// @notice Veto a pending rotation (freeze trigger). In production this is driven by
    ///         the Beldex watchers detecting that `pendingSigner` != the DKG address the
    ///         consensus-selected committee actually generated (H.6.2c). Modeled here as
    ///         an admin (freeze-authority) action.
    ///         A veto is **decisive**: it records the rejected proposal permanently and
    ///         cancels the pending rotation outright, rather than only raising a flag a
    ///         later proposal could clear (H-3).
    function vetoRotation() external onlyAdmin {
        if (pendingActivateAt == 0) revert NoPendingRotation();

        address rejectedSigner = pendingSigner;
        uint64 rejectedEpoch = pendingKeyEpoch;
        vetoedProposals[_proposalId(rejectedSigner, rejectedEpoch)] = true;

        delete pendingSigner;
        delete pendingKeyEpoch;
        delete pendingActivateAt;
        rotationVetoed = true; // retained for observability; no longer load-bearing

        emit RotationVetoed(rejectedSigner, rejectedEpoch);
    }

    /// @notice Un-reject a proposal vetoed in error, so it can be staged again.
    ///         Deliberately admin-only and explicit — the veto is otherwise permanent.
    function clearVetoedProposal(address signer_, uint64 epoch_) external onlyAdmin {
        delete vetoedProposals[_proposalId(signer_, epoch_)];
        emit VetoedProposalCleared(signer_, epoch_);
    }

    /// @notice Break-glass (H.6.2d / H.6.3): admin sets the signer directly when no valid
    ///         hand-off lands (mass exit / refusal). The deliberate fallback, not the
    ///         default path. Still cannot mint — only names the mint authority.
    ///
    ///         Emits `Rotated` **in addition to** `BreakGlassSignerSet`: a break-glass is
    ///         functionally a signer rotation (it advances `keyEpoch`), so the L1
    ///         bond-release gate (H.6.3) treats "the key moved past your epoch" uniformly,
    ///         however it moved. This prevents a refusing minority from freezing honest
    ///         departers' bonds — governance moving the key on-chain releases them too.
    ///         `BreakGlassSignerSet` is retained so the *provenance* (governance override
    ///         vs. self-authorized hand-off) stays visible on-chain for audit/telemetry.
    function breakGlassSetSigner(address newSigner, uint64 newKeyEpoch) external onlyAdmin {
        if (newSigner == address(0)) revert ZeroAddress();
        if (newKeyEpoch <= keyEpoch) revert StaleEpoch();
        currentSigner = newSigner;
        keyEpoch = newKeyEpoch;
        delete pendingSigner;
        delete pendingKeyEpoch;
        delete pendingActivateAt;
        rotationVetoed = false;
        emit Rotated(newSigner, newKeyEpoch);
        emit BreakGlassSignerSet(newSigner, newKeyEpoch);
    }

    // =================================================================================
    // Admin (H.4) — pause, break-glass signer set, caps, upgrade. All admin-only.
    // =================================================================================
    function pause() external onlyAdmin {
        _pause();
        emit Paused_(msg.sender);
    }

    function unpause() external onlyAdmin {
        _unpause();
        emit Unpaused_(msg.sender);
    }

    /// @notice Break-glass signer-set additions (overlap-never-gap, S11). Not the normal
    ///         churn path (that is `rotateSigner`).
    function addSigner(address signer) external onlyAdmin {
        if (signer == address(0)) revert ZeroAddress();
        isSigner[signer] = true;
        emit SignerAdded(signer);
    }

    function removeSigner(address signer) external onlyAdmin {
        isSigner[signer] = false;
        emit SignerRemoved(signer);
    }

    /// @notice Raise/lower the bond-backing ceiling. Governance sets this to mirror the
    ///         actual on-chain `BRIDGE_BOND`; `setCaps` cannot exceed it — encoding the
    ///         "raise the bond before the caps" rule on-chain (§7-bis).
    function setBondBackingCapLimit(uint256 newLimit) external onlyAdmin {
        bondBackingCapLimit = newLimit;
        emit BondBackingCapLimitSet(newLimit);
    }

    /// @notice Set the per-window and per-tx caps. Refuses a window cap above the current
    ///         bond backing — so a cap raise not preceded by a bond raise reverts.
    function setCaps(uint256 newWindowMintCap, uint256 newPerTxMax) external onlyAdmin {
        if (newWindowMintCap > bondBackingCapLimit) revert CapAboveBondBacking();
        windowMintCap = newWindowMintCap;
        perTxMax = newPerTxMax;
        emit CapsSet(newWindowMintCap, newPerTxMax);
    }

    function transferAdmin(address newAdmin) external onlyAdmin {
        if (newAdmin == address(0)) revert ZeroAddress();
        emit AdminTransferred(admin, newAdmin);
        admin = newAdmin;
    }

    /// @dev UUPS upgrade authority: admin (a TimelockController) only.
    function _authorizeUpgrade(address) internal override onlyAdmin { }

    /// @dev Storage gap for future upgrades (this contract's own vars only; OZ v5 bases
    ///      use ERC-7201 namespaced storage and need no gap). Reduced 40 -> 39 when
    ///      `vetoedProposals` was appended, so every pre-existing slot keeps its index.
    uint256[39] private __gap;
}
