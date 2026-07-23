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
/// amount, beldexTxid))`. Every field, order, and the tag value match the Rust signer's
/// `watch.rs::MintEvent::mint_preimage` exactly — otherwise `ecrecover` fails.
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

    // --- Events ----------------------------------------------------------------------
    event Minted(address indexed to, uint256 amount, bytes32 indexed beldexTxid);
    event RedeemToNative(address indexed from, uint256 amount, bytes beldexAddress);
    event RotationProposed(address indexed newSigner, uint64 newKeyEpoch, uint256 activateAt);
    event Rotated(address indexed newSigner, uint64 newKeyEpoch);
    event RotationVetoed(address indexed pendingSigner, uint64 pendingKeyEpoch);
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
    /// @param sig 65-byte secp256k1 signature (r‖s‖v) from the committee key.
    function mint(address to, uint256 amount, bytes32 beldexTxid, bytes calldata sig)
        external
        whenNotPaused
    {
        bytes32 digest =
            keccak256(abi.encode(MINT_TAG, block.chainid, address(this), to, amount, beldexTxid));
        address recovered = ECDSA.recover(digest, sig);
        if (recovered != currentSigner && !isSigner[recovered]) revert BadSigner();
        if (processedDeposits[beldexTxid]) revert Replay();

        // FIXED calendar window (β=1): reset on the boundary, never a rolling window,
        // so no back-to-back 2× burst across a window edge (§7-bis).
        uint256 w = block.timestamp / epochSeconds;
        if (w != windowId) {
            windowId = w;
            windowMinted = 0;
        }
        if (amount > perTxMax) revert PerTxCap();
        if (windowMinted + amount > windowMintCap) revert WindowCap();

        processedDeposits[beldexTxid] = true;
        windowMinted += amount;
        _mint(to, amount);
        emit Minted(to, amount, beldexTxid);
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
    {
        if (newKeyEpoch <= keyEpoch) revert StaleEpoch();
        if (newSigner == address(0)) revert ZeroAddress();

        bytes32 digest =
            keccak256(abi.encode(ROTATE_TAG, block.chainid, address(this), newKeyEpoch, newSigner));
        if (ECDSA.recover(digest, outgoingSig) != currentSigner) revert BadSigner();

        pendingSigner = newSigner;
        pendingKeyEpoch = newKeyEpoch;
        pendingActivateAt = block.timestamp + rotateTimelock;
        rotationVetoed = false; // a fresh valid proposal clears any prior veto
        emit RotationProposed(newSigner, newKeyEpoch, pendingActivateAt);
    }

    /// @notice Activate a proposed rotation after its challenge window, if not vetoed.
    ///         Permissionless. Clean cutover: old-key mints are valid until this runs,
    ///         and rejected after.
    function activateRotation() external {
        if (pendingActivateAt == 0 || block.timestamp < pendingActivateAt) revert RotationNotReady();
        if (rotationVetoed) revert RotationIsVetoed();

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
    function vetoRotation() external onlyAdmin {
        if (pendingActivateAt == 0) revert NoPendingRotation();
        rotationVetoed = true;
        emit RotationVetoed(pendingSigner, pendingKeyEpoch);
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
    ///      use ERC-7201 namespaced storage and need no gap).
    uint256[40] private __gap;
}
