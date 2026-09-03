// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import { Test } from "forge-std/Test.sol";
import { WrappedBDX } from "../src/WrappedBDX.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/// A trivial V2 to prove UUPS upgrades are admin-gated (adds one function).
contract WrappedBDXV2 is WrappedBDX {
    function version() external pure returns (uint256) {
        return 2;
    }
}

contract WrappedBDXTest is Test {
    WrappedBDX internal w;

    address internal admin = address(0xA11CE);
    address internal alice = address(0xB0B);
    address internal relayer = address(0xF00D);

    // Committee Pevm key (a normal secp256k1 key here; in production it is the
    // CGGMP21 group key's address). vm.sign lets us produce the committee signature.
    uint256 internal committeePk = 0xC0FFEE;
    address internal committee;

    uint256 internal constant COIN = 1e9; // 9 decimals
    uint256 internal constant WINDOW_CAP = 1_000_000 * COIN;
    uint256 internal constant PER_TX_MAX = 100_000 * COIN;
    uint256 internal constant BOND_LIMIT = 1_400_000 * COIN; // (t+1)*100k, §7-bis headroom
    uint256 internal constant EPOCH_SECONDS = 1 days;
    uint256 internal constant ROTATE_TIMELOCK = 2 days;

    function setUp() public {
        committee = vm.addr(committeePk);
        WrappedBDX impl = new WrappedBDX();
        bytes memory init = abi.encodeCall(
            WrappedBDX.initialize,
            (admin, committee, WINDOW_CAP, PER_TX_MAX, BOND_LIMIT, EPOCH_SECONDS, ROTATE_TIMELOCK)
        );
        w = WrappedBDX(address(new ERC1967Proxy(address(impl), init)));
        vm.warp(10 * EPOCH_SECONDS + 123); // land mid-window, deterministic
    }

    // ---- signing helpers -----------------------------------------------------------
    function _mintDigest(address to, uint256 amount, bytes32 txid) internal view returns (bytes32) {
        return keccak256(
            abi.encode(w.MINT_TAG(), block.chainid, address(w), to, amount, txid, uint32(0))
        );
    }

    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v); // r‖s‖v, the 65-byte layout ECDSA.recover wants
    }

    function _mintSig(uint256 pk, address to, uint256 amount, bytes32 txid)
        internal
        view
        returns (bytes memory)
    {
        return _sign(pk, _mintDigest(to, amount, txid));
    }

    /// H-2: digest/signature for a specific gateway output of a Beldex tx.
    function _mintDigestAt(address to, uint256 amount, bytes32 txid, uint32 outIdx)
        internal
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode(w.MINT_TAG(), block.chainid, address(w), to, amount, txid, outIdx)
        );
    }

    function _mintSigAt(uint256 pk, address to, uint256 amount, bytes32 txid, uint32 outIdx)
        internal
        view
        returns (bytes memory)
    {
        return _sign(pk, _mintDigestAt(to, amount, txid, outIdx));
    }

    function _rotateDigest(uint64 newEpoch, address newSigner) internal view returns (bytes32) {
        return keccak256(
            abi.encode(w.ROTATE_TAG(), block.chainid, address(w), newEpoch, newSigner)
        );
    }

    function _activateDigest(uint64 pendingEpoch, address pendingSigner) internal view returns (bytes32) {
        return keccak256(
            abi.encode(w.ACTIVATE_TAG(), block.chainid, address(w), pendingEpoch, pendingSigner)
        );
    }

    /// The incoming committee's proof-of-possession over the activation digest.
    function _activateSig(uint256 pendingPk, uint64 pendingEpoch, address pendingSigner)
        internal
        view
        returns (bytes memory)
    {
        return _sign(pendingPk, _activateDigest(pendingEpoch, pendingSigner));
    }

    // =================================================================================
    // Tag value: keccak256 of the domain string, byte-for-byte equal to the signer's
    // hardcoded `watch.rs::MINT_TAG`.
    // =================================================================================
    function test_MintTag_isKeccakOfDomainString() public view {
        assertEq(w.MINT_TAG(), keccak256("BELDEX_BRIDGE_MINT_V1"));
        assertEq(w.ROTATE_TAG(), keccak256("BELDEX_BRIDGE_ROTATE_V1"));
        // Cross-check against the exact 32 bytes the Rust signer hardcodes (watch.rs::MINT_TAG).
        assertEq(
            w.MINT_TAG(),
            bytes32(0x2add0af7a298cb197030ba893d16279820a53d9214b4d3131733a2486b3366d4)
        );
        assertEq(w.decimals(), 9);
    }

    // =================================================================================
    // Mint (H.2)
    // =================================================================================
    function test_Mint_validCommitteeSig_mintsOnce() public {
        bytes32 txid = keccak256("dep-1");
        uint256 amt = 1_000 * COIN;
        bytes memory sig = _mintSig(committeePk, alice, amt, txid);

        vm.prank(relayer); // permissionless relay
        w.mint(alice, amt, txid, 0, sig);

        assertEq(w.balanceOf(alice), amt);
        assertEq(w.windowMinted(), amt);
        // H-2: the replay guard is keyed on (beldexTxid, outputIndex), not the bare txid.
        assertTrue(w.processedDeposits(keccak256(abi.encode(txid, uint32(0)))));
        assertFalse(w.processedDeposits(txid), "raw txid is no longer the key");
    }

    /// H-2 REGRESSION: a Beldex tx may pay the gateway up to 15 times (consensus:
    /// GATEWAY_TX_MAX_OUTPUTS). Every output must mint independently.
    function test_Mint_everyOutputOfOneBeldexTxMintsIndependently() public {
        bytes32 txid = keccak256("one-tx-many-outputs");
        for (uint32 i = 0; i < 15; i++) {
            address who = address(uint160(0x5000 + i));
            uint256 amt = (i + 1) * COIN;
            bytes memory sig = _mintSigAt(committeePk, who, amt, txid, i);
            w.mint(who, amt, txid, i, sig);
            assertEq(w.balanceOf(who), amt, "each output mints");
        }
    }

    /// H-2: each output is still single-use. Replaying one output reverts, and it does
    /// not block the others.
    function test_Mint_perOutputReplayStillReverts() public {
        bytes32 txid = keccak256("per-output-replay");
        bytes memory s0 = _mintSigAt(committeePk, alice, 1 * COIN, txid, 0);
        w.mint(alice, 1 * COIN, txid, 0, s0);

        vm.expectRevert(WrappedBDX.Replay.selector);
        w.mint(alice, 1 * COIN, txid, 0, s0);

        // A different output of the same tx is unaffected.
        w.mint(alice, 2 * COIN, txid, 1, _mintSigAt(committeePk, alice, 2 * COIN, txid, 1));
        assertEq(w.balanceOf(alice), 3 * COIN);
    }

    /// H-2: outputIndex is bound into the digest — a signature for output 0 cannot be
    /// re-used to mint output 1.
    function test_Mint_signatureIsBoundToItsOutputIndex() public {
        bytes32 txid = keccak256("index-binding");
        bytes memory sigFor0 = _mintSigAt(committeePk, alice, 1 * COIN, txid, 0);
        vm.expectRevert(WrappedBDX.BadSigner.selector);
        w.mint(alice, 1 * COIN, txid, 1, sigFor0);
    }

    /// H-2 UPGRADE SAFETY: a deposit recorded under the pre-upgrade raw-txid key must
    /// stay closed, or the upgrade would re-open every historical deposit for a second
    /// mint. Simulated by writing the legacy key directly into storage.
    function test_Mint_legacyRawTxidKeyStillBlocks() public {
        bytes32 txid = keccak256("pre-upgrade-deposit");
        // slot 6 = processedDeposits; legacy entries were keyed on the raw txid.
        vm.store(address(w), keccak256(abi.encode(txid, uint256(6))), bytes32(uint256(1)));
        assertTrue(w.processedDeposits(txid), "legacy entry present");

        bytes memory sig = _mintSigAt(committeePk, alice, 1 * COIN, txid, 0);
        vm.expectRevert(WrappedBDX.Replay.selector);
        w.mint(alice, 1 * COIN, txid, 0, sig);
    }

    function test_Mint_replayReverts() public {
        bytes32 txid = keccak256("dep-replay");
        uint256 amt = 1_000 * COIN;
        bytes memory sig = _mintSig(committeePk, alice, amt, txid);
        w.mint(alice, amt, txid, 0, sig);

        vm.expectRevert(WrappedBDX.Replay.selector);
        w.mint(alice, amt, txid, 0, sig);
    }

    function test_Mint_nonSignerReverts() public {
        uint256 roguePk = 0xBADBAD;
        bytes32 txid = keccak256("dep-rogue");
        bytes memory sig = _mintSig(roguePk, alice, 1 * COIN, txid);
        vm.expectRevert(WrappedBDX.BadSigner.selector);
        w.mint(alice, 1 * COIN, txid, 0, sig);
    }

    function test_Mint_adminCannotMint() public {
        // The admin holds no committee key; a "mint" it could author is just a non-signer
        // signature. Prove the admin address cannot conjure a valid mint.
        uint256 adminPk = 0xA11CE; // arbitrary; not the committee key
        bytes32 txid = keccak256("dep-admin");
        bytes memory sig = _mintSig(adminPk, alice, 1 * COIN, txid);
        vm.prank(admin);
        vm.expectRevert(WrappedBDX.BadSigner.selector);
        w.mint(alice, 1 * COIN, txid, 0, sig);
    }

    function test_Mint_wrongChain_reverts() public {
        bytes32 txid = keccak256("dep-chain");
        uint256 amt = 1 * COIN;
        bytes memory sig = _mintSig(committeePk, alice, amt, txid); // signed under current chainid

        vm.chainId(block.chainid + 1); // domain separation: a different chain's digest differs
        vm.expectRevert(WrappedBDX.BadSigner.selector);
        w.mint(alice, amt, txid, 0, sig);
    }

    function test_Mint_wrongContract_reverts() public {
        // Deploy a second instance; a signature bound to `w` must not mint on `w2`.
        WrappedBDX impl = new WrappedBDX();
        bytes memory init = abi.encodeCall(
            WrappedBDX.initialize,
            (admin, committee, WINDOW_CAP, PER_TX_MAX, BOND_LIMIT, EPOCH_SECONDS, ROTATE_TIMELOCK)
        );
        WrappedBDX w2 = WrappedBDX(address(new ERC1967Proxy(address(impl), init)));

        bytes32 txid = keccak256("dep-addr");
        uint256 amt = 1 * COIN;
        bytes memory sigForW = _mintSig(committeePk, alice, amt, txid); // bound to address(w)

        vm.expectRevert(WrappedBDX.BadSigner.selector);
        w2.mint(alice, amt, txid, 0, sigForW);
    }

    function test_Mint_perTxCap_reverts() public {
        bytes32 txid = keccak256("dep-pertx");
        uint256 amt = PER_TX_MAX + 1;
        bytes memory sig = _mintSig(committeePk, alice, amt, txid);
        vm.expectRevert(WrappedBDX.PerTxCap.selector);
        w.mint(alice, amt, txid, 0, sig);
    }

    // =================================================================================
    // Fixed calendar window (§7-bis, β=1): cap holds within a window; resets on boundary;
    // no rolling-window 2× burst.
    // =================================================================================
    function test_Mint_windowCap_holdsThenResetsOnCalendarBoundary() public {
        // Fill the window to exactly the cap using perTxMax-sized mints.
        uint256 n = WINDOW_CAP / PER_TX_MAX; // 10
        for (uint256 i = 0; i < n; i++) {
            bytes32 txid = keccak256(abi.encode("fill", i));
            w.mint(alice, PER_TX_MAX, txid, 0, _mintSig(committeePk, alice, PER_TX_MAX, txid));
        }
        assertEq(w.windowMinted(), WINDOW_CAP);

        // One more in the SAME window exceeds the cap → revert (no rolling burst).
        bytes32 over = keccak256("over");
        // Sig computed BEFORE expectRevert: _mintSig staticcalls MINT_TAG() through
        // the proxy, and an inline call would consume the expectRevert.
        bytes memory overSig = _mintSig(committeePk, alice, 1 * COIN, over);
        vm.expectRevert(WrappedBDX.WindowCap.selector);
        w.mint(alice, 1 * COIN, over, 0, overSig);

        // A few seconds later — still the same calendar window — still capped.
        vm.warp(block.timestamp + 5);
        vm.expectRevert(WrappedBDX.WindowCap.selector);
        w.mint(alice, 1 * COIN, over, 0, overSig);

        // Cross the calendar boundary → the window resets; minting resumes.
        uint256 nextBoundary = (block.timestamp / EPOCH_SECONDS + 1) * EPOCH_SECONDS;
        vm.warp(nextBoundary);
        bytes32 fresh = keccak256("fresh-window");
        w.mint(alice, PER_TX_MAX, fresh, 0, _mintSig(committeePk, alice, PER_TX_MAX, fresh));
        assertEq(w.windowMinted(), PER_TX_MAX);
    }

    // =================================================================================
    // Redeem (H.3) — emits the exact event the E.2 watcher decodes.
    // =================================================================================
    event RedeemToNative(address indexed from, uint256 amount, bytes beldexAddress);
    event Rotated(address indexed newSigner, uint64 newKeyEpoch);
    event BreakGlassSignerSet(address indexed newSigner, uint64 newKeyEpoch);

    function test_Redeem_burnsAndEmits() public {
        bytes32 txid = keccak256("dep-redeem");
        uint256 amt = 5_000 * COIN;
        w.mint(alice, amt, txid, 0, _mintSig(committeePk, alice, amt, txid));

        string memory bdxAddr = "bxABCDEFdeadbeef00112233445566778899aabbccddeeff00112233445566778899";
        vm.expectEmit(true, false, false, true, address(w));
        emit RedeemToNative(alice, 2_000 * COIN, bytes(bdxAddr));
        vm.prank(alice);
        w.redeemToNative(2_000 * COIN, bdxAddr);

        assertEq(w.balanceOf(alice), amt - 2_000 * COIN);
        assertEq(w.totalSupply(), amt - 2_000 * COIN);
    }

    function test_Redeem_perTxMax_reverts() public {
        // Fund alice past perTxMax with two cap-respecting mints (a single
        // PER_TX_MAX+1 mint is itself rejected by the mint-side per-tx cap).
        bytes32 t1 = keccak256("dep-redeem2a");
        w.mint(alice, PER_TX_MAX, t1, 0, _mintSig(committeePk, alice, PER_TX_MAX, t1));
        bytes32 t2 = keccak256("dep-redeem2b");
        w.mint(alice, 2 * COIN, t2, 0, _mintSig(committeePk, alice, 2 * COIN, t2));
        vm.prank(alice);
        vm.expectRevert(WrappedBDX.PerTxCap.selector);
        w.redeemToNative(PER_TX_MAX + 1, "bxSomeAddress");
    }

    function test_Redeem_emptyAddress_reverts() public {
        bytes32 txid = keccak256("dep-redeem3");
        w.mint(alice, 10 * COIN, txid, 0, _mintSig(committeePk, alice, 10 * COIN, txid));
        vm.prank(alice);
        vm.expectRevert(WrappedBDX.BadRedeemAddress.selector);
        w.redeemToNative(1 * COIN, "");
    }

    // =================================================================================
    // Pause (H.4) — blocks mint but the admin can still rotate signers.
    // =================================================================================
    /// M-4: pause is a real emergency stop — it freezes the mint AUTHORITY as well as
    /// mint activity. The permissionless rotation path is gated; the admin break-glass
    /// path is not, so a compromised/dead signer is still replaceable while paused.
    function test_Pause_blocksMintAndRotation_butNotBreakGlass() public {
        vm.prank(admin);
        w.pause();

        bytes32 txid = keccak256("dep-paused");
        bytes memory sig = _mintSig(committeePk, alice, 1 * COIN, txid);
        vm.expectRevert(); // PausableUpgradeable: EnforcedPause
        w.mint(alice, 1 * COIN, txid, 0, sig);

        // Staging a rotation is now blocked while paused.
        address newSigner = vm.addr(0xD00D);
        bytes memory rot = _sign(committeePk, _rotateDigest(2, newSigner));
        vm.expectRevert(); // EnforcedPause
        w.rotateSigner(newSigner, 2, rot);
        assertEq(w.pendingSigner(), address(0), "no rotation staged while paused");

        // The deliberate escape hatch still works: admin can repoint the signer.
        vm.prank(admin);
        w.breakGlassSetSigner(newSigner, 2);
        assertEq(w.currentSigner(), newSigner);
        assertTrue(w.paused(), "still paused");
    }

    /// M-4: an already-staged rotation cannot be *activated* while paused either —
    /// otherwise pausing on suspicion of compromise would not stop the cutover.
    function test_Pause_blocksActivation_ofAnAlreadyStagedRotation() public {
        (uint256 newPk, address newSigner) = _newSignerPair();
        w.rotateSigner(newSigner, 2, _sign(committeePk, _rotateDigest(2, newSigner)));
        vm.warp(w.pendingActivateAt());

        vm.prank(admin);
        w.pause();

        bytes memory act = _activateSig(newPk, 2, newSigner);
        vm.expectRevert(); // EnforcedPause
        w.activateRotation(act);
        assertEq(w.currentSigner(), committee, "cutover blocked by pause");

        // ...and proceeds normally once unpaused.
        vm.prank(admin);
        w.unpause();
        w.activateRotation(_activateSig(newPk, 2, newSigner));
        assertEq(w.currentSigner(), newSigner);
    }

    // =================================================================================
    // Admin & caps (H.4) — bond-before-caps guard.
    // =================================================================================
    function test_SetCaps_aboveBondBacking_reverts() public {
        vm.prank(admin);
        vm.expectRevert(WrappedBDX.CapAboveBondBacking.selector);
        w.setCaps(BOND_LIMIT + 1, PER_TX_MAX);
    }

    function test_SetCaps_requiresBondRaisedFirst() public {
        uint256 higher = BOND_LIMIT + 500_000 * COIN;
        // Cannot jump the cap first.
        vm.prank(admin);
        vm.expectRevert(WrappedBDX.CapAboveBondBacking.selector);
        w.setCaps(higher, PER_TX_MAX);

        // Raise the bond backing, THEN the cap succeeds.
        vm.prank(admin);
        w.setBondBackingCapLimit(higher);
        vm.prank(admin);
        w.setCaps(higher, PER_TX_MAX);
        assertEq(w.windowMintCap(), higher);
    }

    function test_AdminFns_onlyAdmin() public {
        vm.expectRevert(WrappedBDX.NotAdmin.selector);
        w.pause();
        vm.expectRevert(WrappedBDX.NotAdmin.selector);
        w.setCaps(1, 1);
        vm.expectRevert(WrappedBDX.NotAdmin.selector);
        w.addSigner(alice);
    }

    function test_BreakGlassSigner_letsAdminNameMintAuthority() public {
        address bg = vm.addr(0xBEEF);
        vm.prank(admin);
        w.addSigner(bg);

        bytes32 txid = keccak256("dep-bg");
        uint256 amt = 3 * COIN;
        w.mint(alice, amt, txid, 0, _mintSig(0xBEEF, alice, amt, txid));
        assertEq(w.balanceOf(alice), amt);
    }

    // =================================================================================
    // UUPS upgrade (H.4) — admin-only.
    // =================================================================================
    function test_Upgrade_onlyAdmin() public {
        WrappedBDXV2 v2 = new WrappedBDXV2();

        // Non-admin cannot upgrade.
        vm.prank(alice);
        vm.expectRevert(WrappedBDX.NotAdmin.selector);
        UUPSUpgradeable(address(w)).upgradeToAndCall(address(v2), "");

        // Admin can.
        vm.prank(admin);
        UUPSUpgradeable(address(w)).upgradeToAndCall(address(v2), "");
        assertEq(WrappedBDXV2(address(w)).version(), 2);
        // State survives the upgrade.
        assertEq(w.currentSigner(), committee);
    }

    // =================================================================================
    // Rotation (H.6)
    // =================================================================================
    function _newSignerPair() internal pure returns (uint256 pk, address addr) {
        pk = 0x5165A;
        addr = vm.addr(pk);
    }

    function test_Rotation_proposeThenActivateAfterTimelock() public {
        (uint256 newPk, address newSigner) = _newSignerPair();
        bytes memory rot = _sign(committeePk, _rotateDigest(2, newSigner));

        vm.prank(relayer);
        w.rotateSigner(newSigner, 2, rot);
        assertEq(w.pendingSigner(), newSigner);

        // Before the window elapses, activation reverts (state check fires before the sig).
        bytes memory act = _activateSig(newPk, 2, newSigner);
        vm.expectRevert(WrappedBDX.RotationNotReady.selector);
        w.activateRotation(act);

        // Old key still mints during the challenge window.
        bytes32 t1 = keccak256("pre-activate");
        w.mint(alice, 1 * COIN, t1, 0, _mintSig(committeePk, alice, 1 * COIN, t1));

        // After the window, anyone relays the incoming committee's liveness proof.
        vm.warp(w.pendingActivateAt());
        vm.prank(relayer);
        w.activateRotation(_activateSig(newPk, 2, newSigner));
        assertEq(w.currentSigner(), newSigner);
        assertEq(w.keyEpoch(), 2);

        // New key mints; old key is now rejected (clean cutover).
        bytes32 t2 = keccak256("post-new");
        w.mint(alice, 1 * COIN, t2, 0, _mintSig(newPk, alice, 1 * COIN, t2));
        bytes32 t3 = keccak256("post-old");
        bytes memory oldSig = _mintSig(committeePk, alice, 1 * COIN, t3);
        vm.expectRevert(WrappedBDX.BadSigner.selector);
        w.mint(alice, 1 * COIN, t3, 0, oldSig);
    }

    function test_Rotation_staleEpoch_reverts() public {
        (, address newSigner) = _newSignerPair();
        // keyEpoch is 1; proposing epoch 1 (equal) must revert.
        bytes memory rot = _sign(committeePk, _rotateDigest(1, newSigner));
        vm.expectRevert(WrappedBDX.StaleEpoch.selector);
        w.rotateSigner(newSigner, 1, rot);
    }

    function test_Rotation_wrongContractDigest_reverts() public {
        (, address newSigner) = _newSignerPair();
        // Sign a rotate digest bound to a DIFFERENT contract address.
        bytes32 foreign = keccak256(
            abi.encode(w.ROTATE_TAG(), block.chainid, address(0xDEAD), uint64(2), newSigner)
        );
        bytes memory rot = _sign(committeePk, foreign);
        vm.expectRevert(WrappedBDX.BadSigner.selector);
        w.rotateSigner(newSigner, 2, rot);
    }

    function test_Rotation_notByCurrentSigner_reverts() public {
        (, address newSigner) = _newSignerPair();
        // Signed by a non-committee key.
        bytes memory rot = _sign(0xBADBAD, _rotateDigest(2, newSigner));
        vm.expectRevert(WrappedBDX.BadSigner.selector);
        w.rotateSigner(newSigner, 2, rot);
    }

    function test_Rotation_vetoedCannotActivate() public {
        (uint256 newPk, address newSigner) = _newSignerPair();
        bytes memory rot = _sign(committeePk, _rotateDigest(2, newSigner));
        w.rotateSigner(newSigner, 2, rot);

        vm.prank(admin);
        w.vetoRotation();

        // H-3: the veto now CANCELS the rotation outright rather than flagging it, so
        // there is no longer a pending rotation to activate at all.
        assertEq(w.pendingSigner(), address(0), "veto cancels the pending rotation");
        assertEq(w.pendingActivateAt(), 0);

        vm.warp(block.timestamp + 3 days);
        bytes memory act = _activateSig(newPk, 2, newSigner);
        vm.expectRevert(WrappedBDX.RotationNotReady.selector);
        w.activateRotation(act);
        assertEq(w.currentSigner(), committee); // unchanged
    }

    /// H-3 REGRESSION: the original bypass. An arbitrary address replays the outgoing
    /// committee's still-valid rotate signature to wash out a veto, then replays the
    /// equally unexpiring activation proof. Both must now fail.
    function test_Rotation_vetoedProposalCannotBeRevivedByReplay() public {
        (uint256 newPk, address newSigner) = _newSignerPair();
        bytes memory rotSig = _sign(committeePk, _rotateDigest(2, newSigner));
        bytes memory actSig = _activateSig(newPk, 2, newSigner);

        w.rotateSigner(newSigner, 2, rotSig);
        vm.prank(admin);
        w.vetoRotation();
        assertTrue(w.vetoedProposals(keccak256(abi.encode(newSigner, uint64(2)))));

        // Months later, a stranger replays the original signature.
        vm.warp(block.timestamp + 90 days);
        vm.prank(address(0xBAD));
        vm.expectRevert(WrappedBDX.RotationIsVetoed.selector);
        w.rotateSigner(newSigner, 2, rotSig);

        // Nothing was staged, so the stale activation proof has nothing to activate.
        vm.prank(address(0xBAD));
        vm.expectRevert(WrappedBDX.RotationNotReady.selector);
        w.activateRotation(actSig);

        assertEq(w.currentSigner(), committee, "veto held");
        assertEq(w.keyEpoch(), 1);
    }

    /// H-3: a veto blocks only the rejected (signer, epoch). Governance can still hand
    /// off to a different successor, so the bridge is not bricked by a veto.
    function test_Rotation_vetoBlocksOnlyTheRejectedProposal() public {
        (, address rejected) = _newSignerPair();
        w.rotateSigner(rejected, 2, _sign(committeePk, _rotateDigest(2, rejected)));
        vm.prank(admin);
        w.vetoRotation();

        // A different successor at the same epoch is fine.
        uint256 goodPk = 0xC0D0;
        address good = vm.addr(goodPk);
        w.rotateSigner(good, 2, _sign(committeePk, _rotateDigest(2, good)));
        vm.warp(w.pendingActivateAt());
        w.activateRotation(_activateSig(goodPk, 2, good));
        assertEq(w.currentSigner(), good);
    }

    /// H-3: a veto raised in error can be cleared by the admin, and only the admin.
    function test_Rotation_clearVetoedProposal_isAdminOnly() public {
        (uint256 newPk, address newSigner) = _newSignerPair();
        w.rotateSigner(newSigner, 2, _sign(committeePk, _rotateDigest(2, newSigner)));
        vm.prank(admin);
        w.vetoRotation();

        vm.expectRevert(WrappedBDX.NotAdmin.selector);
        w.clearVetoedProposal(newSigner, 2);

        vm.prank(admin);
        w.clearVetoedProposal(newSigner, 2);

        w.rotateSigner(newSigner, 2, _sign(committeePk, _rotateDigest(2, newSigner)));
        vm.warp(w.pendingActivateAt());
        w.activateRotation(_activateSig(newPk, 2, newSigner));
        assertEq(w.currentSigner(), newSigner);
    }

    function test_Rotation_breakGlassWhenNoHandoff() public {
        address bgSigner = vm.addr(0xC0DE);
        vm.prank(admin);
        w.breakGlassSetSigner(bgSigner, 5);
        assertEq(w.currentSigner(), bgSigner);
        assertEq(w.keyEpoch(), 5);
    }

    /// H.6.3: a break-glass must emit `Rotated` (in addition to `BreakGlassSignerSet`) so
    /// the L1 bond-release gate is satisfied uniformly — governance moving the key on-chain
    /// releases honest departers' bonds even when a refusing minority blocked a hand-off.
    function test_Rotation_breakGlass_emitsRotatedForBondGate() public {
        address bgSigner = vm.addr(0xC0DE);
        vm.expectEmit(true, false, false, true, address(w));
        emit Rotated(bgSigner, 7);
        vm.expectEmit(true, false, false, true, address(w));
        emit BreakGlassSignerSet(bgSigner, 7);
        vm.prank(admin);
        w.breakGlassSetSigner(bgSigner, 7);
        assertEq(w.currentSigner(), bgSigner);
        assertEq(w.keyEpoch(), 7);
    }

    function test_Rotation_breakGlass_onlyAdmin_andMonotonic() public {
        address bgSigner = vm.addr(0xC0DE);
        vm.expectRevert(WrappedBDX.NotAdmin.selector);
        w.breakGlassSetSigner(bgSigner, 5);

        vm.prank(admin);
        vm.expectRevert(WrappedBDX.StaleEpoch.selector);
        w.breakGlassSetSigner(bgSigner, 1); // equal to current keyEpoch
    }
}
