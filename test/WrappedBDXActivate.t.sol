// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import { Test } from "forge-std/Test.sol";
import { WrappedBDX } from "../src/WrappedBDX.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// H.6.2b — activation liveness gate.
///
/// The scenario this closes: while the committee (quorum) is switching, there is an
/// off-chain moment where the successor is being stood up. If the contract flipped
/// `currentSigner` to the new key *before* the new committee could actually sign, deposits
/// arriving in that window could not be minted — old key retired, new key not yet live.
///
/// The fix requires the INCOMING key to sign an activation digest (proof-of-possession).
/// The cutover cannot happen until the successor has demonstrably taken office, so the
/// "no active quorum" mint gap cannot open. The gate is on WHO SIGNED, not on msg.sender,
/// so a threshold key held by the mesh (not an EOA) can still authorize — relayed by anyone.
contract WrappedBDXActivateTest is Test {
    WrappedBDX internal w;

    address internal admin = address(0xA11CE);
    address internal alice = address(0xB0B);
    address internal relayer = address(0xF00D);

    uint256 internal committeePk = 0xC0FFEE;      // outgoing committee key
    address internal committee;

    uint256 internal newPk = 0x5165A;             // incoming committee key
    address internal newSigner;

    uint256 internal constant COIN = 1e9;
    uint256 internal constant WINDOW_CAP = 1_000_000 * COIN;
    uint256 internal constant PER_TX_MAX = 100_000 * COIN;
    uint256 internal constant BOND_LIMIT = 1_400_000 * COIN;
    uint256 internal constant EPOCH_SECONDS = 1 days;
    uint256 internal constant ROTATE_TIMELOCK = 2 days;

    function setUp() public {
        committee = vm.addr(committeePk);
        newSigner = vm.addr(newPk);
        WrappedBDX impl = new WrappedBDX();
        bytes memory init = abi.encodeCall(
            WrappedBDX.initialize,
            (admin, committee, WINDOW_CAP, PER_TX_MAX, BOND_LIMIT, EPOCH_SECONDS, ROTATE_TIMELOCK)
        );
        w = WrappedBDX(address(new ERC1967Proxy(address(impl), init)));
        vm.warp(10 * EPOCH_SECONDS + 123);
    }

    // ---- signing helpers -----------------------------------------------------------
    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _rotateDigest(uint64 e, address s) internal view returns (bytes32) {
        return keccak256(abi.encode(w.ROTATE_TAG(), block.chainid, address(w), e, s));
    }

    function _activateDigest(uint64 e, address s) internal view returns (bytes32) {
        return keccak256(abi.encode(w.ACTIVATE_TAG(), block.chainid, address(w), e, s));
    }

    function _mintDigest(address to, uint256 amount, bytes32 txid) internal view returns (bytes32) {
        return keccak256(abi.encode(w.MINT_TAG(), block.chainid, address(w), to, amount, txid, uint32(0)));
    }

    // Stage a valid rotation to `newSigner` at epoch 2 and warp past the challenge window.
    function _proposeAndReachWindow() internal {
        bytes memory rot = _sign(committeePk, _rotateDigest(2, newSigner));
        vm.prank(relayer);
        w.rotateSigner(newSigner, 2, rot);
        vm.warp(w.pendingActivateAt());
    }

    // =================================================================================
    // (a) With no / stale / wrong-key incoming proof, the cutover cannot happen.
    // =================================================================================

    /// An empty incoming signature reverts — the timelock elapsing is not enough.
    function test_Activate_withoutIncomingProof_reverts() public {
        _proposeAndReachWindow();
        vm.prank(relayer);
        vm.expectRevert(); // ECDSA rejects a zero-length signature
        w.activateRotation("");
        assertEq(w.currentSigner(), committee); // no cutover
        assertEq(w.pendingSigner(), newSigner);  // proposal still pending
    }

    /// A well-formed signature by the WRONG key (the outgoing committee, not the incoming
    /// one) reverts with IncomingNotReady — proving the gate is on the *incoming* key.
    function test_Activate_signedByOutgoingKey_reverts() public {
        _proposeAndReachWindow();
        bytes memory wrong = _sign(committeePk, _activateDigest(2, newSigner)); // outgoing signs
        vm.prank(relayer);
        vm.expectRevert(WrappedBDX.IncomingNotReady.selector);
        w.activateRotation(wrong);
        assertEq(w.currentSigner(), committee);
    }

    /// A proof over the wrong epoch (a stale/replayed activation preimage) reverts.
    function test_Activate_wrongEpochProof_reverts() public {
        _proposeAndReachWindow();
        bytes memory stale = _sign(newPk, _activateDigest(1, newSigner)); // pendingEpoch is 2
        vm.prank(relayer);
        vm.expectRevert(WrappedBDX.IncomingNotReady.selector);
        w.activateRotation(stale);
        assertEq(w.currentSigner(), committee);
    }

    // =================================================================================
    // (b) With a valid incoming proof, activation succeeds and the cutover is clean.
    // =================================================================================

    function test_Activate_withIncomingProof_succeeds() public {
        _proposeAndReachWindow();

        // Anyone may relay the incoming committee's proof-of-possession.
        bytes memory proof = _sign(newPk, _activateDigest(2, newSigner));
        vm.prank(relayer);
        w.activateRotation(proof);

        assertEq(w.currentSigner(), newSigner);
        assertEq(w.keyEpoch(), 2);
        assertEq(w.pendingSigner(), address(0)); // pending state cleared
        assertEq(w.pendingActivateAt(), 0);

        // New key mints; old key is now rejected — clean cutover, no gap.
        bytes32 t2 = keccak256("post-new");
        w.mint(alice, 1 * COIN, t2, 0, _sign(newPk, _mintDigest(alice, 1 * COIN, t2)));
        assertEq(w.balanceOf(alice), 1 * COIN);

        bytes32 t3 = keccak256("post-old");
        bytes memory oldSig = _sign(committeePk, _mintDigest(alice, 1 * COIN, t3));
        vm.expectRevert(WrappedBDX.BadSigner.selector);
        w.mint(alice, 1 * COIN, t3, 0, oldSig);
    }

    /// The old key keeps minting for the whole challenge window right up to activation —
    /// so there is never a moment with no live minting authority.
    function test_Activate_oldKeyMintsUntilCutover_noGap() public {
        _proposeAndReachWindow(); // window elapsed, but not yet activated

        // Old key still valid here (currentSigner unchanged until activateRotation runs).
        bytes32 t1 = keccak256("pre-cutover");
        w.mint(alice, 1 * COIN, t1, 0, _sign(committeePk, _mintDigest(alice, 1 * COIN, t1)));
        assertEq(w.balanceOf(alice), 1 * COIN);
        assertEq(w.currentSigner(), committee);

        // Cut over with the incoming proof; from here the new key is the authority.
        w.activateRotation(_sign(newPk, _activateDigest(2, newSigner)));
        assertEq(w.currentSigner(), newSigner);
    }
}
