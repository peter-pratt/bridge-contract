// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import { Test } from "forge-std/Test.sol";
import { WrappedBDX } from "../src/WrappedBDX.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { TimelockController } from "@openzeppelin/contracts/governance/TimelockController.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/// Trivial V2 to prove UUPS upgrades flow through the timelock (Phase G.2).
contract WrappedBDXTimelockV2 is WrappedBDX {
    function version() external pure returns (uint256) {
        return 2;
    }
}

/// Phase G.2 — the EVM admin is an OpenZeppelin `TimelockController`. Every admin action is
/// subject to a public, timelocked review window: the governance multisig (a proposer)
/// schedules an operation, and only after `MIN_DELAY` can anyone execute it. Direct admin
/// calls (even from the multisig) revert, because the *timelock* is the admin, not the EOA.
contract WrappedBDXTimelockTest is Test {
    WrappedBDX internal w;
    TimelockController internal timelock;

    address internal multisig = address(0x6115); // governance proposer (a Safe, in production)
    address internal alice = address(0xB0B);
    address internal committee = address(0xC0FFEE);

    uint256 internal constant COIN = 1e9;
    uint256 internal constant WINDOW_CAP = 1_000_000 * COIN;
    uint256 internal constant PER_TX_MAX = 100_000 * COIN;
    uint256 internal constant BOND_LIMIT = 1_400_000 * COIN;
    uint256 internal constant EPOCH_SECONDS = 1 days;
    uint256 internal constant ROTATE_TIMELOCK = 2 days;
    uint256 internal constant MIN_DELAY = 2 days;

    function setUp() public {
        address[] memory proposers = new address[](1);
        proposers[0] = multisig;
        address[] memory executors = new address[](1);
        executors[0] = address(0); // open executor
        timelock = new TimelockController(MIN_DELAY, proposers, executors, address(0));

        WrappedBDX impl = new WrappedBDX();
        bytes memory init = abi.encodeCall(
            WrappedBDX.initialize,
            (address(timelock), committee, WINDOW_CAP, PER_TX_MAX, BOND_LIMIT, EPOCH_SECONDS, ROTATE_TIMELOCK)
        );
        w = WrappedBDX(address(new ERC1967Proxy(address(impl), init)));
        vm.warp(10 * EPOCH_SECONDS + 5);
    }

    // Schedule an operation from the multisig, warp past the delay, and execute it (open).
    function _scheduleAndExecute(address target, bytes memory data) internal {
        vm.prank(multisig);
        timelock.schedule(target, 0, data, bytes32(0), bytes32(0), MIN_DELAY);
        vm.warp(block.timestamp + MIN_DELAY);
        timelock.execute(target, 0, data, bytes32(0), bytes32(0));
    }

    // ---- the admin IS the timelock ---------------------------------------------------
    function test_Admin_isTheTimelock() public view {
        assertEq(w.admin(), address(timelock));
    }

    function test_DirectAdminCall_evenFromMultisig_reverts() public {
        // The multisig is a timelock *proposer*, not the wBDX admin — direct calls fail.
        vm.prank(multisig);
        vm.expectRevert(WrappedBDX.NotAdmin.selector);
        w.setCaps(1, 1);

        vm.prank(multisig);
        vm.expectRevert(WrappedBDX.NotAdmin.selector);
        w.pause();

        vm.prank(alice);
        vm.expectRevert(WrappedBDX.NotAdmin.selector);
        w.addSigner(alice);
    }

    // ---- the timelock flow lands admin actions ---------------------------------------
    function test_Timelock_setCaps_afterDelay() public {
        // Raise the bond backing then the cap, both through the timelock.
        _scheduleAndExecute(address(w), abi.encodeCall(WrappedBDX.setBondBackingCapLimit, (BOND_LIMIT * 2)));
        _scheduleAndExecute(address(w), abi.encodeCall(WrappedBDX.setCaps, (BOND_LIMIT * 2, PER_TX_MAX)));
        assertEq(w.windowMintCap(), BOND_LIMIT * 2);
    }

    function test_Timelock_pause_afterDelay() public {
        _scheduleAndExecute(address(w), abi.encodeCall(WrappedBDX.pause, ()));
        assertTrue(w.paused());
    }

    function test_Timelock_addSigner_afterDelay() public {
        address bg = vm.addr(0xBEEF);
        _scheduleAndExecute(address(w), abi.encodeCall(WrappedBDX.addSigner, (bg)));
        assertTrue(w.isSigner(bg));
    }

    // ---- the delay is enforced -------------------------------------------------------
    function test_Timelock_executeBeforeDelay_reverts() public {
        bytes memory data = abi.encodeCall(WrappedBDX.pause, ());
        vm.prank(multisig);
        timelock.schedule(address(w), 0, data, bytes32(0), bytes32(0), MIN_DELAY);

        // Not yet ready → execution reverts (TimelockController state guard).
        vm.expectRevert();
        timelock.execute(address(w), 0, data, bytes32(0), bytes32(0));

        // One second before the delay elapses is still too early.
        vm.warp(block.timestamp + MIN_DELAY - 1);
        vm.expectRevert();
        timelock.execute(address(w), 0, data, bytes32(0), bytes32(0));

        // Exactly at the delay it succeeds.
        vm.warp(block.timestamp + 1);
        timelock.execute(address(w), 0, data, bytes32(0), bytes32(0));
        assertTrue(w.paused());
    }

    function test_Timelock_nonProposerCannotSchedule() public {
        vm.prank(alice);
        vm.expectRevert(); // AccessControl: missing PROPOSER_ROLE
        timelock.schedule(address(w), 0, abi.encodeCall(WrappedBDX.pause, ()), bytes32(0), bytes32(0), MIN_DELAY);
    }

    // ---- the bond-before-caps guard fires *inside* the timelocked call ---------------
    function test_Timelock_setCapsAboveBond_revertsOnExecute() public {
        // Even scheduled and past the delay, a cap above the current bond backing reverts
        // when the timelock calls setCaps — the guard is in the target, not the scheduler.
        bytes memory data = abi.encodeCall(WrappedBDX.setCaps, (BOND_LIMIT + 1, PER_TX_MAX));
        vm.prank(multisig);
        timelock.schedule(address(w), 0, data, bytes32(0), bytes32(0), MIN_DELAY);
        vm.warp(block.timestamp + MIN_DELAY);
        vm.expectRevert(); // TimelockController bubbles the CapAboveBondBacking revert
        timelock.execute(address(w), 0, data, bytes32(0), bytes32(0));
        assertEq(w.windowMintCap(), WINDOW_CAP); // unchanged
    }

    // ---- UUPS upgrade only via the timelock ------------------------------------------
    function test_Timelock_upgrade() public {
        WrappedBDXTimelockV2 v2 = new WrappedBDXTimelockV2();

        // A direct upgrade (not via timelock) reverts.
        vm.prank(multisig);
        vm.expectRevert(WrappedBDX.NotAdmin.selector);
        UUPSUpgradeable(address(w)).upgradeToAndCall(address(v2), "");

        // Through the timelock it lands, and state survives.
        _scheduleAndExecute(
            address(w), abi.encodeCall(UUPSUpgradeable.upgradeToAndCall, (address(v2), ""))
        );
        assertEq(WrappedBDXTimelockV2(address(w)).version(), 2);
        assertEq(w.currentSigner(), committee);
    }

    // ---- signer-set overlap (add-before-remove, S11) through the timelock ------------
    function test_Timelock_signerOverlapAddBeforeRemove() public {
        address oldSigner = vm.addr(0xA11);
        address newSigner = vm.addr(0xB22);

        _scheduleAndExecute(address(w), abi.encodeCall(WrappedBDX.addSigner, (oldSigner)));
        _scheduleAndExecute(address(w), abi.encodeCall(WrappedBDX.addSigner, (newSigner)));
        // Both are valid simultaneously — no gap.
        assertTrue(w.isSigner(oldSigner));
        assertTrue(w.isSigner(newSigner));

        _scheduleAndExecute(address(w), abi.encodeCall(WrappedBDX.removeSigner, (oldSigner)));
        assertFalse(w.isSigner(oldSigner));
        assertTrue(w.isSigner(newSigner));
    }
}
