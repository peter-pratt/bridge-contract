// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import { Script, console2 } from "forge-std/Script.sol";
import { WrappedBDX } from "../src/WrappedBDX.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { TimelockController } from "@openzeppelin/contracts/governance/TimelockController.sol";

/// Production deploy (Phase G.2): the wBDX `admin` is an OpenZeppelin `TimelockController`,
/// never an EOA and never a committee signer. The timelock's **proposer** is the governance
/// multisig (a Safe, passed as `PROPOSER`); executors are open (address(0)) so anyone can
/// execute an operation once its delay has elapsed — the delay, not the executor, is the
/// safety property. This makes every admin action (pause, addSigner/removeSigner, setCaps
/// with the bond-before-caps guard, UUPS upgrade) subject to a public, timelocked review
/// window (S8/S11).
///
///   MIN_DELAY, PROPOSER (governance multisig), INITIAL_SIGNER, WINDOW_MINT_CAP, PER_TX_MAX,
///   BOND_BACKING_CAP_LIMIT, EPOCH_SECONDS, ROTATE_TIMELOCK  (all via env)
contract DeployWithTimelock is Script {
    function run() external {
        uint256 minDelay = vm.envUint("MIN_DELAY");
        address proposer = vm.envAddress("PROPOSER"); // governance multisig
        address initialSigner = vm.envAddress("INITIAL_SIGNER");
        uint256 windowMintCap = vm.envUint("WINDOW_MINT_CAP");
        uint256 perTxMax = vm.envUint("PER_TX_MAX");
        uint256 bondBackingCapLimit = vm.envUint("BOND_BACKING_CAP_LIMIT");
        uint256 epochSeconds = vm.envUint("EPOCH_SECONDS");
        uint256 rotateTimelock = vm.envUint("ROTATE_TIMELOCK");

        vm.startBroadcast();

        // Timelock: the multisig proposes; execution is permissionless (address(0)); no
        // extra admin (self-administered), so no lingering privileged key.
        address[] memory proposers = new address[](1);
        proposers[0] = proposer;
        address[] memory executors = new address[](1);
        executors[0] = address(0); // open executor: anyone may execute after the delay
        TimelockController timelock =
            new TimelockController(minDelay, proposers, executors, address(0) /* self-administered */);

        WrappedBDX impl = new WrappedBDX();
        bytes memory init = abi.encodeCall(
            WrappedBDX.initialize,
            (
                address(timelock), // admin = the timelock
                initialSigner,
                windowMintCap,
                perTxMax,
                bondBackingCapLimit,
                epochSeconds,
                rotateTimelock
            )
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), init);

        vm.stopBroadcast();

        console2.log("TimelockController :", address(timelock));
        console2.log("WrappedBDX impl    :", address(impl));
        console2.log("WrappedBDX proxy   :", address(proxy));
    }
}
