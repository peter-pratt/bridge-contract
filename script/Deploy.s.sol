// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import { Script, console2 } from "forge-std/Script.sol";
import { WrappedBDX } from "../src/WrappedBDX.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// Deploys the WrappedBDX implementation behind an ERC1967 UUPS proxy.
///
/// Per-chain values (caps, window, timelock) come from the E.3 chain registry; pass
/// them via env. `ADMIN` MUST be a TimelockController (+ multisig), never an EOA, and
/// never a committee signer. `INITIAL_SIGNER` is the genesis `Pevm` committee address.
///
///   forge script script/Deploy.s.sol \
///     --rpc-url $RPC --broadcast \
///     --sig 'run()'
contract Deploy is Script {
    function run() external {
        address admin = vm.envAddress("ADMIN");
        address initialSigner = vm.envAddress("INITIAL_SIGNER");
        uint256 windowMintCap = vm.envUint("WINDOW_MINT_CAP");
        uint256 perTxMax = vm.envUint("PER_TX_MAX");
        uint256 bondBackingCapLimit = vm.envUint("BOND_BACKING_CAP_LIMIT");
        uint256 epochSeconds = vm.envUint("EPOCH_SECONDS");
        uint256 rotateTimelock = vm.envUint("ROTATE_TIMELOCK");

        vm.startBroadcast();

        WrappedBDX impl = new WrappedBDX();
        bytes memory init = abi.encodeCall(
            WrappedBDX.initialize,
            (admin, initialSigner, windowMintCap, perTxMax, bondBackingCapLimit, epochSeconds, rotateTimelock)
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), init);

        vm.stopBroadcast();

        console2.log("WrappedBDX impl :", address(impl));
        console2.log("WrappedBDX proxy:", address(proxy));
    }
}
