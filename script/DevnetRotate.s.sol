// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { Script, console2 } from "forge-std/Script.sol";
import { WrappedBDX } from "../src/WrappedBDX.sol";

/// @title  H.6 signer-rotation ceremony, driven against a local anvil.
/// @notice Sibling of `DevnetMint.s.sol`. The *outgoing* committee threshold-signs the
///         *incoming* committee's fresh-DKG address, so the hand-off is self-authorizing:
///         no admin key is involved on the happy path.
///
///         Two entrypoints because the challenge window has to be crossed by real chain
///         time — `vm.warp` only moves the script's local EVM, not anvil's, so the shell
///         driver warps between them with `evm_increaseTime`.
///
///           forge script ... --sig 'propose()'  --broadcast
///           <shell warps anvil past pendingActivateAt>
///           forge script ... --sig 'activate()' --broadcast
///
///         Env in: PROXY, NEW_SIGNER, NEW_KEY_EPOCH, ROTATE_RS (0x + 64 bytes of r‖s).
contract DevnetRotate is Script {
    /// secp256k1 group order — for EIP-2 low-S normalisation.
    uint256 internal constant N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    function _w() internal view returns (WrappedBDX) {
        return WrappedBDX(vm.envAddress("PROXY"));
    }

    /// @dev Assemble a 65-byte `r‖s‖v` from the committee's raw `r‖s`.
    ///
    ///      Two things a threshold signature does not hand you, both handled here:
    ///        * **low-S** — cggmp21 emits whichever of `s` / `N-s` the protocol produced;
    ///          OZ's `ECDSA.recover` rejects the high half outright (EIP-2 malleability).
    ///        * **recovery id** — `v` is not part of an ECDSA signature at all. It is a
    ///          decoding hint, and the only honest way to get it is to try both.
    function _assemble(bytes32 digest, bytes memory rs, address expect)
        internal
        view
        returns (bytes memory)
    {
        require(rs.length == 64, "ROTATE_RS must be exactly 64 bytes (r||s)");

        bytes32 r;
        bytes32 s;
        assembly {
            r := mload(add(rs, 32))
            s := mload(add(rs, 64))
        }

        if (uint256(s) > N / 2) {
            s = bytes32(N - uint256(s));
            console2.log("  low-S normalised (the committee emitted the high-S form)");
        } else {
            console2.log("  s was already low-S (no normalisation needed this run)");
        }

        uint8 v;
        for (uint8 cand = 27; cand <= 28; ++cand) {
            if (ecrecover(digest, cand, r, s) == expect) {
                v = cand;
                break;
            }
        }
        require(
            v != 0,
            "neither v=27 nor v=28 recovers the outgoing signer - the committee signed a different preimage"
        );
        console2.log("  recovery id v :", uint256(v));

        return abi.encodePacked(r, s, v);
    }

    // =====================================================================================
    // Step 1 — propose
    // =====================================================================================
    function propose() external {
        WrappedBDX w = _w();

        address newSigner = vm.envAddress("NEW_SIGNER");
        uint64 newEpoch = uint64(vm.envUint("NEW_KEY_EPOCH"));
        bytes memory rs = vm.envBytes("ROTATE_RS");

        address outgoing = w.currentSigner();
        uint64 curEpoch = w.keyEpoch();

        console2.log("outgoing signer :", outgoing);
        console2.log("current keyEpoch:", uint256(curEpoch));
        console2.log("incoming signer :", newSigner);
        console2.log("new keyEpoch    :", uint256(newEpoch));

        // Fail loudly here rather than let the contract's StaleEpoch/BadSigner do it —
        // a local require names the actual mistake.
        require(newEpoch > curEpoch, "NEW_KEY_EPOCH must be strictly greater than keyEpoch");
        require(newSigner != address(0), "NEW_SIGNER is the zero address");
        require(
            newSigner != outgoing,
            "successor equals the outgoing key - run a *fresh* DKG (cggmp21 0.6.3 has no refresh)"
        );

        // Mirrors WrappedBDX.rotateSigner exactly. Note the field order differs from the
        // mint digest: epoch precedes signer here.
        bytes32 digest =
            keccak256(abi.encode(w.ROTATE_TAG(), block.chainid, address(w), newEpoch, newSigner));
        console2.log("rotate digest   :", vm.toString(digest));

        bytes memory sig = _assemble(digest, rs, outgoing);

        vm.startBroadcast();
        w.rotateSigner(newSigner, newEpoch, sig);
        vm.stopBroadcast();

        console2.log("");
        console2.log("PROPOSED");
        console2.log("  pendingSigner    :", w.pendingSigner());
        console2.log("  pendingKeyEpoch  :", uint256(w.pendingKeyEpoch()));
        console2.log("  pendingActivateAt:", w.pendingActivateAt());
        console2.log("  block.timestamp  :", block.timestamp);
        console2.log("  vetoed           :", w.rotationVetoed());

        // The contract must NOT have switched yet — that is the whole point of H.6.2.
        require(w.currentSigner() == outgoing, "currentSigner moved at propose time - challenge window is not being honoured");
        require(w.keyEpoch() == curEpoch, "keyEpoch moved at propose time");
        console2.log("  currentSigner unchanged during the challenge window - correct");
    }

    // =====================================================================================
    // Step 2 — activate (after the shell has warped anvil past pendingActivateAt)
    // =====================================================================================
    function activate() external {
        WrappedBDX w = _w();

        address pending = w.pendingSigner();
        uint64 pendingEpoch = w.pendingKeyEpoch();
        // NB: named `prevSigner`, not `before` — Solidity reserves `after`, and the
        // sibling mint script already hit this class of collision once.
        address prevSigner = w.currentSigner();

        console2.log("block.timestamp  :", block.timestamp);
        console2.log("pendingActivateAt:", w.pendingActivateAt());
        console2.log("pendingSigner    :", pending);
        require(pending != address(0), "no pending rotation - run propose() first");

        vm.startBroadcast();
        w.activateRotation();
        vm.stopBroadcast();

        console2.log("");
        console2.log("ACTIVATED");
        console2.log("  currentSigner :", w.currentSigner());
        console2.log("  keyEpoch      :", uint256(w.keyEpoch()));

        require(w.currentSigner() == pending, "currentSigner did not become the pending signer");
        require(w.keyEpoch() == pendingEpoch, "keyEpoch did not become the pending epoch");
        require(w.currentSigner() != prevSigner, "currentSigner did not actually change");
        require(w.pendingSigner() == address(0), "pending rotation was not cleared");
        require(w.pendingActivateAt() == 0, "pendingActivateAt was not cleared");
        console2.log("  pending state cleared - correct");
    }
}
