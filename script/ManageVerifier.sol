// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {CommitteeManagement} from "../src/CommitteeManagement.sol";
import {GatewayUpgradeable} from "../src/Gateway.sol";

/// @notice Adds or removes a verifier PeerId after checking committee authorization locally.
/// Required env vars:
/// - PRIVATE_KEY:          relayer/payer EVM private key; does not need to be a committee member
/// - GATEWAY_ADDR:         Gateway proxy address
/// - VERIFIER_PEER_ID:     verifier PeerId as hex bytes
/// - VERIFIER_ACTION:      "add" or "remove"
/// - AUTH_NONCE:           nonce used by every committee signature
/// - COMMITTEE_SIG_0...N:  sequential 65-byte signatures encoded as r || s || v
contract ManageVerifier is Script {
    function run() external {
        uint256 relayerPrivateKey = vm.envUint("PRIVATE_KEY");
        bytes memory peerId = vm.envBytes("VERIFIER_PEER_ID");
        string memory action = vm.envString("VERIFIER_ACTION");
        uint256 nonce = vm.envUint("AUTH_NONCE");
        bytes[] memory signatures = _readSequentialSignatures();
        CommitteeManagement committee = _committeeManagement(vm.envAddress("GATEWAY_ADDR"));

        require(peerId.length != 0, "empty verifier peer id");
        require(signatures.length >= committee.quorumSize(), "fewer signatures than quorum");

        bytes32 actionHash = keccak256(bytes(action));
        bool add = actionHash == keccak256("add");
        bool remove = actionHash == keccak256("remove");
        require(add || remove, "VERIFIER_ACTION must be add or remove");

        bytes32 digest = add
            ? committee.getAddVerifierDigestNonced(peerId, nonce)
            : committee.getRemoveVerifierDigestNonced(peerId, nonce);
        require(committee.verifySignatures(digest, signatures), "invalid committee signatures");

        bool registered = committee.isVerifier(peerId);
        if (add) require(!registered, "verifier already registered");
        if (remove) require(registered, "verifier is not registered");

        console.log("CommitteeManagement:", address(committee));
        console.log("Relayer:", vm.addr(relayerPrivateKey));
        console.log("Authorization digest:");
        console.logBytes32(digest);

        vm.startBroadcast(relayerPrivateKey);
        if (add) {
            committee.addVerifier(peerId, nonce, signatures);
        } else {
            committee.removeVerifier(peerId, nonce, signatures);
        }
        vm.stopBroadcast();

        require(committee.isVerifier(peerId) == add, "verifier state not updated");
        console.log(add ? "Verifier added" : "Verifier removed");
    }

    function _committeeManagement(address gatewayAddr) internal view returns (CommitteeManagement) {
        return CommitteeManagement(address(GatewayUpgradeable(payable(gatewayAddr)).committeeManagement()));
    }

    function _readSequentialSignatures() internal view returns (bytes[] memory signatures) {
        uint256 count;
        while (true) {
            string memory key = string(abi.encodePacked("COMMITTEE_SIG_", vm.toString(count)));
            bytes memory signature = vm.envOr(key, bytes(""));
            if (signature.length == 0) break;
            require(signature.length == 65, "committee signature must be 65 bytes");
            unchecked {
                ++count;
            }
        }

        require(count > 0, "no committee signatures");
        signatures = new bytes[](count);
        for (uint256 i; i < count; ++i) {
            signatures[i] = vm.envBytes(string(abi.encodePacked("COMMITTEE_SIG_", vm.toString(i))));
        }
    }
}
