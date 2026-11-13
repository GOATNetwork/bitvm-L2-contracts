// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {CommitteeManagement} from "../src/CommitteeManagement.sol";
import {GatewayUpgradeable} from "../src/Gateway.sol";

/// @notice Generates one committee member's authorization signature for a verifier change.
/// @dev This script does not broadcast a transaction. Run it separately for each committee signer.
/// Required env vars:
/// - PRIVATE_KEY:          committee member EVM private key
/// - GATEWAY_ADDR:         Gateway proxy address
/// - VERIFIER_PEER_ID:     verifier PeerId as hex bytes
/// - VERIFIER_ACTION:      "add" or "remove"
/// - AUTH_NONCE:           nonce agreed by the committee for this authorization
contract SignVerifierAuthorization is Script {
    function run() external view {
        uint256 signerPrivateKey = vm.envUint("PRIVATE_KEY");
        address signer = vm.addr(signerPrivateKey);
        bytes memory peerId = vm.envBytes("VERIFIER_PEER_ID");
        uint256 nonce = vm.envUint("AUTH_NONCE");

        CommitteeManagement committee = _committeeManagement(vm.envAddress("GATEWAY_ADDR"));
        require(committee.isCommitteeMember(signer), "signer is not a committee member");

        bytes32 digest = _authorizationDigest(committee, peerId, vm.envString("VERIFIER_ACTION"), nonce);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);

        console.log("Committee:", signer);
        console.log("CommitteeManagement:", address(committee));
        console.log("Authorization digest:");
        console.logBytes32(digest);
        console.log("COMMITTEE_SIG (r || s || v):");
        console.logBytes(abi.encodePacked(r, s, v));
    }

    function _committeeManagement(address gatewayAddr) internal view returns (CommitteeManagement) {
        return CommitteeManagement(address(GatewayUpgradeable(payable(gatewayAddr)).committeeManagement()));
    }

    function _authorizationDigest(
        CommitteeManagement committee,
        bytes memory peerId,
        string memory action,
        uint256 nonce
    ) internal view returns (bytes32) {
        bytes32 actionHash = keccak256(bytes(action));
        if (actionHash == keccak256("add")) {
            return committee.getAddVerifierDigestNonced(peerId, nonce);
        }
        if (actionHash == keccak256("remove")) {
            return committee.getRemoveVerifierDigestNonced(peerId, nonce);
        }
        revert("VERIFIER_ACTION must be add or remove");
    }
}
