// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {GatewayUpgradeable} from "../src/Gateway.sol";
import {IGateway} from "../src/interfaces/IGateway.sol";
import {IBitcoinSPV} from "../src/interfaces/IBitcoinSPV.sol";
import {ICommitteeManagement} from "../src/interfaces/ICommitteeManagement.sol";
import {IStakeManagement} from "../src/interfaces/IStakeManagement.sol";
import {BitvmTxParser} from "../src/libraries/BitvmTxParser.sol";
import {MerkleProof} from "../src/libraries/MerkleProof.sol";

contract GatewayHarness is GatewayUpgradeable {
    function setDependencies(IBitcoinSPV spv, ICommitteeManagement committee, IStakeManagement stake) external {
        bitcoinSPV = spv;
        committeeManagement = committee;
        stakeManagement = stake;
        minDisproverReward = 7;
    }

    function setPegin(bytes16 instanceId, bytes32 peginTxid, address committeeMember) external {
        PeginDataInner storage pegin = peginDataMap[instanceId];
        pegin.instanceId = instanceId;
        pegin.peginTxid = peginTxid;
        pegin.committeeAddresses.push(committeeMember);
    }

    function setGraph(bytes16 graphId, GraphData memory graphData) external {
        graphDataMap[graphId] = graphData;
    }
}

contract MockSPV is IBitcoinSPV {
    mapping(uint256 => bytes32) public blockHash;

    function setBlockHash(uint256 height, bytes32 hash) external {
        blockHash[height] = hash;
    }

    function latestHeight() external pure returns (uint256) {
        return 0;
    }
}

contract MockToken {
    mapping(address => uint256) public received;

    function transfer(address to, uint256 amount) external returns (bool) {
        received[to] += amount;
        return true;
    }
}

/// Only the calls the Gateway makes in these tests are implemented.
contract MockDependencies {
    address public stakeTokenAddress;

    constructor(address token) {
        stakeTokenAddress = token;
    }

    function isCommitteeMember(address) external pure returns (bool) {
        return true;
    }

    function quorumSize() external pure returns (uint256) {
        return 1;
    }

    function pubkeyToAddress(bytes32) external pure returns (address) {
        return address(0xBEEF);
    }

    function stakeOf(address) external pure returns (uint256) {
        return 1 ether;
    }

    function lockedStakeOf(address) external pure returns (uint256) {
        return 1 ether;
    }

    function slashStake(address, uint256) external {}
}

contract GatewayDisproveTest is Test {
    GatewayHarness gateway;
    MockSPV spv;
    MockToken token;

    bytes16 constant INSTANCE_ID = bytes16(uint128(1));
    bytes16 constant GRAPH_ID = bytes16(uint128(2));
    bytes32 constant PEGIN_TXID = bytes32(uint256(3));
    bytes32 constant KICKOFF_TXID = bytes32(uint256(4));
    bytes32 constant PROVER_ASSERT_TXID = bytes32(uint256(5));
    uint256 constant VERIFIERS = 3;
    address constant DISPROVER = address(0xD15);
    uint256 committeeKey = 0xC0;

    function setUp() public {
        gateway = new GatewayHarness();
        spv = new MockSPV();
        token = new MockToken();
        MockDependencies deps = new MockDependencies(address(token));
        gateway.setDependencies(spv, ICommitteeManagement(address(deps)), IStakeManagement(address(deps)));
        gateway.setPegin(INSTANCE_ID, PEGIN_TXID, vm.addr(committeeKey));
        vm.roll(1000);
    }

    function verifierAssertTxid(uint256 index) internal pure returns (bytes32) {
        return bytes32(uint256(0xA55E27) + index);
    }

    function graphData() internal pure returns (IGateway.GraphData memory data) {
        data.peginTxid = PEGIN_TXID;
        data.kickoffTxid = KICKOFF_TXID;
        data.proverAssertTxid = PROVER_ASSERT_TXID;
        data.verifierAssertTxids = new bytes32[](VERIFIERS);
        for (uint256 i = 0; i < VERIFIERS; i++) {
            data.verifierAssertTxids[i] = verifierAssertTxid(i);
        }
    }

    function postGraph() internal {
        IGateway.GraphData memory data = graphData();
        bytes32 digest = gateway.getPostGraphDigest(INSTANCE_ID, GRAPH_ID, data);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(committeeKey, digest);
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = abi.encodePacked(r, s, v);
        gateway.postGraphData(INSTANCE_ID, GRAPH_ID, data, sigs);
    }

    // ---- raw Bitcoin transactions ----

    function input(bytes32 txid, uint32 vout) internal pure returns (bytes memory) {
        return abi.encodePacked(
            txid, uint8(vout), uint8(vout >> 8), uint8(vout >> 16), uint8(vout >> 24), uint8(0), bytes4(0xffffffff)
        );
    }

    function output(bytes memory script) internal pure returns (bytes memory) {
        return abi.encodePacked(bytes8(0), uint8(script.length), script);
    }

    function rewardOpReturn(address to) internal pure returns (bytes memory) {
        return abi.encodePacked(bytes2(0x6a14), to);
    }

    function anchor() internal pure returns (bytes memory) {
        return hex"51024e73";
    }

    function tx2(bytes memory in0, bytes memory in1, bytes memory outs, uint8 outCount)
        internal
        pure
        returns (BitvmTxParser.BitcoinTx memory)
    {
        return BitvmTxParser.BitcoinTx({
            version: bytes4(0x02000000),
            inputVector: abi.encodePacked(uint8(2), in0, in1),
            outputVector: abi.encodePacked(outCount, outs),
            locktime: bytes4(0)
        });
    }

    function challenge() internal pure returns (BitvmTxParser.BitcoinTx memory) {
        return BitvmTxParser.BitcoinTx({
            version: bytes4(0x02000000),
            inputVector: abi.encodePacked(uint8(1), input(KICKOFF_TXID, 0)),
            outputVector: abi.encodePacked(uint8(1), output(anchor())),
            locktime: bytes4(0)
        });
    }

    /// A Disprove-X whose outputs were changed by its broadcaster: the reward
    /// OP_RETURN at output 0 and an anchor.
    function disprove(uint256 verifier) internal pure returns (BitvmTxParser.BitcoinTx memory) {
        return tx2(
            input(verifierAssertTxid(verifier), 0),
            input(PROVER_ASSERT_TXID, uint32(VERIFIERS)),
            abi.encodePacked(output(rewardOpReturn(DISPROVER)), output(anchor())),
            2
        );
    }

    /// A single-transaction block, so the merkle root is the txid itself.
    function proof(BitvmTxParser.BitcoinTx memory bitcoinTx, uint256 height)
        internal
        returns (MerkleProof.BitcoinTxProof memory)
    {
        bytes32 txid = BitvmTxParser._computeTxid(bitcoinTx);
        bytes memory header = abi.encodePacked(bytes4(0x02000000), bytes32(0), txid, bytes12(0));
        spv.setBlockHash(height, BitvmTxParser._hash256(header));
        return MerkleProof.BitcoinTxProof({rawHeader: header, height: height, proof: new bytes32[](0), index: 0});
    }

    struct Settlement {
        uint256 txnIndex;
        BitvmTxParser.BitcoinTx start;
        MerkleProof.BitcoinTxProof startProof;
        BitvmTxParser.BitcoinTx finish;
        MerkleProof.BitcoinTxProof finishProof;
    }

    /// Records both transactions in the SPV mock. Call before `expectRevert`
    /// or `expectEmit`, which apply to the next external call.
    function settlement(uint256 txnIndex, BitvmTxParser.BitcoinTx memory finish) internal returns (Settlement memory) {
        BitvmTxParser.BitcoinTx memory start = challenge();
        return Settlement(txnIndex, start, proof(start, 10), finish, proof(finish, 11));
    }

    function finishDisprove(Settlement memory s) internal {
        gateway.finishWithdrawDisproved(
            GRAPH_ID, IGateway.DisproveTxType.Disprove, s.txnIndex, s.start, s.startProof, s.finish, s.finishProof
        );
    }

    // ---- tests ----

    function test_disproveWithChangedOutputsSettlesAndPaysTheDisprover() public {
        postGraph();
        BitvmTxParser.BitcoinTx memory finish = disprove(1);
        Settlement memory s = settlement(1, finish);
        vm.expectEmit(false, true, false, true);
        emit IGateway.WithdrawDisproved(
            INSTANCE_ID,
            GRAPH_ID,
            IGateway.DisproveTxType.Disprove,
            1,
            BitvmTxParser._computeTxid(challenge()),
            BitvmTxParser._computeTxid(finish),
            address(0),
            DISPROVER,
            0,
            7
        );
        finishDisprove(s);
        (IGateway.WithdrawStatus status,,,,,) = gateway.withdrawDataMap(GRAPH_ID);
        assertEq(uint8(status), uint8(IGateway.WithdrawStatus.Disproved));
        assertEq(token.received(DISPROVER), 7);
    }

    function test_disproveMustSpendTheNamedVerifiersAssert() public {
        postGraph();
        Settlement memory s = settlement(0, disprove(1));
        vm.expectRevert(IGateway.TxidMismatch.selector);
        finishDisprove(s);
    }

    function test_disproveMustSpendTheProverConnectorOfTheVerifierAssert() public {
        postGraph();
        BitvmTxParser.BitcoinTx memory finish =
            tx2(input(verifierAssertTxid(1), 1), input(PROVER_ASSERT_TXID, uint32(VERIFIERS)), output(anchor()), 1);
        Settlement memory s = settlement(1, finish);
        vm.expectRevert(IGateway.TxidMismatch.selector);
        finishDisprove(s);
    }

    function test_disproveMustSpendConnectorD() public {
        postGraph();
        BitvmTxParser.BitcoinTx memory finish =
            tx2(input(verifierAssertTxid(1), 0), input(PROVER_ASSERT_TXID, 0), output(anchor()), 1);
        Settlement memory s = settlement(1, finish);
        vm.expectRevert(IGateway.TxidMismatch.selector);
        finishDisprove(s);
    }

    function test_verifierAssertItselfIsNotADisprove() public {
        postGraph();
        // Spends connector-D but not a verifier's prover connector.
        BitvmTxParser.BitcoinTx memory finish =
            tx2(input(bytes32(uint256(99)), 0), input(PROVER_ASSERT_TXID, uint32(VERIFIERS)), output(anchor()), 1);
        Settlement memory s = settlement(1, finish);
        vm.expectRevert(IGateway.TxidMismatch.selector);
        finishDisprove(s);
    }

    function test_disproveIndexOutOfRange() public {
        postGraph();
        Settlement memory s = settlement(VERIFIERS, disprove(1));
        vm.expectRevert(IGateway.IndexOutOfRange.selector);
        finishDisprove(s);
    }
}
