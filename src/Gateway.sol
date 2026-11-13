// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {IBitcoinSPV} from "./interfaces/IBitcoinSPV.sol";
import {IPegBTC} from "./interfaces/IPegBTC.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {ICommitteeManagement} from "./interfaces/ICommitteeManagement.sol";
import {IStakeManagement} from "./interfaces/IStakeManagement.sol";
import {IGateway} from "./interfaces/IGateway.sol";
import {BitvmTxParser} from "./libraries/BitvmTxParser.sol";
import {MerkleProof} from "./libraries/MerkleProof.sol";

contract BitvmPolicy {
    uint64 constant rateMultiplier = 10000;

    uint64 public minChallengeAmountSats;
    uint64 public minPeginFeeSats;
    uint64 public peginFeeRate;
    uint64 public minOperatorRewardSats;
    uint64 public operatorRewardRate;

    uint256 public minStakeAmount;
    uint256 public minChallengerReward;
    uint256 public minDisproverReward;
    uint256 public minSlashAmount;

    // TODO Initializer & setters
}

contract GatewayUpgradeable is BitvmPolicy, Initializable, IGateway {
    using ECDSA for bytes32;

    uint8 private constant BTC_DECIMALS = 8;

    error ERC20TransferFailed();

    // EIP-712-like typehash constants to avoid recomputing literals
    bytes32 private constant POST_PEGIN_TYPEHASH =
        keccak256("POST_PEGIN_DATA(address contract,bytes16 instanceId,bytes32 peginTxid)");
    bytes32 private constant POST_GRAPH_TYPEHASH =
        keccak256("POST_GRAPH_DATA(address contract,bytes16 instanceId,bytes16 graphId,bytes32 graphDataHash)");
    bytes32 private constant CANCEL_WITHDRAW_TYPEHASH = keccak256("CANCEL_WITHDRAW(address contract,bytes16 graphId)");
    bytes32 private constant UNLOCK_STAKE_TYPEHASH =
        keccak256("UNLOCK_OPERATOR_STAKE(address contract,address operator,uint256 amount)");

    IPegBTC public pegBTC;
    IBitcoinSPV public bitcoinSPV;
    ICommitteeManagement public committeeManagement;
    IStakeManagement public stakeManagement;

    uint256 public responseWindowBlocks = 40; // 40 goat blocks ~ 2 minutes

    uint256 public cancelWithdrawTimelock = 144; // 144 btc blocks ~ 24 hours

    bytes16[] public instanceIds;
    mapping(bytes16 instanceId => bytes16[] graphIds) public instanceIdToGraphIds;
    mapping(bytes16 instanceId => PeginDataInner) public peginDataMap;
    mapping(bytes16 graphId => GraphData) public graphDataMap;
    mapping(bytes16 graphId => WithdrawData) public withdrawDataMap;

    constructor() {
        _disableInitializers();
    }

    // initializer
    function initialize(
        IPegBTC _pegBTC,
        IBitcoinSPV _bitcoinSPV,
        ICommitteeManagement _committeeManagement,
        IStakeManagement _stakeManagement
    ) external initializer {
        // set initial parameters
        minChallengeAmountSats = 1000000; // 0.01 BTC
        minPeginFeeSats = 5000; // 0.00005 BTC
        peginFeeRate = 50; // 0.5%
        minOperatorRewardSats = 3000; // 0.00003 BTC
        operatorRewardRate = 30; // 0.3%

        minStakeAmount = 60000000000000000; // 0.06 stakeToken(WGBTC)
        minChallengerReward = 12500000000000000; // 0.0125 stakeToken(WGBTC)
        minDisproverReward = 2500000000000000; // 0.0025 stakeToken(WGBTC)
        minSlashAmount = 30000000000000000; // 0.03 stakeToken(WGBTC)

        responseWindowBlocks = 200; // 200 goat blocks ~ 10 minutes
        cancelWithdrawTimelock = 144; // 144 btc blocks ~ 24 hours

        pegBTC = _pegBTC;
        bitcoinSPV = _bitcoinSPV;
        committeeManagement = _committeeManagement;
        stakeManagement = _stakeManagement;
    }

    // getters
    function getGraphIdsByInstanceId(bytes16 instanceId) external view returns (bytes16[] memory) {
        return instanceIdToGraphIds[instanceId];
    }

    function getPeginData(bytes16 instanceId) external view returns (PeginData memory) {
        PeginDataInner storage data = peginDataMap[instanceId];
        return PeginData({
            status: data.status,
            instanceId: data.instanceId,
            depositorAddress: data.depositorAddress,
            peginAmountSats: data.peginAmountSats,
            txnFees: data.txnFees,
            userInputs: data.userInputs,
            userXonlyPubkey: data.userXonlyPubkey,
            userChangeAddress: data.userChangeAddress,
            userRefundAddress: data.userRefundAddress,
            peginTxid: data.peginTxid,
            createdAt: data.createdAt,
            committeeAddresses: data.committeeAddresses,
            committeePubkeys: getCommitteePubkeysUnsafe(instanceId)
        });
    }

    function getGraphData(bytes16 graphId) external view returns (GraphData memory) {
        return graphDataMap[graphId];
    }
    // helpers

    function verifyCommitteeSignatures(bytes32 msgHash, bytes[] memory signatures, address[] memory members)
        public
        pure
        returns (bool)
    {
        address[] memory signers = new address[](signatures.length);
        for (uint256 i = 0; i < signatures.length; i++) {
            address signer = msgHash.recover(signatures[i]);
            signers[i] = signer;
        }
        // require signers contains all members
        for (uint256 i = 0; i < members.length; i++) {
            bool found = false;
            for (uint256 j = 0; j < signers.length; j++) {
                if (members[i] == signers[j]) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                return false;
            }
        }
        return true;
    }

    function getPostPeginDigest(bytes16 instanceId, bytes32 peginTxid) public view returns (bytes32) {
        return keccak256(abi.encode(POST_PEGIN_TYPEHASH, address(this), instanceId, peginTxid));
    }

    function getPostGraphDigest(bytes16 instanceId, bytes16 graphId, GraphData calldata graphData)
        public
        view
        returns (bytes32)
    {
        bytes32 graphDataHash = keccak256(abi.encode(graphData));
        return keccak256(abi.encode(POST_GRAPH_TYPEHASH, address(this), instanceId, graphId, graphDataHash));
    }

    function _getCancelWithdrawDigest(bytes16 graphId) internal view returns (bytes32) {
        return keccak256(abi.encode(CANCEL_WITHDRAW_TYPEHASH, address(this), graphId));
    }

    function getCancelWithdrawDigestNonced(bytes16 graphId, uint256 nonce) public view returns (bytes32) {
        bytes32 msgHash = _getCancelWithdrawDigest(graphId);
        return committeeManagement.getNoncedDigest(msgHash, nonce);
    }

    function _getUnlockStakeDigest(address operator, uint256 amount) internal view returns (bytes32) {
        return keccak256(abi.encode(UNLOCK_STAKE_TYPEHASH, address(this), operator, amount));
    }

    function getUnlockStakeDigestNonced(address operator, uint256 amount, uint256 nonce)
        public
        view
        returns (bytes32)
    {
        bytes32 msgHash = _getUnlockStakeDigest(operator, amount);
        return committeeManagement.getNoncedDigest(msgHash, nonce);
    }

    function _operatorReward(uint64 peginAmountSats) internal view returns (uint64) {
        return minOperatorRewardSats + (peginAmountSats * operatorRewardRate) / rateMultiplier;
    }

    function _safeTransfer(IERC20 token, address to, uint256 amount) internal {
        if (!token.transfer(to, amount)) revert ERC20TransferFailed();
    }

    function _safeTransferFrom(IERC20 token, address from, address to, uint256 amount) internal {
        if (!token.transferFrom(from, to, amount)) revert ERC20TransferFailed();
    }

    function _verifyMerkleInclusion(MerkleProof.BitcoinTxProof calldata proof, bytes32 txid, bool disproveContext)
        internal
        view
    {
        (bytes32 blockHash, bytes32 merkleRoot) = MerkleProof.parseBtcBlockHeader(proof.rawHeader);
        if (bitcoinSPV.blockHash(proof.height) != blockHash) {
            if (disproveContext) revert DisproveInvalidHeader();
            revert InvalidHeader();
        }
        if (!MerkleProof.verifyMerkleProof(merkleRoot, proof.proof, txid, proof.index)) {
            revert MerkleVerifyFail();
        }
    }

    function _finalizeWithdraw(
        bytes16 graphId,
        BitvmTxParser.BitcoinTx calldata rawTakeTx,
        MerkleProof.BitcoinTxProof calldata takeProof,
        bytes32 expectedTxid,
        bool happyPath
    ) internal {
        WithdrawData storage withdrawData = withdrawDataMap[graphId];
        bytes16 instanceId = withdrawData.instanceId;
        PeginDataInner storage peginData = peginDataMap[instanceId];
        GraphData storage graphData = graphDataMap[graphId];
        if (withdrawData.status != WithdrawStatus.Processing) {
            revert WithdrawStatusInvalid();
        }
        if (graphData.peginTxid == bytes32(0) || graphData.peginTxid != withdrawData.peginTxid) {
            revert GraphPeginTxidMismatch();
        }

        bytes32 takeTxid = BitvmTxParser._computeTxid(rawTakeTx);
        if (takeTxid != expectedTxid) revert TxidMismatch();
        _verifyMerkleInclusion(takeProof, takeTxid, false);

        peginData.status = PeginStatus.Claimed;
        withdrawData.status = WithdrawStatus.Complete;

        uint64 rewardAmountSats = _operatorReward(peginData.peginAmountSats);
        _safeTransfer(pegBTC, withdrawData.operatorAddress, _amountFromSats(rewardAmountSats));

        if (happyPath) {
            emit WithdrawHappyPath(instanceId, graphId, takeTxid, withdrawData.operatorAddress, rewardAmountSats);
        } else {
            emit WithdrawUnhappyPath(instanceId, graphId, takeTxid, withdrawData.operatorAddress, rewardAmountSats);
        }
    }

    modifier onlyCommittee() {
        if (!committeeManagement.isCommitteeMember(msg.sender)) {
            revert NotCommittee();
        }
        _;
    }

    modifier onlyOperator(bytes16 graphId) {
        if (withdrawDataMap[graphId].operatorAddress != msg.sender) {
            revert NotOperator();
        }
        _;
    }

    function postPeginRequest(
        bytes16 instanceId,
        uint64 peginAmountSats,
        uint64[3] calldata txnFees,
        address receiverAddress,
        Utxo[] calldata userInputs,
        bytes32 userXonlyPubkey,
        string calldata userChangeAddress,
        string calldata userRefundAddress
    ) external payable {
        PeginDataInner storage peginData = peginDataMap[instanceId];
        if (peginData.status != PeginStatus.None) revert InstanceUsed();
        // TODO: check peginAmount,feeRate,userInputs
        // TODO: charge fee

        peginData.status = PeginStatus.Pending;
        peginData.instanceId = instanceId;
        peginData.depositorAddress = receiverAddress;
        peginData.peginAmountSats = peginAmountSats;
        peginData.txnFees = txnFees;
        peginData.userInputs = userInputs;
        peginData.userXonlyPubkey = userXonlyPubkey;
        peginData.userChangeAddress = userChangeAddress;
        peginData.userRefundAddress = userRefundAddress;
        peginData.createdAt = block.number;
        instanceIds.push(instanceId);

        emit BridgeInRequest(
            instanceId,
            receiverAddress,
            peginAmountSats,
            txnFees,
            userInputs,
            userXonlyPubkey,
            userChangeAddress,
            userRefundAddress
        );
    }

    function answerPeginRequest(bytes16 instanceId, bytes memory committeePubkey) external onlyCommittee {
        PeginDataInner storage peginData = peginDataMap[instanceId];
        if (peginData.status != PeginStatus.Pending) revert NotPending();
        if (peginData.createdAt + responseWindowBlocks < block.number) {
            revert WindowExpired();
        }
        if (committeePubkey.length != 33) revert InvalidPubkeyLen();
        bytes1 committeePubkeyParity = committeePubkey[0];
        if (!(committeePubkeyParity == 0x02 || committeePubkeyParity == 0x03)) {
            revert InvalidPubkeyParity();
        }
        bytes32 committeeXonlyPubkey;
        assembly {
            committeeXonlyPubkey := mload(add(committeePubkey, 0x21))
        }

        address committeeAddress = msg.sender;
        if (peginData.committeeAddressPositions[committeeAddress] == 0) {
            peginData.committeeAddresses.push(committeeAddress);
            // The value is stored at length-1, but we add 1 to all indexes and use 0 as a sentinel value
            peginData.committeeAddressPositions[committeeAddress] = peginData.committeeAddresses.length;
        }
        peginData.committeePubkeyParitys[committeeAddress] = committeePubkeyParity;
        peginData.committeeXonlyPubkeys[committeeAddress] = committeeXonlyPubkey;

        emit CommitteeResponse(instanceId, committeeAddress, committeePubkey);
    }

    function getCommitteePubkeys(bytes16 instanceId) public view returns (bytes[] memory committeePubkeys) {
        if (peginDataMap[instanceId].createdAt + responseWindowBlocks >= block.number) revert WindowNotExpired();
        committeePubkeys = getCommitteePubkeysUnsafe(instanceId);
        if (committeePubkeys.length < committeeManagement.quorumSize()) {
            revert NotEnoughCommittee();
        }
    }

    function getCommitteeAddresses(bytes16 instanceId) public view returns (address[] memory committeeAddresses) {
        if (peginDataMap[instanceId].createdAt + responseWindowBlocks >= block.number) revert WindowNotExpired();
        committeeAddresses = peginDataMap[instanceId].committeeAddresses;
        if (committeeAddresses.length < committeeManagement.quorumSize()) {
            revert NotEnoughCommittee();
        }
    }

    function getCommitteePubkeysUnsafe(bytes16 instanceId) public view returns (bytes[] memory committeePubkeys) {
        PeginDataInner storage peginData = peginDataMap[instanceId];
        committeePubkeys = new bytes[](peginData.committeeAddresses.length);
        for (uint256 i = 0; i < peginData.committeeAddresses.length; ++i) {
            address committeeAddress = peginData.committeeAddresses[i];
            bytes1 parity = peginData.committeePubkeyParitys[committeeAddress];
            bytes32 XonlyPubkeys = peginData.committeeXonlyPubkeys[committeeAddress];
            committeePubkeys[i] = abi.encodePacked(parity, XonlyPubkeys);
        }
    }

    // TODO: post canceled pegin request?

    function postPeginData(
        bytes16 instanceId,
        BitvmTxParser.BitcoinTx calldata rawPeginTx,
        MerkleProof.BitcoinTxProof calldata peginProof,
        bytes[] calldata committeeSigs
    ) external onlyCommittee {
        PeginDataInner storage peginData = peginDataMap[instanceId];
        if (peginData.status != PeginStatus.Pending) revert NotPending();
        (bytes32 peginTxid, uint64 peginAmountSats, address depositorAddress, bytes16 parsedInstanceId) =
            BitvmTxParser._parsePegin(rawPeginTx);
        if (parsedInstanceId != instanceId) revert InstanceMismatch();
        if (peginAmountSats != peginData.peginAmountSats) {
            revert PeginAmountMismatch();
        }

        // validate pegin tx
        _verifyMerkleInclusion(peginProof, peginTxid, false);

        // validate committeeSigs
        bytes32 pegin_digest = getPostPeginDigest(instanceId, peginTxid);
        if (!verifyCommitteeSignatures(pegin_digest, committeeSigs, getCommitteeAddresses(instanceId))) {
            revert InvalidSignatures();
        }

        // update storage
        peginData.status = PeginStatus.Withdrawable;
        peginData.peginTxid = peginTxid;

        // mint pegBTC to user
        // deduct a fee from the User to cover the Operator's peg-out reward
        uint64 feeAmountSats = minPeginFeeSats + (peginAmountSats * peginFeeRate) / rateMultiplier;
        if (feeAmountSats >= peginAmountSats) revert FeeTooHigh();
        pegBTC.mint(depositorAddress, _amountFromSats(peginAmountSats - feeAmountSats));
        pegBTC.mint(address(this), _amountFromSats(feeAmountSats));

        emit BridgeIn(depositorAddress, instanceId, peginAmountSats, feeAmountSats);
    }

    function postGraphData(
        bytes16 instanceId,
        bytes16 graphId,
        GraphData calldata graphData,
        bytes[] calldata committeeSigs
    ) public onlyCommittee {
        // check operator stake
        // Note:committee should check operator's locked stake before pre-signed any graph txns
        address operatorStakeAddress = stakeManagement.pubkeyToAddress(graphData.operatorPubkey);
        if (operatorStakeAddress == address(0)) revert OperatorNotRegistered();
        if (stakeManagement.lockedStakeOf(operatorStakeAddress) < minStakeAmount) revert StakeInsufficient();

        // check committeeSigs
        bytes32 graph_digest = getPostGraphDigest(instanceId, graphId, graphData);
        if (!verifyCommitteeSignatures(graph_digest, committeeSigs, getCommitteeAddresses(instanceId))) {
            revert InvalidSignatures();
        }

        // check graph data
        if (graphDataMap[graphId].peginTxid != 0) revert GraphAlreadyPosted();
        PeginDataInner storage peginData = peginDataMap[instanceId];
        if (graphData.peginTxid != peginData.peginTxid) {
            revert GraphPeginTxidMismatch();
        }

        // store graph data
        graphDataMap[graphId] = graphData;
        instanceIdToGraphIds[instanceId].push(graphId);
        // A graph can be disproved without initWithdraw ever running; record its
        // instance now so the WithdrawDisproved event names it. initWithdraw later
        // writes the same value, as the peg-in txid ties the graph to this instance.
        withdrawDataMap[graphId].instanceId = instanceId;

        emit PostGraphData(instanceId, graphId);
    }

    function initWithdraw(bytes16 instanceId, bytes16 graphId) external {
        WithdrawData storage withdrawData = withdrawDataMap[graphId];
        if (!(withdrawData.status == WithdrawStatus.None || withdrawData.status == WithdrawStatus.Canceled)) {
            revert WithdrawStatusInvalid();
        }
        PeginDataInner storage peginData = peginDataMap[instanceId];
        if (peginData.status != PeginStatus.Withdrawable) {
            revert NotWithdrawable();
        }
        GraphData storage graphData = graphDataMap[graphId];
        if (graphData.peginTxid == bytes32(0) || graphData.peginTxid != peginData.peginTxid) {
            revert GraphPeginTxidMismatch();
        }

        // lock the pegin utxo so others can not withdraw it
        peginData.status = PeginStatus.Locked;

        // lock operator's pegBTC
        uint256 lockAmount = _amountFromSats(peginData.peginAmountSats);
        _safeTransferFrom(pegBTC, msg.sender, address(this), lockAmount);

        withdrawData.peginTxid = peginData.peginTxid;
        withdrawData.operatorAddress = msg.sender;
        withdrawData.status = WithdrawStatus.Initialized;
        withdrawData.instanceId = instanceId;
        withdrawData.lockAmount = lockAmount;
        withdrawData.btcBlockHeightAtWithdraw = bitcoinSPV.latestHeight();

        emit InitWithdraw(instanceId, graphId, withdrawData.operatorAddress, peginData.peginAmountSats);
    }

    // function cancelWithdraw(bytes16 graphId) external onlyOperator(graphId) {
    //     WithdrawData storage withdrawData = withdrawDataMap[graphId];
    //     PeginDataInner storage peginData = peginDataMap[withdrawData.instanceId];
    //     if (withdrawData.status != WithdrawStatus.Initialized) {
    //         revert WithdrawStatusInvalid();
    //     }
    //     if (withdrawData.btcBlockHeightAtWithdraw + cancelWithdrawTimelock >= bitcoinSPV.latestHeight()) {
    //         revert TimelockNotExpired();
    //     }
    //     withdrawData.status = WithdrawStatus.Canceled;
    //     pegBTC.transfer(withdrawData.operatorAddress, withdrawData.lockAmount);
    //     peginData.status = PeginStatus.Withdrawable;

    //     emit CancelWithdraw(withdrawData.instanceId, graphId, withdrawData.operatorAddress);
    // }

    function committeeCancelWithdraw(bytes16 graphId, uint256 nonce, bytes[] calldata committeeSigs) external {
        // validate committeeSigs
        WithdrawData storage withdrawData = withdrawDataMap[graphId];
        bytes32 cancel_digest = _getCancelWithdrawDigest(graphId);
        committeeManagement.executeNoncedSignatures(cancel_digest, nonce, committeeSigs);
        // update storage
        PeginDataInner storage peginData = peginDataMap[withdrawData.instanceId];
        if (withdrawData.status != WithdrawStatus.Initialized) {
            revert WithdrawStatusInvalid();
        }
        withdrawData.status = WithdrawStatus.Canceled;
        _safeTransfer(pegBTC, withdrawData.operatorAddress, withdrawData.lockAmount);
        peginData.status = PeginStatus.Withdrawable;
        emit CancelWithdraw(withdrawData.instanceId, graphId, withdrawData.operatorAddress);
    }

    // post kickoff tx
    function proceedWithdraw(
        bytes16 graphId,
        BitvmTxParser.BitcoinTx calldata rawKickoffTx,
        MerkleProof.BitcoinTxProof calldata kickoffProof
    ) external onlyCommittee {
        WithdrawData storage withdrawData = withdrawDataMap[graphId];
        bytes16 instanceId = withdrawData.instanceId;
        if (withdrawData.status != WithdrawStatus.Initialized) {
            revert WithdrawStatusInvalid();
        }
        if (withdrawData.btcBlockHeightAtWithdraw >= kickoffProof.height) {
            revert KickoffHeightLow();
        }

        GraphData storage graphData = graphDataMap[graphId];
        if (graphData.peginTxid == bytes32(0) || graphData.peginTxid != withdrawData.peginTxid) {
            revert GraphPeginTxidMismatch();
        }
        bytes32 kickoffTxid = BitvmTxParser._computeTxid(rawKickoffTx);
        if (kickoffTxid != graphData.kickoffTxid) revert TxidMismatch();
        _verifyMerkleInclusion(kickoffProof, kickoffTxid, false);

        // once kickoff is braodcasted , operator will not be able to cancel withdrawal
        withdrawData.status = WithdrawStatus.Processing;

        // burn pegBTC
        pegBTC.burn(withdrawData.lockAmount);

        emit ProceedWithdraw(instanceId, graphId, kickoffTxid);
    }

    function finishWithdrawHappyPath(
        bytes16 graphId,
        BitvmTxParser.BitcoinTx calldata rawTake1Tx,
        MerkleProof.BitcoinTxProof calldata take1Proof
    ) external onlyCommittee {
        GraphData storage graphData = graphDataMap[graphId];
        _finalizeWithdraw(graphId, rawTake1Tx, take1Proof, graphData.take1Txid, true);
    }

    function finishWithdrawUnhappyPath(
        bytes16 graphId,
        BitvmTxParser.BitcoinTx calldata rawTake2Tx,
        MerkleProof.BitcoinTxProof calldata take2Proof
    ) external onlyCommittee {
        GraphData storage graphData = graphDataMap[graphId];
        _finalizeWithdraw(graphId, rawTake2Tx, take2Proof, graphData.take2Txid, false);
    }

    // if no challengeStartTx happens, set rawChallengeStartTx.inputVector to empty
    function finishWithdrawDisproved(
        bytes16 graphId,
        DisproveTxType disproveTxType,
        uint256 txnIndex, // per-index disprove/timeout/nack tx index, ignored for pubin and operator commit timeout
        BitvmTxParser.BitcoinTx calldata rawChallengeStartTx,
        MerkleProof.BitcoinTxProof calldata challengeStartTxProof,
        BitvmTxParser.BitcoinTx calldata rawChallengeFinishTx,
        MerkleProof.BitcoinTxProof calldata challengeFinishTxProof
    ) external onlyCommittee {
        WithdrawData storage withdrawData = withdrawDataMap[graphId];
        GraphData storage graphData = graphDataMap[graphId];
        bytes16 instanceId = withdrawData.instanceId;
        // Malicious operator may skip initWithdraw & procceedWithdraw
        if (withdrawData.status == WithdrawStatus.Disproved) {
            revert AlreadyDisproved();
        }

        // verify ChallengeStart tx
        bytes32 challengeStartTxid;
        address challengerAddress;
        bytes32 kickoffTxid;
        uint32 kickoffVout;
        if (
            (
                disproveTxType == DisproveTxType.QuickChallenge
                    || disproveTxType == DisproveTxType.ChallengeIncompleteKickoff
                    || disproveTxType == DisproveTxType.PubinDisprove
                    || disproveTxType == DisproveTxType.OperatorChallengeNack
                    || disproveTxType == DisproveTxType.OperatorCommitTimeout
            ) && (rawChallengeStartTx.inputVector.length == 0)
        ) {
            // no challenge start tx
        } else {
            (challengeStartTxid, kickoffTxid, kickoffVout, challengerAddress) =
                BitvmTxParser._parseChallengeTx(rawChallengeStartTx);
            if (kickoffTxid != graphData.kickoffTxid) revert TxidMismatch();
            if (kickoffVout != BitvmTxParser.CHALLENGE_CONNECTOR_VOUT) {
                revert TxidMismatch();
            }
            _verifyMerkleInclusion(challengeStartTxProof, challengeStartTxid, true);
        }

        // verify ChallengeFinish tx
        bytes32 challengeFinishTxid;
        address disproverAddress;
        if (disproveTxType == DisproveTxType.Disprove) {
            // Disprove-X is pre-signed with SIGHASH_NONE, so its outputs (the
            // disprover's OP_RETURN among them) are free: identify it by the two
            // outpoints its signatures commit to instead of by its txid.
            uint256 verifierCount = graphData.verifierAssertTxids.length;
            if (verifierCount <= txnIndex) {
                revert IndexOutOfRange();
            }
            bytes32 assertTxid;
            uint32 connectorDVout;
            (challengeFinishTxid, assertTxid, connectorDVout, disproverAddress) =
                BitvmTxParser._parseDisproveTx(rawChallengeFinishTx);
            // OperatorAssert outputs are one connector per verifier, then connector-D.
            // forge-lint: disable-next-line(unsafe-typecast)
            if (assertTxid != graphData.proverAssertTxid || connectorDVout != uint32(verifierCount)) {
                revert TxidMismatch();
            }
            (bytes32 verifierAssertTxid, uint32 proverConnectorVout) =
                BitvmTxParser._parseInputOutpoint(rawChallengeFinishTx, 0);
            if (
                verifierAssertTxid != graphData.verifierAssertTxids[txnIndex]
                    || proverConnectorVout != BitvmTxParser.VERIFIER_ASSERT_PROVER_CONNECTOR_VOUT
            ) {
                revert TxidMismatch();
            }
        } else if (disproveTxType == DisproveTxType.QuickChallenge) {
            (challengeFinishTxid, kickoffTxid, kickoffVout, disproverAddress) =
                BitvmTxParser._parseQuickChallengeTx(rawChallengeFinishTx);
            if (kickoffTxid != graphData.kickoffTxid) revert TxidMismatch();
            if (kickoffVout != BitvmTxParser.GUARDIAN_CONNECTOR_VOUT) {
                revert TxidMismatch();
            }
        } else if (disproveTxType == DisproveTxType.ChallengeIncompleteKickoff) {
            (challengeFinishTxid, kickoffTxid, kickoffVout, disproverAddress) =
                BitvmTxParser._parseChallengeIncompleteKickoffTx(rawChallengeFinishTx);
            if (kickoffTxid != graphData.kickoffTxid) revert TxidMismatch();
            if (kickoffVout != BitvmTxParser.GUARDIAN_CONNECTOR_VOUT) {
                revert TxidMismatch();
            }
        } else if (disproveTxType == DisproveTxType.PubinDisprove) {
            challengeFinishTxid = BitvmTxParser._computeTxid(rawChallengeFinishTx);
            if (challengeFinishTxid == graphData.take2Txid) {
                revert TxidMismatch();
            }
            if (
                !BitvmTxParser._hasInputOutpoint(
                    rawChallengeFinishTx, graphData.proverAssertTxid, uint32(graphData.verifierAssertTxids.length)
                )
            ) {
                revert TxidMismatch();
            }
        } else if (disproveTxType == DisproveTxType.OperatorChallengeNack) {
            challengeFinishTxid = BitvmTxParser._computeTxid(rawChallengeFinishTx);
            if (graphData.operatorChallengeNackTxids.length <= txnIndex) {
                revert IndexOutOfRange();
            }
            if (challengeFinishTxid != graphData.operatorChallengeNackTxids[txnIndex]) {
                revert TxidMismatch();
            }
        } else if (disproveTxType == DisproveTxType.OperatorCommitTimeout) {
            challengeFinishTxid = BitvmTxParser._computeTxid(rawChallengeFinishTx);
            if (challengeFinishTxid != graphData.operatorCommitTimeoutTxid) {
                revert TxidMismatch();
            }
        } else {
            revert UnknownDisproveType();
        }
        _verifyMerkleInclusion(challengeFinishTxProof, challengeFinishTxid, true);
        withdrawData.status = WithdrawStatus.Disproved;

        // slash Operator & reward Challenger and Disprover
        IERC20 stakeToken = IERC20(stakeManagement.stakeTokenAddress());
        address operatorStakeAddress = stakeManagement.pubkeyToAddress(graphData.operatorPubkey);
        uint256 slashAmount = minSlashAmount;
        uint256 operatorStake = stakeManagement.stakeOf(operatorStakeAddress);
        if (operatorStake < slashAmount) slashAmount = operatorStake;
        stakeManagement.slashStake(operatorStakeAddress, slashAmount);

        uint256 challengerRewardAmount = minChallengerReward;
        uint256 disproverRewardAmount = minDisproverReward;
        if (challengerAddress != address(0)) {
            _safeTransfer(stakeToken, challengerAddress, challengerRewardAmount);
        }
        if (disproverAddress != address(0)) {
            _safeTransfer(stakeToken, disproverAddress, disproverRewardAmount);
        }

        emit WithdrawDisproved(
            instanceId,
            graphId,
            disproveTxType,
            txnIndex,
            challengeStartTxid,
            challengeFinishTxid,
            challengerAddress,
            disproverAddress,
            challengerRewardAmount,
            disproverRewardAmount
        );
    }

    /*
        If an operator wants to unlockStake, they must prove to the committee 
        that they have processed or discarded all graphs (for example, by spending the 
        prekickoff-connector through another path). Once the committee members have verified 
        this, they provide their signatures.
    */
    function unlockOperatorStake(address operator, uint256 amount, uint256 nonce, bytes[] calldata committeeSigs)
        external
    {
        bytes32 msgHash = _getUnlockStakeDigest(operator, amount);
        committeeManagement.executeNoncedSignatures(msgHash, nonce, committeeSigs);
        stakeManagement.unlockStake(operator, amount);
    }

    function _amountFromSats(uint64 amountSats) internal view returns (uint256) {
        uint8 tokenDecimals = IERC20Metadata(address(pegBTC)).decimals();
        if (tokenDecimals >= BTC_DECIMALS) {
            return uint256(amountSats) * 10 ** (tokenDecimals - BTC_DECIMALS);
        }
        return uint256(amountSats / uint64(10 ** (BTC_DECIMALS - tokenDecimals)));
    }
}
