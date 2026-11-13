// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Interface housing shared Gateway declarations. Keeps the main contract lean by
///         centralizing events, errors, enums, and structs that integrators need to reference.
interface IGateway {
    // ===== Errors =====
    error NotCommittee();
    error NotOperator();
    error InstanceUsed();
    error NotPending();
    error WindowExpired();
    error WindowNotExpired();
    error NotEnoughCommittee();
    error InvalidPubkeyLen();
    error InvalidPubkeyParity();
    error InstanceMismatch();
    error PeginAmountMismatch();
    error InvalidHeader();
    error MerkleVerifyFail();
    error InvalidSignatures();
    error FeeTooHigh();
    error OperatorNotRegistered();
    error StakeInsufficient();
    error GraphAlreadyPosted();
    error GraphPeginTxidMismatch();
    error WithdrawStatusInvalid();
    error NotWithdrawable();
    error TimelockNotExpired();
    error KickoffHeightLow();
    error TxidMismatch();
    error AlreadyDisproved();
    error IndexOutOfRange();
    error UnknownDisproveType();
    error DisproveInvalidHeader();

    // ===== Enums =====
    enum DisproveTxType {
        Disprove,
        QuickChallenge,
        ChallengeIncompleteKickoff,
        PubinDisprove,
        OperatorChallengeNack,
        OperatorCommitTimeout
    }

    enum PeginStatus {
        None,
        Pending,
        Withdrawable,
        Processing,
        Locked,
        Claimed,
        Discarded
    }

    enum WithdrawStatus {
        None,
        Processing,
        Initialized,
        Canceled,
        Complete,
        Disproved
    }

    // ===== Structs =====
    struct Utxo {
        bytes32 txid;
        uint32 vout;
        uint64 amountSats;
    }

    struct PeginDataInner {
        PeginStatus status;
        bytes16 instanceId;
        address depositorAddress;
        uint64 peginAmountSats;
        uint64[3] txnFees;
        Utxo[] userInputs;
        bytes32 userXonlyPubkey;
        string userChangeAddress;
        string userRefundAddress;
        bytes32 peginTxid;
        uint256 createdAt;
        address[] committeeAddresses;
        mapping(address value => uint256) committeeAddressPositions;
        mapping(address => bytes1) committeePubkeyParitys;
        mapping(address => bytes32) committeeXonlyPubkeys;
    }

    struct PeginData {
        PeginStatus status;
        bytes16 instanceId;
        address depositorAddress;
        uint64 peginAmountSats;
        uint64[3] txnFees;
        Utxo[] userInputs;
        bytes32 userXonlyPubkey;
        string userChangeAddress;
        string userRefundAddress;
        bytes32 peginTxid;
        uint256 createdAt;
        address[] committeeAddresses;
        bytes[] committeePubkeys;
    }

    struct WithdrawData {
        WithdrawStatus status;
        bytes32 peginTxid;
        address operatorAddress;
        bytes16 instanceId;
        uint256 lockAmount;
        uint256 btcBlockHeightAtWithdraw;
    }

    struct GraphData {
        bytes1 operatorPubkeyPrefix;
        bytes32 operatorPubkey;
        bytes32 peginTxid;
        bytes32 kickoffTxid;
        bytes32 take1Txid;
        bytes32 take2Txid;
        bytes32 watchtowerChallengeInitTxid;
        bytes32 proverAssertTxid;
        // ChallengeAssert txid of each verifier, in verifier order; a Disprove
        // spends output 0 of one of them together with the operator's connector-D.
        bytes32[] verifierAssertTxids;
        bytes32[] watchtowerChallengeTimeoutTxids;
        bytes32[] operatorChallengeNackTxids;
        bytes32 operatorCommitTimeoutTxid;
    }

    // ===== Events =====
    event BridgeInRequest(
        bytes16 indexed instanceId,
        address indexed depositorAddress,
        uint64 peginAmountSats,
        uint64[3] txnFees,
        Utxo[] userInputs,
        bytes32 userXonlyPubkey,
        string userChangeAddress,
        string userRefundAddress
    );
    event CommitteeResponse(bytes16 indexed instanceId, address indexed committeeAddress, bytes committeePubkey);
    event BridgeIn(
        address indexed depositorAddress,
        bytes16 indexed instanceId,
        uint64 indexed peginAmountSats,
        uint64 feeAmountSats
    );
    event PostGraphData(bytes16 indexed instanceId, bytes16 indexed graphId);
    event InitWithdraw(
        bytes16 indexed instanceId, bytes16 indexed graphId, address indexed operatorAddress, uint64 withdrawAmountSats
    );
    event CancelWithdraw(bytes16 indexed instanceId, bytes16 indexed graphId, address indexed triggerAddress);
    event ProceedWithdraw(bytes16 indexed instanceId, bytes16 indexed graphId, bytes32 kickoffTxid);
    event WithdrawHappyPath(
        bytes16 indexed instanceId,
        bytes16 indexed graphId,
        bytes32 take1Txid,
        address indexed operatorAddress,
        uint64 rewardAmountSats
    );
    event WithdrawUnhappyPath(
        bytes16 indexed instanceId,
        bytes16 indexed graphId,
        bytes32 take2Txid,
        address indexed operatorAddress,
        uint64 rewardAmountSats
    );
    event WithdrawDisproved(
        bytes16 indexed instanceId,
        bytes16 indexed graphId,
        DisproveTxType disproveTxType,
        uint256 txnIndex,
        bytes32 challengeStartTxid,
        bytes32 challengeFinishTxid,
        address challengerAddress,
        address disproverAddress,
        uint256 challengerRewardAmount,
        uint256 disproverRewardAmount
    );
}
