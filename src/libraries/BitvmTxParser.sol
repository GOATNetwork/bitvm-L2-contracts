// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Constants} from "../Constants.sol";

library BitvmTxParser {
    struct BitcoinTx {
        bytes4 version;
        bytes inputVector;
        bytes outputVector;
        bytes4 locktime;
    }

    uint32 constant CHALLENGE_CONNECTOR_VOUT = 0;
    uint32 constant VERIFIER_ASSERT_PROVER_CONNECTOR_VOUT = 0;
    uint32 constant GUARDIAN_CONNECTOR_VOUT = 3;

    uint256 private constant BYTES_DATA_OFFSET = 32;
    uint256 private constant OUTPOINT_SIZE = 36;
    uint256 private constant SEQUENCE_SIZE = 4;
    uint256 private constant TXOUT_VALUE_SIZE = 8;
    uint256 private constant OP_RETURN_ADDRESS_SCRIPT_SIZE = 22;
    uint256 private constant PEGIN_OP_RETURN_SCRIPT_SIZE = 46;

    bytes2 private constant OP_RETURN_ADDRESS_PREFIX = 0x6a14;
    bytes2 private constant PEGIN_OP_RETURN_PREFIX = 0x6a2c;

    function _parsePegin(BitcoinTx memory bitcoinTx)
        internal
        view
        returns (bytes32 peginTxid, uint64 peginAmountSats, address depositorAddress, bytes16 instanceId)
    {
        _validateInputVector(bitcoinTx.inputVector);
        peginTxid = _computeTxid(bitcoinTx);

        bytes memory txouts = bitcoinTx.outputVector;
        (peginAmountSats,,) = _parseTxOut(txouts, 0);
        (, uint256 opReturnScriptOffset, uint256 opReturnScriptSize) = _parseTxOut(txouts, 1);

        require(
            opReturnScriptSize == PEGIN_OP_RETURN_SCRIPT_SIZE
                && _readBytes2(txouts, opReturnScriptOffset) == PEGIN_OP_RETURN_PREFIX,
            "invalid pegin OP_RETURN script"
        );
        require(_readBytes8(txouts, opReturnScriptOffset + 2) == Constants.magicBytes(), "magic_bytes mismatch");

        instanceId = _readBytes16(txouts, opReturnScriptOffset + 10);
        depositorAddress = address(_readBytes20(txouts, opReturnScriptOffset + 26));
    }

    function _parseChallengeTx(BitcoinTx memory bitcoinTx)
        internal
        pure
        returns (bytes32 challengeTxid, bytes32 kickoffTxid, uint32 kickoffVout, address challengerAddress)
    {
        (challengeTxid, kickoffTxid, kickoffVout, challengerAddress) = _parseKickoffChallengeTx(bitcoinTx, 1);
    }

    function _parseDisproveTx(BitcoinTx memory bitcoinTx)
        internal
        pure
        returns (bytes32 disproveTxid, bytes32 assertTxid, uint32 connectorDVout, address challengerAddress)
    {
        disproveTxid = _computeTxid(bitcoinTx);
        (assertTxid, connectorDVout) = _parseInputOutpoint(bitcoinTx, 1);
        challengerAddress = _parseOpReturnAddress(bitcoinTx.outputVector, 0);
    }

    function _parseQuickChallengeTx(BitcoinTx memory bitcoinTx)
        internal
        pure
        returns (bytes32 quickChallengeTxid, bytes32 kickoffTxid, uint32 kickoffVout, address challengerAddress)
    {
        (quickChallengeTxid, kickoffTxid, kickoffVout, challengerAddress) = _parseKickoffChallengeTx(bitcoinTx, 0);
    }

    function _parseChallengeIncompleteKickoffTx(BitcoinTx memory bitcoinTx)
        internal
        pure
        returns (
            bytes32 challengeIncompleteKickoffTxid,
            bytes32 kickoffTxid,
            uint32 kickoffVout,
            address challengerAddress
        )
    {
        (challengeIncompleteKickoffTxid, kickoffTxid, kickoffVout, challengerAddress) =
            _parseKickoffChallengeTx(bitcoinTx, 0);
    }

    function _computeTxid(BitcoinTx memory bitcoinTx) internal pure returns (bytes32) {
        bytes memory rawTx =
            abi.encodePacked(bitcoinTx.version, bitcoinTx.inputVector, bitcoinTx.outputVector, bitcoinTx.locktime);
        return _hash256(rawTx);
    }

    function _hasInputOutpoint(BitcoinTx memory bitcoinTx, bytes32 expectedTxid, uint32 expectedVout)
        internal
        pure
        returns (bool found)
    {
        bytes memory txins = bitcoinTx.inputVector;
        uint256 inputCount;
        uint256 offset;
        (inputCount, offset) = _parseCompactSize(txins, BYTES_DATA_OFFSET);
        require(inputCount > 0, "empty input vector");

        for (uint256 i = 0; i < inputCount; i++) {
            (bytes32 inputTxid, uint32 inputVout) = _parseInputOutpointAt(txins, offset);
            if (inputTxid == expectedTxid && inputVout == expectedVout) {
                found = true;
            }

            offset = _nextTxInOffset(txins, offset);
        }

        require(offset == _dataEnd(txins), "extra input bytes");
    }

    function _parseInputOutpoint(BitcoinTx memory bitcoinTx, uint256 inputIndex)
        internal
        pure
        returns (bytes32 inputTxid, uint32 inputVout)
    {
        bytes memory txins = bitcoinTx.inputVector;
        uint256 inputCount;
        uint256 offset;
        (inputCount, offset) = _parseCompactSize(txins, BYTES_DATA_OFFSET);
        require(inputCount > 0, "empty input vector");
        require(inputIndex < inputCount, "input index out of bounds");

        for (uint256 i = 0; i < inputCount; i++) {
            if (i == inputIndex) {
                (inputTxid, inputVout) = _parseInputOutpointAt(txins, offset);
            }

            offset = _nextTxInOffset(txins, offset);
        }

        require(offset == _dataEnd(txins), "extra input bytes");
    }

    function _parseKickoffChallengeTx(BitcoinTx memory bitcoinTx, uint256 challengerOutputIndex)
        private
        pure
        returns (bytes32 txid, bytes32 kickoffTxid, uint32 kickoffVout, address challengerAddress)
    {
        txid = _computeTxid(bitcoinTx);
        (kickoffTxid, kickoffVout) = _parseInputOutpoint(bitcoinTx, 0);
        challengerAddress = _parseOpReturnAddress(bitcoinTx.outputVector, challengerOutputIndex);
    }

    function _validateInputVector(bytes memory txins) private pure {
        uint256 inputCount;
        uint256 offset;
        (inputCount, offset) = _parseCompactSize(txins, BYTES_DATA_OFFSET);
        require(inputCount > 0, "empty input vector");

        for (uint256 i = 0; i < inputCount; i++) {
            offset = _nextTxInOffset(txins, offset);
        }

        require(offset == _dataEnd(txins), "extra input bytes");
    }

    function _parseInputOutpointAt(bytes memory txins, uint256 offset)
        private
        pure
        returns (bytes32 inputTxid, uint32 inputVout)
    {
        inputTxid = _readBytes32(txins, offset);
        inputVout = _readUint32LE(txins, offset + 32);
    }

    function _nextTxInOffset(bytes memory txins, uint256 offset) private pure returns (uint256 nextOffset) {
        _requireDataAvailable(txins, offset, OUTPOINT_SIZE, "txin out of bounds");

        uint256 scriptSigSize;
        uint256 scriptSigOffset;
        (scriptSigSize, scriptSigOffset) = _parseCompactSize(txins, offset + OUTPOINT_SIZE);
        _requireDataAvailable(txins, scriptSigOffset, scriptSigSize, "scriptSig out of bounds");

        nextOffset = scriptSigOffset + scriptSigSize;
        _requireDataAvailable(txins, nextOffset, SEQUENCE_SIZE, "txin sequence out of bounds");
        nextOffset += SEQUENCE_SIZE;
    }

    function _parseTxOut(bytes memory txouts, uint256 outputIndex)
        private
        pure
        returns (uint64 amountSats, uint256 scriptOffset, uint256 scriptSize)
    {
        bool found;
        (found, amountSats, scriptOffset, scriptSize) = _tryParseTxOut(txouts, outputIndex);
        require(found, "output index out of bounds");
    }

    function _parseOpReturnAddress(bytes memory txouts, uint256 outputIndex)
        private
        pure
        returns (address challengerAddress)
    {
        bool found;
        uint256 scriptOffset;
        uint256 scriptSize;
        (found,, scriptOffset, scriptSize) = _tryParseTxOut(txouts, outputIndex);
        if (!found || scriptSize != OP_RETURN_ADDRESS_SCRIPT_SIZE) return address(0);
        if (_readBytes2(txouts, scriptOffset) != OP_RETURN_ADDRESS_PREFIX) return address(0);
        challengerAddress = address(_readBytes20(txouts, scriptOffset + 2));
    }

    function _tryParseTxOut(bytes memory txouts, uint256 outputIndex)
        private
        pure
        returns (bool found, uint64 amountSats, uint256 scriptOffset, uint256 scriptSize)
    {
        uint256 outputCount;
        uint256 offset;
        (outputCount, offset) = _parseCompactSize(txouts, BYTES_DATA_OFFSET);
        require(outputCount > 0, "empty output vector");

        for (uint256 i = 0; i < outputCount; i++) {
            uint64 currentAmountSats = _readUint64LE(txouts, offset);

            uint256 currentScriptSize;
            uint256 currentScriptOffset;
            (currentScriptSize, currentScriptOffset) = _parseCompactSize(txouts, offset + TXOUT_VALUE_SIZE);
            _requireDataAvailable(txouts, currentScriptOffset, currentScriptSize, "txout script out of bounds");

            if (i == outputIndex) {
                found = true;
                amountSats = currentAmountSats;
                scriptOffset = currentScriptOffset;
                scriptSize = currentScriptSize;
            }

            offset = currentScriptOffset + currentScriptSize;
        }

        require(offset == _dataEnd(txouts), "extra output bytes");
    }

    function _parseCompactSize(bytes memory data, uint256 offset)
        internal
        pure
        returns (uint256 size, uint256 nextOffset)
    {
        uint8 firstByte = _readUint8(data, offset);

        if (firstByte == 0xff) {
            size = _readUint64LE(data, offset + 1);
            require(size > type(uint32).max, "non-canonical compact size");
            nextOffset = offset + 9;
        } else if (firstByte == 0xfe) {
            size = _readUint32LE(data, offset + 1);
            require(size > type(uint16).max, "non-canonical compact size");
            nextOffset = offset + 5;
        } else if (firstByte == 0xfd) {
            size = _readUint16LE(data, offset + 1);
            require(size >= 0xfd, "non-canonical compact size");
            nextOffset = offset + 3;
        } else {
            size = firstByte;
            nextOffset = offset + 1;
        }
    }

    function _hash256(bytes memory raw) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(sha256(raw)));
    }

    function _readUint8(bytes memory data, uint256 offset) private pure returns (uint8) {
        _requireDataAvailable(data, offset, 1, "data out of bounds");
        return uint8(data[offset - BYTES_DATA_OFFSET]);
    }

    function _readUint16LE(bytes memory data, uint256 offset) private pure returns (uint16) {
        _requireDataAvailable(data, offset, 2, "data out of bounds");
        return _reverseUint16(uint16(bytes2(_memLoad(data, offset))));
    }

    function _readUint32LE(bytes memory data, uint256 offset) private pure returns (uint32) {
        _requireDataAvailable(data, offset, 4, "data out of bounds");
        return _reverseUint32(uint32(bytes4(_memLoad(data, offset))));
    }

    function _readUint64LE(bytes memory data, uint256 offset) private pure returns (uint64) {
        _requireDataAvailable(data, offset, 8, "data out of bounds");
        return _reverseUint64(uint64(bytes8(_memLoad(data, offset))));
    }

    function _readBytes2(bytes memory data, uint256 offset) private pure returns (bytes2) {
        _requireDataAvailable(data, offset, 2, "data out of bounds");
        return bytes2(_memLoad(data, offset));
    }

    function _readBytes8(bytes memory data, uint256 offset) private pure returns (bytes8) {
        _requireDataAvailable(data, offset, 8, "data out of bounds");
        return bytes8(_memLoad(data, offset));
    }

    function _readBytes16(bytes memory data, uint256 offset) private pure returns (bytes16) {
        _requireDataAvailable(data, offset, 16, "data out of bounds");
        return bytes16(_memLoad(data, offset));
    }

    function _readBytes20(bytes memory data, uint256 offset) private pure returns (bytes20) {
        _requireDataAvailable(data, offset, 20, "data out of bounds");
        return bytes20(_memLoad(data, offset));
    }

    function _readBytes32(bytes memory data, uint256 offset) private pure returns (bytes32) {
        _requireDataAvailable(data, offset, 32, "data out of bounds");
        return _memLoad(data, offset);
    }

    function _requireDataAvailable(bytes memory data, uint256 offset, uint256 size, string memory reason) private pure {
        require(offset >= BYTES_DATA_OFFSET, "cannot point to memory size slot");
        uint256 dataOffset = offset - BYTES_DATA_OFFSET;
        require(dataOffset <= data.length && size <= data.length - dataOffset, reason);
    }

    function _dataEnd(bytes memory data) private pure returns (uint256) {
        return BYTES_DATA_OFFSET + data.length;
    }

    function _memLoad(bytes memory data, uint256 offset) internal pure returns (bytes32 res) {
        assembly {
            res := mload(add(data, offset))
        }
    }

    function _reverseUint64(uint64 _b) private pure returns (uint64 v) {
        v = _b;
        v = ((v >> 8) & 0x00FF00FF00FF00FF) | ((v & 0x00FF00FF00FF00FF) << 8);
        v = ((v >> 16) & 0x0000FFFF0000FFFF) | ((v & 0x0000FFFF0000FFFF) << 16);
        v = (v >> 32) | (v << 32);
    }

    function _reverseUint32(uint32 _b) private pure returns (uint32 v) {
        v = _b;
        v = ((v >> 8) & 0x00FF00FF) | ((v & 0x00FF00FF) << 8);
        v = (v >> 16) | (v << 16);
    }

    function _reverseUint16(uint16 _b) private pure returns (uint16 v) {
        v = (_b << 8) | (_b >> 8);
    }
}
