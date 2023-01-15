// SPDX-License-Identifier: UNLICENSED

pragma solidity ^0.8.0;

import "./UnipassVerifier.sol";

contract ZkTest is UnipassVerifier {
    event Verified(bytes32 header_hash, uint256 sucess);

    constructor(address _admin) UnipassVerifier(_admin) {}

    function testNew1024(
        bytes32 header_hash,
        bytes32 addr_hash,
        bytes memory header_pub_match,
        uint32 header_len,
        uint32 from_left_index,
        uint32 from_len,
        uint128 domain_size,
        uint256[] memory vkdata,
        uint256[] calldata public_inputs,
        uint256[] memory serialized_proof
    ) public returns (bool) {
        bool matched = checkPublicInputs1024(
            header_hash,
            addr_hash,
            sha256(header_pub_match),
            header_len,
            from_left_index,
            from_len,
            public_inputs
        );

        bool success = verifyV1024(
            domain_size,
            vkdata,
            public_inputs,
            serialized_proof
        );
        if (success && matched) {
            emit Verified("1", 1);
        } else {
            emit Verified("1001", 1001);
        }

        return (success && matched);
    }

    function testNew2048(
        bytes32 header_hash,
        bytes32 addr_hash,
        bytes calldata header_pub_match,
        uint32 header_len,
        uint32 from_left_index,
        uint32 from_len,
        uint128 domain_size,
        uint256[] memory vkdata,
        uint256[] calldata public_inputs,
        uint256[] memory serialized_proof
    ) public returns (bool) {
        bool matched = checkPublicInputs2048(
            header_hash,
            addr_hash,
            sha256(header_pub_match),
            header_len,
            from_left_index,
            from_len,
            public_inputs
        );

        bool success = verifyV2048(
            domain_size,
            vkdata,
            public_inputs,
            serialized_proof
        );
        if (success && matched) {
            emit Verified("1", 1);
        } else {
            emit Verified("1001", 1001);
        }

        return (success && matched);
    }

    function testNew2048tri(
        uint128 domain_size,
        uint256[] memory vkdata,
        uint256[] memory public_inputs,
        uint256[] memory serialized_proof
    ) public returns (bool) {
        bool success = verifyV2048tri(
            domain_size,
            vkdata,
            public_inputs,
            serialized_proof
        );
        if (success) {
            emit Verified("1", 1);
        } else {
            emit Verified("1001", 1001);
        }

        return (success);
    }
}
