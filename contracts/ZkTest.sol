// SPDX-License-Identifier: UNLICENSED

pragma solidity 0.8.17;

import "./UnipassVerifier.sol";

contract ZkTest is UnipassVerifier {
    event Verified(bytes32 header_hash, uint256 sucess);

    constructor(address _admin) UnipassVerifier(_admin) {}

    function testV1024(
        uint32 from_left_index,
        uint32 from_len,
        uint128 domain_size,
        uint256[] memory vkdata,
        uint256[] memory public_inputs,
        uint256[] memory serialized_proof
    )
        public
        returns (
            bool,
            bytes32,
            bytes32,
            bytes32
        )
    {
        (
            bytes32 header_hash,
            bytes32 from_hash,
            bytes32 header_pub_match_hash
        ) = checkPublicInputs1024(from_left_index, from_len, public_inputs);
        bool success = verifyV1024(
            domain_size,
            vkdata,
            public_inputs,
            serialized_proof
        );
        if (success) {
            emit Verified(header_hash, 1);
        } else {
            emit Verified(header_hash, 1001);
        }

        return (success, header_hash, from_hash, header_pub_match_hash);
    }

    function testV2048(
        uint32 from_left_index,
        uint32 from_len,
        uint128 domain_size,
        uint256[] memory vkdata,
        uint256[] memory public_inputs,
        uint256[] memory serialized_proof
    )
        public
        returns (
            bool,
            bytes32,
            bytes32,
            bytes32
        )
    {
        (
            bytes32 header_hash,
            bytes32 from_hash,
            bytes32 header_pub_match_hash
        ) = checkPublicInputs2048(from_left_index, from_len, public_inputs);
        bool success = verifyV2048(
            domain_size,
            vkdata,
            public_inputs,
            serialized_proof
        );

        if (success) {
            emit Verified(header_hash, 1);
        } else {
            emit Verified(header_hash, 1001);
        }

        return (success, header_hash, from_hash, header_pub_match_hash);
    }
}
