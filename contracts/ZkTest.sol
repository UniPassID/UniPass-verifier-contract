// SPDX-License-Identifier: UNLICENSED

pragma solidity ^0.8.0;

import "./UnipassVerifier.sol";

// import "hardhat/console.sol";

contract ZkTest {
    event Verified(bytes32 header_hash, uint256 sucess);

    UnipassVerifier verifier;

    constructor(address _verifier) {
        verifier = UnipassVerifier(_verifier);
    }

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
        PublicParams memory public_params;
        public_params.header_hash = header_hash;
        public_params.addr_hash = addr_hash;
        public_params.pub_match_hash = sha256(header_pub_match);
        public_params.header_len = header_len;
        public_params.from_left_index = from_left_index;
        public_params.from_len = from_len;
        bool matched = verifier.checkPublicInputs1024(
            public_params,
            public_inputs
        );

        bool success = verifier.verifyV1024(
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

    function testOpenId(
        bytes memory concat_hash,
        uint32 header_base64_len,
        uint32 payload_left_index,
        uint32 payload_base64_len,
        uint32 addr_left_index,
        uint32 addr_len,
        uint128 domain_size,
        uint256[] memory vkdata,
        uint256[] calldata public_inputs,
        uint256[] memory serialized_proof
    ) public returns (bool) {
        OpenIdPublicParams memory public_params;
        public_params.concat_hash = concat_hash;
        public_params.header_base64_len = header_base64_len;
        public_params.payload_left_index = payload_left_index;
        public_params.payload_base64_len = payload_base64_len;
        public_params.addr_left_index = addr_left_index;
        public_params.addr_len = addr_len;
        bool matched = verifier.checkPublicInputsOpenId(
            public_params,
            public_inputs
        );
        bool success = verifier.verifyOpenId(
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
        PublicParams memory public_params;
        public_params.header_hash = header_hash;
        public_params.addr_hash = addr_hash;
        public_params.pub_match_hash = sha256(header_pub_match);
        public_params.header_len = header_len;
        public_params.from_left_index = from_left_index;
        public_params.from_len = from_len;
        bool matched = verifier.checkPublicInputs2048(
            public_params,
            public_inputs
        );
        bool success = verifier.verifyV2048(
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
        bytes32[] memory header_hash,
        bytes32[] memory addr_hash,
        bytes[] calldata header_pub_match,
        uint32[] memory header_len,
        uint32[] memory from_left_index,
        uint32[] memory from_len,
        uint128 domain_size,
        uint256[] memory vkdata,
        uint256[] memory public_inputs,
        uint256[] memory serialized_proof
    ) public returns (bool) {
        PublicParams[] memory public_params = new PublicParams[](3);
        for (uint256 i = 0; i < 3; i++) {
            public_params[i].header_hash = header_hash[i];
            public_params[i].addr_hash = addr_hash[i];
            public_params[i].pub_match_hash = sha256(header_pub_match[i]);
            public_params[i].header_len = header_len[i];
            public_params[i].from_left_index = from_left_index[i];
            public_params[i].from_len = from_len[i];
        }

        bool matched = verifier.checkPublicInputs2048tri(
            public_params,
            public_inputs
        );

        bool success = verifier.verifyV2048tri(
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

        return (success);
    }
}
