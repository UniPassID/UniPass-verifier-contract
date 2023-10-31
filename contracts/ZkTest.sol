// SPDX-License-Identifier: UNLICENSED

pragma solidity ^0.8.0;

import "./UnipassVerifier.sol";

import "hardhat/console.sol";

contract ZkTest {
    event Verified(bytes32 header_hash, uint256 sucess);

    UnipassVerifier verifier;

    constructor(address _verifier) {
        verifier = UnipassVerifier(_verifier);
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
        // bool matched = verifier.checkPublicInputsOpenId(
        //     public_params,
        //     public_inputs
        // );
        bool matched = true;
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


}
