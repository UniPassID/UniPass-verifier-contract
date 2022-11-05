pragma solidity 0.8.17;

import "./PlonkCoreLib.sol";
import "./PlookupSingleCore.sol";
import "hardhat/console.sol";

contract UnipassVerifier is Plonk4SingleVerifierWithAccessToDNext {
    // uint256 constant SERIALIZED_PROOF_LENGTH = 0;

    address admin;
    uint128 domain_size_1024;
    uint128 domain_size_2048;

    modifier adminOnly() {
        require(msg.sender == admin, "!_!");
        _;
    }

    receive() external payable {}

    constructor() public {
        admin = address(msg.sender);
    }

    event Verified(address caller, uint256 success);

    // first register srshash
    function setupSRSHash(uint256 srshash_init)
        public
        adminOnly
        returns (bool)
    {
        srshash = bytes32(srshash_init);
        return true;
    }

    // then register vkdata
    function setupVKHash(
        uint64 string_length,
        uint64 num_inputs,
        uint128 domain_size,
        uint256[] memory vkdata
    ) public adminOnly returns (bool) {
        if (string_length == 1024) {
            vk1024hash = sha256(
                abi.encodePacked(num_inputs, domain_size, vkdata)
            );
            domain_size_1024 = domain_size;
            console.log("domain_size 1024: %s", domain_size);
        } else if (string_length == 2048) {
            vk2048hash = sha256(
                abi.encodePacked(num_inputs, domain_size, vkdata)
            );
            domain_size_2048 = domain_size;
            console.log("domain_size 2048: %s", domain_size);
        } else {
            return false;
        }
        return true;
    }

    function checkPublicInputs1024(
        uint32 from_left_index,
        uint32 from_len,
        uint256[] memory public_inputs
    )
        public
        returns (
            bytes32,
            bytes32,
            bytes32
        )
    {
        require(
            from_left_index + from_len < 1024 &&
                from_len >= 5 &&
                from_len <= 192,
            "from param error"
        );
        require(public_inputs.length == 12, "public inputs error");

        bytes32 header_hash = (bytes32)(
            (public_inputs[0] << 128) | ((public_inputs[1] << 128) >> 128)
        );
        bytes32 from_hash = (bytes32)(
            (public_inputs[2] << 128) | ((public_inputs[3] << 128) >> 128)
        );

        uint256 start_index = from_left_index / 252;
        uint256 header_offset = from_left_index % 252;
        for (uint256 i = 0; i < from_len; i++) {
            if (header_offset >= 252) {
                start_index++;
                header_offset = 0;
            }

            // check header mask string
            require(
                (public_inputs[4 + start_index] >> (252 - header_offset - 1)) &
                    uint256(1) ==
                    uint256(1),
                "unmatch"
            );

            // check addr mask string
            require(
                (public_inputs[9] >> (192 - i - 1)) & uint256(1) == uint256(1),
                "unmatch"
            );

            header_offset++;
        }

        bytes32 header_pub_match_hash = (bytes32)(
            (public_inputs[10] << 128) | ((public_inputs[11] << 128) >> 128)
        );

        console.logBytes32(header_hash);
        console.logBytes32(from_hash);
        console.logBytes32(header_pub_match_hash);

        return (header_hash, from_hash, header_pub_match_hash);
    }

    function checkPublicInputs2048(
        uint32 from_left_index,
        uint32 from_len,
        uint256[] memory public_inputs
    )
        public
        returns (
            bytes32,
            bytes32,
            bytes32
        )
    {
        require(
            from_left_index + from_len < 2048 &&
                from_len >= 5 &&
                from_len <= 192,
            "from param error"
        );
        require(public_inputs.length == 16, "public inputs error");

        bytes32 header_hash = (bytes32)(
            (public_inputs[0] << 128) | ((public_inputs[1] << 128) >> 128)
        );
        bytes32 from_hash = (bytes32)(
            (public_inputs[2] << 128) | ((public_inputs[3] << 128) >> 128)
        );

        uint256 start_index = from_left_index / 252;
        uint256 header_offset = from_left_index % 252;
        for (uint256 i = 0; i < from_len; i++) {
            if (header_offset >= 252) {
                start_index++;
                header_offset = 0;
            }

            // check header mask string
            require(
                (public_inputs[4 + start_index] >> (252 - header_offset - 1)) &
                    uint256(1) ==
                    uint256(1),
                "unmatch"
            );

            // check addr mask string
            require(
                (public_inputs[13] >> (192 - i - 1)) & uint256(1) == uint256(1),
                "unmatch"
            );

            header_offset++;
        }

        bytes32 header_pub_match_hash = (bytes32)(
            (public_inputs[14] << 128) | ((public_inputs[15] << 128) >> 128)
        );

        console.logBytes32(header_hash);
        console.logBytes32(from_hash);
        console.logBytes32(header_pub_match_hash);

        return (header_hash, from_hash, header_pub_match_hash);
    }

    function verifyV1024(
        uint256[] memory vkdata,
        uint256[] memory public_inputs,
        uint256[] memory serialized_proof
    ) public returns (bool) {
        uint64 num_inputs = uint64(public_inputs.length);
        bytes32 vkhash = sha256(
            abi.encodePacked(num_inputs, domain_size_1024, vkdata)
        );
        console.log("-- [SC] verifyV1024 > start");
        require(vk1024hash == vkhash, "E: wrong vkey");

        VerificationKey memory vk;
        vk.domain_size = domain_size_1024;
        vk.num_inputs = num_inputs;

        vk.omega = PairingsBn254.new_fr(vkdata[0]);

        uint256 j = 1;
        for (uint256 i = 0; i < STATE_WIDTH + 3 + 3; i++) {
            vk.selector_commitments[i] = PairingsBn254.new_g1_checked(
                vkdata[j],
                vkdata[j + 1]
            );
            j += 2;
        }
        console.log("-- [SC] verifyV1024 > selectors checked");

        for (uint256 i = 0; i < STATE_WIDTH; i++) {
            vk.permutation_commitments[i] = PairingsBn254.new_g1_checked(
                vkdata[j],
                vkdata[j + 1]
            );
            j += 2;
        }
        console.log("-- [SC] verifyV1024 > permutations checked");

        for (uint256 i = 0; i < STATE_WIDTH + 1; i++) {
            vk.tables_commitments[i] = PairingsBn254.new_g1_checked(
                vkdata[j],
                vkdata[j + 1]
            );
            j += 2;
        }
        console.log("-- [SC] verifyV1024 > tables checked");

        // q_substring0 q_substring_r0 q_pubmatch
        for (uint256 i = 0; i < 3; i++) {
            vk.selector_commitments[STATE_WIDTH + 3 + 3 + i] = PairingsBn254
                .new_g1_checked(vkdata[j], vkdata[j + 1]);
            j += 2;
        }
        console.log("-- [SC] verifyV1024 > substr selectors checked");

        uint256[2] memory tmpx;
        uint256[2] memory tmpy;

        tmpx[1] = vkdata[j];
        j += 1;
        tmpx[0] = vkdata[j];
        j += 1;
        tmpy[1] = vkdata[j];
        j += 1;
        tmpy[0] = vkdata[j];
        j += 1;
        vk.g2_x = PairingsBn254.new_g2(tmpx, tmpy);

        Proof memory proof = deserialize_proof(public_inputs, serialized_proof);
        console.log("-- [SC] verifyV1024 > proof deserialized");

        PartialVerifierState memory state;

        (bool res, PairingsBn254.Fr memory return_zeta_pow_n) = verify_initial(
            state,
            proof,
            vk,
            vkhash
        );
        if (res == false) {
            emit Verified(msg.sender, 1002);
            console.log("-- [SC] verifyV1024 > initialized failed");
            return false;
        }

        bool success = verify_commitments(return_zeta_pow_n, state, proof, vk);
        if (success) {
            emit Verified(msg.sender, 1);
            console.log("-- [SC] verifyV1024 > Verified");
        } else {
            emit Verified(msg.sender, 1001);
            console.log("-- [SC] verifyV1024 > Failed");
        }
        console.log("-- [SC] verifyV1024 > res =", res);

        return success;
    }

    function verifyV2048(
        uint256[] memory vkdata,
        uint256[] memory public_inputs,
        uint256[] memory serialized_proof
    ) public returns (bool) {
        uint64 num_inputs = uint64(public_inputs.length);
        bytes32 vkhash = sha256(
            abi.encodePacked(num_inputs, domain_size_2048, vkdata)
        );
        console.log("-- [SC] verifyV2048 > start");
        require(vk2048hash == vkhash, "E: wrong vkey");

        VerificationKey memory vk;
        vk.domain_size = domain_size_2048;
        vk.num_inputs = num_inputs;

        vk.omega = PairingsBn254.new_fr(vkdata[0]);

        uint256 j = 1;
        for (uint256 i = 0; i < STATE_WIDTH + 3 + 3; i++) {
            vk.selector_commitments[i] = PairingsBn254.new_g1_checked(
                vkdata[j],
                vkdata[j + 1]
            );
            j += 2;
        }

        console.log("-- [SC] verifyV2048 > selectors checked");

        for (uint256 i = 0; i < STATE_WIDTH; i++) {
            vk.permutation_commitments[i] = PairingsBn254.new_g1_checked(
                vkdata[j],
                vkdata[j + 1]
            );
            j += 2;
        }
        console.log("-- [SC] verifyV2048 > permutations checked");

        for (uint256 i = 0; i < STATE_WIDTH + 1; i++) {
            vk.tables_commitments[i] = PairingsBn254.new_g1_checked(
                vkdata[j],
                vkdata[j + 1]
            );
            j += 2;
        }
        console.log("-- [SC] verifyV2048 > tables checked");

        // q_substring0 q_substring_r0 q_pubmatch
        for (uint256 i = 0; i < 3; i++) {
            vk.selector_commitments[STATE_WIDTH + 3 + 3 + i] = PairingsBn254
                .new_g1_checked(vkdata[j], vkdata[j + 1]);
            j += 2;
        }
        console.log("-- [SC] verifyV2048 > substr selectors checked");

        uint256[2] memory tmpx;
        uint256[2] memory tmpy;

        tmpx[1] = vkdata[j];
        j += 1;
        tmpx[0] = vkdata[j];
        j += 1;
        tmpy[1] = vkdata[j];
        j += 1;
        tmpy[0] = vkdata[j];
        j += 1;
        vk.g2_x = PairingsBn254.new_g2(tmpx, tmpy);

        Proof memory proof = deserialize_proof(public_inputs, serialized_proof);

        console.log("-- [SC] verifyV2048 > proof deserialized");

        PartialVerifierState memory state;

        (bool res, PairingsBn254.Fr memory return_zeta_pow_n) = verify_initial(
            state,
            proof,
            vk,
            vkhash
        );
        if (res == false) {
            emit Verified(msg.sender, 1002);
            console.log("-- [SC] verifyV2048 > initialized failed");
            return false;
        }

        bool success = verify_commitments(return_zeta_pow_n, state, proof, vk);
        if (success) {
            emit Verified(msg.sender, 1);
            console.log("-- [SC] verifyV2048 > Verified");
        } else {
            emit Verified(msg.sender, 1001);
            console.log("-- [SC] verifyV2048 > Failed");
        }
        console.log("-- [SC] verifyV2048 > res =", res);

        return success;
    }

    function deserialize_proof(
        uint256[] memory public_inputs,
        uint256[] memory serialized_proof
    ) internal pure returns (Proof memory proof) {
        // require(serialized_proof.length == SERIALIZED_PROOF_LENGTH);
        proof.input_values = new uint256[](public_inputs.length);
        for (uint256 i = 0; i < public_inputs.length; i++) {
            proof.input_values[i] = public_inputs[i];
        }

        //witness 0123...
        uint256 j = 0;
        for (uint256 i = 0; i < STATE_WIDTH; i++) {
            proof.wire_commitments[i] = PairingsBn254.new_g1_checked(
                serialized_proof[j],
                serialized_proof[j + 1]
            );
            j += 2;
        }
        //s
        proof.sorted_lookup_commitment = PairingsBn254.new_g1_checked(
            serialized_proof[j],
            serialized_proof[j + 1]
        );
        j += 2;
        //z
        proof.grand_product_commitment = PairingsBn254.new_g1_checked(
            serialized_proof[j],
            serialized_proof[j + 1]
        );
        j += 2;
        //zlookup
        proof.grand_product_lookup_commitment = PairingsBn254.new_g1_checked(
            serialized_proof[j],
            serialized_proof[j + 1]
        );
        j += 2;
        //z_substring
        proof.z_substring_commitment = PairingsBn254.new_g1_checked(
            serialized_proof[j],
            serialized_proof[j + 1]
        );
        j += 2;
        //t123...
        for (uint256 i = 0; i < STATE_WIDTH; i++) {
            proof.quotient_poly_commitments[i] = PairingsBn254.new_g1_checked(
                serialized_proof[j],
                serialized_proof[j + 1]
            );
            j += 2;
        }

        //t(z)
        proof.quotient_polynomial_at_z = PairingsBn254.new_fr(
            serialized_proof[j]
        );
        j += 1;
        //r(z)
        proof.linearization_polynomial_at_z = PairingsBn254.new_fr(
            serialized_proof[j]
        );
        j += 1;
        //`w_0(z)`, `w_1(z)`, `w_2(z)`...
        for (uint256 i = 0; i < STATE_WIDTH; i++) {
            proof.wire_values_at_z[i] = PairingsBn254.new_fr(
                serialized_proof[j]
            );
            j += 1;
        }
        //`sigma_0(z)`, `sigma_1(z)`, `sigma_2(z)`...
        for (uint256 i = 0; i < STATE_WIDTH - 1; i++) {
            proof.permutation_polynomials_at_z[i] = PairingsBn254.new_fr(
                serialized_proof[j]
            );
            j += 1;
        }
        //`q_arith(z)`, `q_table(z)`, `q_lookup(z)`
        for (uint256 i = 0; i < 3; i++) {
            proof.some_selectors_at_z[i] = PairingsBn254.new_fr(
                serialized_proof[j]
            );
            j += 1;
        }
        // `table(z)`
        proof.table_at_z = PairingsBn254.new_fr(serialized_proof[j]);
        j += 1;

        //w0(zw)
        proof.wire0_at_z_omega = PairingsBn254.new_fr(serialized_proof[j]);
        j += 1;
        //z(zw)
        proof.grand_product_at_z_omega = PairingsBn254.new_fr(
            serialized_proof[j]
        );
        j += 1;
        //s(zw)
        proof.sorted_lookup_at_z_omega = PairingsBn254.new_fr(
            serialized_proof[j]
        );
        j += 1;
        //zlookup(zw)
        proof.grand_product_lookup_at_z_omega = PairingsBn254.new_fr(
            serialized_proof[j]
        );
        j += 1;
        //table(zw)
        proof.table_at_z_omega = PairingsBn254.new_fr(serialized_proof[j]);
        j += 1;
        //w1(zw)
        proof.wire1_at_z_omega = PairingsBn254.new_fr(serialized_proof[j]);
        j += 1;
        //w2(zw)
        proof.wire2_at_z_omega = PairingsBn254.new_fr(serialized_proof[j]);
        j += 1;
        //w3(zw)
        proof.wire3_at_z_omega = PairingsBn254.new_fr(serialized_proof[j]);
        j += 1;
        //z_substring(zw)
        proof.z_substring_at_z_omega = PairingsBn254.new_fr(
            serialized_proof[j]
        );
        j += 1;

        proof.opening_at_z_proof = PairingsBn254.new_g1_checked(
            serialized_proof[j],
            serialized_proof[j + 1]
        );
        j += 2;

        proof.opening_at_z_omega_proof = PairingsBn254.new_g1_checked(
            serialized_proof[j],
            serialized_proof[j + 1]
        );
    }
}
