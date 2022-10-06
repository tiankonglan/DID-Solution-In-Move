module my_addr::eth_sig_verifier {
    // use aptos_std::hash;
    use aptos_std::secp256k1;
    use aptos_std::aptos_hash;
    use std::vector;
    #[test_only]
    use my_addr::utils;
    #[test_only]
    use std::debug;
    #[test_only]
    use std::string;

    fun pubkey_to_address(pk_bytes : vector<u8>) : vector<u8>{
        // let length = vector::length(&pk_bytes);
        // debug::print(&length);
        // if (vector::length(&pk_bytes) != 33 && (vector::length(&pk_bytes)-2) % 32 != 0) {
        //     // common_pubkey_length: length(pk_bytes + 0x00) must be 33.
        //     // multi_pubkey_length: length(pk_bytes - k - 0x01) % 32 must be 0.
        //     abort 1003
        // };
        // debug::print(&pk_bytes);
        // vector::remove(&mut pk_bytes, 0); //
        let data = aptos_hash::keccak256(pk_bytes);
        // let data_length = vector::length(&data); //32 bytes length
        // debug::print(&data_length);
        let result = vector::empty<u8>();
        
        let i = 12;
        while (i < 32) {
            let v  = vector::borrow(&data, i);
            vector::push_back(&mut result, *v);
            i=i+1
        };
        // debug::print(&result);
        result
    }

   public fun verify_eth_sig(signature: vector<u8>, addr: vector<u8>, message: vector<u8>) : bool{
        let signature_length = vector::length(&signature);
        // debug::print(&signature_length);
        // debug::print(&signature);
        assert!(signature_length == 65, 3001);

        let recovery_byte = vector::remove(&mut signature, signature_length - 1);
        // assert!(recovery_byte == 27 || recovery_byte = 28, 3002);

        let recovery_id = 0;
        if (recovery_byte == 28) {
            recovery_id  = 1
        };

        let ecdsa_signature = secp256k1::ecdsa_signature_from_bytes(signature);
        let pk = secp256k1::ecdsa_recover(message, recovery_id, &ecdsa_signature);
        assert!(std::option::is_some(&pk), 1);

        let public_key = std::option::borrow(&pk);
        // assert!(std::option::extract(&mut pk).bytes == x"4646ae5047316b4230d0086c8acec687f00b1cd9d1dc634f6cb358ac0a9a8ffffe77b4dd0a4bfb95851f3b7355c781dd60f8418fc8a65d14907aff47c903a559", 1);
        let pk_bytes = secp256k1::ecdsa_raw_public_key_to_bytes(public_key);
        let origin_addr = pubkey_to_address(pk_bytes);
        if (origin_addr == addr) {
            return true
        };

        false
   }

    #[test]
    public fun verify_eth_sig_test(){
        // let signature = x"90a938f7457df6e8f741264c32697fc52f9a8f867c52dd70713d9d2d472f2e415d9c94148991bbe1f4a1818d1dff09165782749c877f5cf1eff4ef126e55714d1c";
        // let msg_hash = x"b453bd4e271eed985cbab8231da609c4ce0a9cf1f763b6c1594e76315510e0f1";
        // let address_bytes = x"29c76e6ad8f28bb1004902578fb108c507be341b";

        let msg = b"0a.nonce_geek";
        let eth_prefix = b"\x19Ethereum Signed Message:\n";
        let msg_length = vector::length(&msg);
        let sign_origin = vector::empty<u8>();
        
        vector::append(&mut sign_origin, eth_prefix);
        vector::append(&mut sign_origin, utils::u64_to_vec_u8_string(msg_length));
        vector::append(&mut sign_origin, msg);
        let msg_hash = aptos_hash::keccak256(copy sign_origin); 
        // debug::print(&sign_origin);
        // debug::print(&msg_hash);
        // let signature = x"6f90301664e3cfda973d4d56067289110a08feb0eca78cc1598a8b992ba9d80f2f77bfe7673c16ec49b81955cf6e1d900aa6fc371bc075a98e8d588fe165c2e61b";
        // let signature = x"6f90301664e3cfda973d4d56067289110a08feb0eca78cc1598a8b992ba9d80f2f77bfe7673c16ec49b81955cf6e1d900aa6fc371bc075a98e8d588fe165c2e61b";
        let str = string::utf8(b"6f90301664e3cfda973d4d56067289110a08feb0eca78cc1598a8b992ba9d80f2f77bfe7673c16ec49b81955cf6e1d900aa6fc371bc075a98e8d588fe165c2e61b");
        let address_bytes = x"14791697260e4c9a71f18484c9f997b308e59325";

        // from_bsc::to_u8(*string::bytes(&str))
        let sig = utils::string_to_vector_u8(&str);
       
        
        // assert!(verify_eth_sig(signature, address_bytes, msg_hash), 101);
        // assert!(verify_eth_sig(*string::bytes(&str), address_bytes, msg_hash), 101);
        assert!(verify_eth_sig(sig, address_bytes, msg_hash), 101);
    }
}