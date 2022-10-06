module my_addr::addr_aggregator {
   use aptos_framework::signer;
   use aptos_framework::block;
   use aptos_framework::timestamp;
   use std::vector;
   use my_addr::utils;
   use my_addr::eth_sig_verifier;
   use std::string::{Self, String};
   use aptos_std::aptos_hash;
   use std::bcs;
   use aptos_std::hash;
   use aptos_std::ed25519;

   //addr type enum
   const ADDR_TYPE_SECP256K1: u64 = 1;
   const ADDR_TYPE_ED25519: u64 = 2;

   //err enum
   const ERR_ADDR_INFO_MSG_EMPTY: u64 = 1001;
   const ERR_SIGNATURE_VERIFY_FAIL: u64 = 1002;
   const ERR_TIMESTAMP_EXCEED: u64 = 1003;

   const ERR_INVALID_ADR_TYPE: u64 = 200;
   const ERR_INVALID_SECP256K1_ADR: u64 = 201;  //secp256k1
   const ERR_INVALID_ED25519: u64 = 202;   //ed25519



   struct AddrInfo has store, copy, drop {
      addr: String,
      description: String,
      chain_name: String,
      msg: String,
      signature: vector<u8>,
      created_at: u64,
      updated_at: u64,
      id : u64,
      addr_type : u64,
   }

   struct AddrAggregator has key {
      key_addr: address,
      addr_infos: vector<AddrInfo>,
      max_id : u64,
   }

   public entry fun create_addr_aggregator(acct: &signer){
      let addr_aggr =  AddrAggregator{
         key_addr: signer::address_of(acct),
         addr_infos: vector::empty<AddrInfo>(),
         max_id : 0
      };
      move_to<AddrAggregator>(acct, addr_aggr);
   }

   public entry fun add_addr(acct: &signer, 
      addr_type: u64,
      addr: String, 
      chain_name: String,
      description: String) acquires AddrAggregator {
      // assert!(addr_type != ADDR_TYPE_SECP256K1 && addr_type != ADDR_TYPE_ED25519, ERR_INVALID_ADR_TYPE);

      if (addr_type == ADDR_TYPE_SECP256K1) {
         assert!(string::length(&addr) != 20, ERR_INVALID_SECP256K1_ADR)
      } else (
         assert!(string::length(&addr) != 32, ERR_INVALID_ED25519)
      );

      let addr_aggr = borrow_global_mut<AddrAggregator>(signer::address_of(acct));   
      let id = addr_aggr.max_id + 1;
      
      // gen msg
      let height = block::get_current_block_height();
      let msg = utils::u64_to_vec_u8_string(height);
      let msg_suffix = b".nonce_geek";
      vector::append(&mut msg, msg_suffix);

      let now = timestamp::now_seconds();
         
      let addr_info = AddrInfo{
         addr: addr, 
         chain_name: chain_name,
         description: description,
         signature: b"",
         msg: string::utf8(msg),
         created_at: now,
         updated_at: 0,
         id : id,
         addr_type: addr_type,
      };
      vector::push_back(&mut addr_aggr.addr_infos, addr_info);
      addr_aggr.max_id = addr_aggr.max_id + 1;
   }



   public fun get_msg(contract: address, addr: String) :String acquires AddrAggregator {
      let addr_aggr = borrow_global_mut<AddrAggregator>(contract);
      let length = vector::length(&mut addr_aggr.addr_infos);
      let i = 0;
    
      while (i < length) {
         let addr_info = vector::borrow_mut<AddrInfo>(&mut addr_aggr.addr_infos, i);
         if (addr_info.addr == addr) {
            return addr_info.msg
         };
         i = i + 1;
      };

      return string::utf8(b"")
   }

   public entry fun update_addr_with_sig(acct: &signer, 
      addr: String, signature : String) acquires AddrAggregator {
      let addr_aggr = borrow_global_mut<AddrAggregator>(signer::address_of(acct));
      let length = vector::length(&mut addr_aggr.addr_infos);
      let i = 0;
      while (i < length) {
         let addr_info = vector::borrow_mut<AddrInfo>(&mut addr_aggr.addr_infos, i);
         if (addr_info.addr == addr) {
            if (addr_info.msg == string::utf8(b"")) {
               abort 1001
            };

            // let sig = string::bytes(&signature);
            let sig_bytes = utils::string_to_vector_u8(&signature);

            // verify the signature for the msg 
            let addr_byte = *string::bytes(&addr);
            if (addr_info.addr_type == ADDR_TYPE_ED25519) {
               // verify the signature for the msg 
               let eth_prefix = b"\x19Ethereum Signed Message:\n";
               // let msg_length = vector::length(&addr_info.msg);
               let msg_length = string::length(&addr_info.msg);
               let sign_origin = vector::empty<u8>();
               vector::append(&mut sign_origin, eth_prefix);
               vector::append(&mut sign_origin, utils::u64_to_vec_u8_string(msg_length));
               vector::append(&mut sign_origin, *string::bytes(&addr_info.msg));
               let msg_hash = aptos_hash::keccak256(sign_origin); //kecacak256 hash 
               if (eth_sig_verifier::verify_eth_sig(sig_bytes, addr_byte, msg_hash)) {
                  abort 1002
               };
            };

            // verify the now - created_at <= 2h 
            let now = timestamp::now_seconds();
            if (now - addr_info.created_at > 2*60*60) {
               abort 1003
            };

            // update signature, updated_at 
            addr_info.signature = sig_bytes;
            addr_info.updated_at = now;
            break
         };
         i = i + 1;
      };
   }

   public entry fun update_addr_with_sig_and_pubkey(acct: &signer, 
      addr: String, signature : String, pubkey : String) acquires AddrAggregator {
      let addr_aggr = borrow_global_mut<AddrAggregator>(signer::address_of(acct));
      let length = vector::length(&mut addr_aggr.addr_infos);
      let i = 0;
      while (i < length) {
         let addr_info = vector::borrow_mut<AddrInfo>(&mut addr_aggr.addr_infos, i);
         if (addr_info.addr == addr) {
            if (addr_info.msg == string::utf8(b"")) {
               abort 1001
            };

            let sig_bytes = utils::string_to_vector_u8(&signature);
            let pubkey_bytes = utils::string_to_vector_u8(&pubkey);

            // let addr_byte = *string::bytes(&addr);
            if (addr_info.addr_type == ADDR_TYPE_ED25519) {
               // verify the signature for the msg 
               let msg_data = vector::empty<u8>();
               let prefix = b"APTOS::RawTransaction";
               let prefix_hash_bytes = hash::sha3_256(prefix);
               let msg_bytes =  bcs::to_bytes(&addr_info.msg);
               vector::append(&mut msg_data, prefix_hash_bytes);
               vector::append(&mut msg_data, msg_bytes);

               let pk = ed25519::new_validated_public_key_from_bytes(pubkey_bytes);
               let pk = std::option::extract(&mut pk);
               let pk = ed25519::public_key_into_unvalidated(pk);
               let sig = ed25519::new_signature_from_bytes(sig_bytes);

               if (!ed25519::signature_verify_strict(&sig, &pk, msg_data)) {
                  abort 1002
               };
            };

            // verify the now - created_at <= 2h 
            let now = timestamp::now_seconds();
            if (now - addr_info.created_at > 2*60*60) {
               abort 1003
            };

            // update signature, updated_at 
            addr_info.signature = sig_bytes;
            addr_info.updated_at = now;
            break
         };
         i = i + 1;
      };
   }

   // public fun delete addr
   public entry fun delete_addr(
      acct: signer,  
      addr: String) acquires AddrAggregator{
      let addr_aggr = borrow_global_mut<AddrAggregator>(signer::address_of(&acct));
      let length = vector::length(&mut addr_aggr.addr_infos);
      let i = 0;
      while (i < length) {
         let addr_info = vector::borrow(&mut addr_aggr.addr_infos, i);
         if (addr_info.addr == addr) {
            vector::remove(&mut addr_aggr.addr_infos, i);
            break
         };
         i = i + 1;
      }
   }
}