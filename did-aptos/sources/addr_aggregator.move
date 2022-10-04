module my_addr::addr_aggregator {
   use aptos_framework::signer;
   use aptos_framework::block;
   use aptos_framework::timestamp;
   use std::vector;
   use my_addr::utils;
   // use my_addr::eth_sig_verifier;
   // use aptos_framework::bcs;
   use std::string::{Self, String};

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
      signature: String,
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
      assert!(addr_type != ADDR_TYPE_SECP256K1 && addr_type != ADDR_TYPE_ED25519, ERR_INVALID_ADR_TYPE);

      if (addr_type == ADDR_TYPE_SECP256K1) {
         assert!(string::length(&addr) == 20, ERR_INVALID_SECP256K1_ADR)
      } else (
         assert!(string::length(&addr) == 32, ERR_INVALID_ED25519)
      );

      let addr_aggr = borrow_global_mut<AddrAggregator>(signer::address_of(acct));   
      let id = addr_aggr.max_id + 1;
      
      let height = block::get_current_block_height();

      let msg = utils::u64_to_vec_u8(height);
      let now = timestamp::now_seconds();
         
      let addr_info = AddrInfo{
         addr: addr, 
         chain_name: chain_name,
         description: description,
         signature: string::utf8(b""),
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

            // // verify the signature for the msg 
            // let addr_byte = bcs::to_bytes(&addr);
            // if (addr_info.addr_type == ADDR_TYPE_SECP256K1) {
            //     if (eth_sig_verifier::verify_eth_sig(signature, addr_byte, addr_info.msg)) {
            //          abort 1002
            //       };
            // }else{
            //    //Todo: modify to ed25519 verify 
            //    if (eth_sig_verifier::verify_eth_sig(signature, addr_byte, addr_info.msg)) {
            //          abort 1002
            //    };
            // };

            // verify the now - created_at <= 2h 
            let now = timestamp::now_seconds();
            if (now - addr_info.created_at > 2*60*60) {
               abort 1003
            };

            // update signature, updated_at 
            addr_info.signature = signature;
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