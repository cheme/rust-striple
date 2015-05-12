//! striple kind combining rust-crypto primitive for ecdsa (ED25519) and key
//! representation or content signing hash as RIPEMD-160 of rsa key or original content.

extern crate crypto;
extern crate rand;



use std::fmt::Debug;
use std::marker::PhantomData;
use striple::SignatureScheme;
use striple::IDDerivation;
use striple::StripleKind;
use striple::PublicScheme;
use self::crypto::digest::Digest;
use self::crypto::ripemd160::Ripemd160;
use self::crypto::ed25519;
use std::io::Write;
use stripledata;
use self::rand::Rng;
use self::rand::thread_rng;

#[cfg(test)]
use striple::test::{test_striple_kind,chaining_test};

/// Key derivation using SHA-512
pub struct RIPEMD160KD;

/// key is same as signature (case where signature does not need to be serialize)
impl IDDerivation for RIPEMD160KD {
  /// id
  #[inline]
  fn derive_id(sig : &[u8]) -> Vec<u8> {
    // TODO len to 512 when test ok
    if sig.len() < 1 {
      Vec::new()
    } else {
      let mut digest = Ripemd160::new();
      hash_buf_crypto(sig, &mut digest)
    }
  }
}


#[derive(Debug,Clone)]
struct Ecdsa;

/// generic public signature scheme
impl SignatureScheme for Ecdsa {
  /// hash of content and from key (pri)
  fn sign_content(pri : &[u8], cont : &[u8]) -> Vec<u8> {
    let mut digest = Ripemd160::new();
    let chash = hash_buf_crypto(cont, &mut digest);
 
    let sig = ed25519::signature(&chash[..], pri).to_vec();
    sig
  }

  /// first parameter is public key, second is content and third is signature
  fn check_content(publ : &[u8], cont : &[u8], sign : &[u8]) -> bool {
    if sign.len() != 64 {
      false
    } else {
      let mut digest = Ripemd160::new();
      let chash = hash_buf_crypto(cont, &mut digest);

      ed25519::verify(&chash[..],publ,sign)
    }
  }

  /// create keypair (first is public, second is private)
  fn new_keypair() -> (Vec<u8>, Vec<u8>) {
    let seed = random_bytes(512);
    let (pr, pu) = ed25519::keypair(&seed[..]);
    (pu.to_vec(), pr.to_vec())
  }
}



#[derive(Debug,Clone)]
struct EcdsaRipemd160;

impl StripleKind for EcdsaRipemd160 {
  type D = RIPEMD160KD;
  type S = Ecdsa;
  fn get_algo_key() -> &'static [u8] {
    stripledata::ECDSARIPEMD160KEY
  }
}

#[test]
fn test_crypto() {
    let seed = random_bytes(512);
    let content = random_bytes(512);
    let (pr, pu) = ed25519::keypair(&seed[..]);
    let publkey = pu.to_vec();
    let prikey = pr.to_vec();
    let exch = ed25519::exchange(&publkey[..],&prikey[..]).to_vec();
    let sig = ed25519::signature(&content[..], &prikey[..]).to_vec();
    let result =  ed25519::verify(&content[..],&publkey[..],&sig[..]);
    println!("check res : {:?}", result);
    assert!(result);
}

/* TODO when lib basic fn works enable those test (see previous)
#[test]
fn test_ecdsripemd160kind(){
  // TODO key length to 160 when test with quickcheck
  test_striple_kind::<EcdsaRipemd160> (1, false);
}

#[test]
fn test_chaining() {
  chaining_test::<EcdsaRipemd160, EcdsaRipemd160> () 
}
*/
fn hash_buf_crypto(buff : &[u8], digest : &mut Digest) -> Vec<u8> {
  let bsize = digest.block_size();
  let bbytes = ((bsize+7)/8);
  let ressize = digest.output_bits();
  let outbytes = ((ressize+7)/8);
  debug!("{:?}:{:?}", bsize,ressize);
  let mut tmpvec : Vec<u8> = vec![0; bbytes];
  let buf = &mut tmpvec[..];

  let nbiter = if buff.len() == 0 {
      0
  }else {
    (buff.len() - 1) / bbytes
  };
  for i in (0 .. nbiter + 1) {
    let end = (i+1) * bbytes;
    if end < buff.len() {
      digest.input(&buff[i * bbytes .. end]);
    } else {
      digest.input(&buff[i * bbytes ..]);
    };
  };

  let mut rvec : Vec<u8> = vec![0; outbytes];
  let rbuf = &mut rvec[..];
  digest.result(rbuf);
  rbuf.to_vec()
}



fn random_bytes(size : usize) -> Vec<u8> {
   let mut rng = rand::thread_rng();
   let mut bytes = vec![0; size];
   rng.fill_bytes(&mut bytes[..]);
   bytes
}

