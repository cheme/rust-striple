//! striple kind combining rust-crypto primitive for ecdsa (ED25519) and key
//! representation or content signing hash as RIPEMD-160 of rsa key or original content.

extern crate crypto;
extern crate rand;

use striple::SignatureScheme;
use striple::IDDerivation;
use striple::StripleKind;
use striple::Error;
use self::crypto::digest::Digest;
use self::crypto::ripemd160::Ripemd160;
use self::crypto::ed25519;
use stripledata;
use self::rand::Rng;
use self::rand::os::OsRng;
use std::io::Read;
use std::io::Cursor;

#[cfg(test)]
#[cfg(feature="public_crypto")]
use public::public_crypto::PubRipemd;

#[cfg(test)]
use striple::test::{test_striple_kind,chaining_test};

/// Key derivation using SHA-512
#[allow(dead_code)]
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
      hash_buf_crypto(&mut Cursor::new(sig), &mut digest)
    }
  }
}


#[derive(Debug,Clone)]
pub struct Ecdsa;

/// generic public signature scheme
impl SignatureScheme for Ecdsa {
  /// hash of content and from key (pri)
  fn sign_content(pri : &[u8], cont : &mut Read) -> Result<Vec<u8>,Error> {
    let mut digest = Ripemd160::new();
    let chash = hash_buf_crypto(cont, &mut digest);
 
    let sig = ed25519::signature(&chash, pri).to_vec();
    Ok(sig)
  }

  /// first parameter is public key, second is content and third is signature
  fn check_content(publ : &[u8], cont : &mut Read, sign : &[u8]) -> bool {
    if sign.len() != 64 {
      false
    } else {
      let mut digest = Ripemd160::new();
      let chash = hash_buf_crypto(cont, &mut digest);

      ed25519::verify(&chash,publ,sign)
    }
  }

  /// create keypair (first is public, second is private)
  fn new_keypair() -> (Vec<u8>, Vec<u8>) {
    let seed = sec_random_bytes(32);
    let (pr, pu) = ed25519::keypair(&seed);
    (pu.to_vec(), pr.to_vec())
  }
}



#[derive(Debug,Clone)]
pub struct EcdsaRipemd160;

impl StripleKind for EcdsaRipemd160 {
  type D = RIPEMD160KD;
  type S = Ecdsa;
  fn get_algo_key() -> &'static [u8] {
      match *stripledata::KINDIDS {
        Some (ref kinds) => {
          &kinds.ecdsaripemd160[..]
        },
        None => stripledata::ECDSARIPEMD160KEY,
      }
  }


}

#[test]
fn test_crypto() {
    let seed = random_bytes(32);
//    let seed = [0x26, 0x27, 0xf6, 0x85, 0x97, 0x15, 0xad, 0x1d, 0xd2, 0x94, 0xdd, 0xc4, 0x76, 0x19, 0x39, 0x31,
 //                   0xf1, 0xad, 0xb5, 0x58, 0xf0, 0x93, 0x97, 0x32, 0x19, 0x2b, 0xd1, 0xc0, 0xfd, 0x16, 0x8e, 0x4e];
    let content = random_bytes(512);
    let (pr, pu) = ed25519::keypair(&seed);
    let sig = ed25519::signature(&content, &pr);
    let result =  ed25519::verify(&content,&pu, &sig);
    assert!(result);
}

#[test]
fn test_ecdsripemd160kind(){
  test_striple_kind::<EcdsaRipemd160> (64, false);
}

#[test]
fn test_chaining() {
  chaining_test::<EcdsaRipemd160, EcdsaRipemd160> () 
}


#[test]
#[cfg(feature="public_crypto")]
fn test_chaining_multi() {
  chaining_test::<PubRipemd, EcdsaRipemd160> () 
}



fn hash_buf_crypto(r : &mut Read, digest : &mut Digest) -> Vec<u8> {
  let bsize = digest.block_size();
  let bbytes = (bsize+7)/8;
  let ressize = digest.output_bits();
  let outbytes = (ressize+7)/8;
  debug!("{:?}:{:?}", bsize,ressize);

  let mut vbuff = vec![0;bbytes];
  let buff = &mut vbuff[..];

  loop {
    let end = r.read(buff).unwrap();
    if end == 0 {
          break
    };
    if end != bbytes {
     digest.input(&buff[0 .. end]);
    } else {
      digest.input(buff);
    };
  };

  let mut rvec : Vec<u8> = vec![0; outbytes];
  let rbuf = &mut rvec;
  digest.result(rbuf);
  rbuf.to_vec()
}


fn sec_random_bytes(size : usize) -> Vec<u8> {
   let mut rng = OsRng::new().unwrap();
   let mut bytes = vec![0; size];
   rng.fill_bytes(&mut bytes[..]);
   bytes
}

#[cfg(test)]
fn random_bytes(size : usize) -> Vec<u8> {
   let mut rng = rand::thread_rng();
   let mut bytes = vec![0; size];
   rng.fill_bytes(&mut bytes[..]);
   bytes
}

