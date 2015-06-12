//! striple kind combining Openssl primitive for RSA 2048 and key
//! representation or content signing hash as SHA-512 of rsa key or original content.
//! PKCS#1 structure is used to encode key

extern crate openssl;

use striple::SignatureScheme;
use striple::IDDerivation;
use striple::StripleKind;
use self::openssl::crypto::hash::{Hasher,Type};
use self::openssl::crypto::pkey::{PKey};
use std::io::Write;
use std::io::Read;
use stripledata;

#[cfg(test)]
#[cfg(feature="public_openssl")]
use public::public_openssl::PubSha512;



#[cfg(test)]
use striple::test::{test_striple_kind,chaining_test};

static RSA_SIZE : usize = 2048;
static HASH_SIGN : Type = Type::SHA512;
static HASH_BYTE_SIZE : usize = 512 / 8;

/// Key derivation using SHA-512
pub struct SHA512KD;

/// key is same as signature (case where signature does not need to be serialize)
impl IDDerivation for SHA512KD {
  /// id
  #[inline]
  fn derive_id(sig : &[u8]) -> Vec<u8> {
    if sig.len() < 1 {
      Vec::new()
    } else {
      let mut digest = Hasher::new(HASH_SIGN);
      digest.write_all(sig).unwrap();
      digest.finish()
    }
  }
}


#[derive(Debug,Clone)]
pub struct Rsa2048;

/// generic public signature scheme
impl SignatureScheme for Rsa2048 {
  /// hash of content and from key (pri)
  fn sign_content(pri : &[u8], cont : &mut Read) -> Vec<u8> {
    let mut pkey = PKey::new();
    pkey.load_priv(pri);
    let mut digest = Hasher::new(HASH_SIGN);
    let mut vbuff = vec!(0;HASH_BYTE_SIZE);
    let buff = &mut vbuff[..];

    loop {
      let end = cont.read(buff).unwrap();
      if end == 0 {
         break
      };
      if end != HASH_BYTE_SIZE {
       digest.write(&buff[0 .. end]).unwrap();
      } else {
        digest.write(buff).unwrap();
      };
    };

    //digest.write_all(cont).unwrap();
    let tosig = digest.finish();
    //println!("TOSIG {:?} : {:?}",tosig.len(),tosig);
    pkey.sign_with_hash(&tosig, HASH_SIGN)
  }

  /// first parameter is public key, second is content and third is signature
  fn check_content(publ : &[u8], cont : &mut Read, sign : &[u8]) -> bool {
    let mut pkey = PKey::new();
    pkey.load_pub(publ);

    let mut digest = Hasher::new(HASH_SIGN);
    let mut vbuff = vec!(0;HASH_BYTE_SIZE);
    let buff = &mut vbuff[..];

    loop {
      let end = cont.read(buff).unwrap();
      if end == 0 {
          break
      };
      if end != HASH_BYTE_SIZE {
       digest.write(&buff[0 .. end]).unwrap();
      } else {
        digest.write(buff).unwrap();
      };
    };


//    digest.write_all(cont).unwrap();
    pkey.verify_with_hash(&digest.finish(), sign, HASH_SIGN)
  }

  /// create keypair (first is public, second is private)
  fn new_keypair() -> (Vec<u8>, Vec<u8>) {
    let mut pkey = PKey::new();
    pkey.gen(RSA_SIZE);

    let private = pkey.save_priv();
    let public  = pkey.save_pub();

    (public, private)
  }
}



#[derive(Debug,Clone)]
pub struct Rsa2048Sha512;

impl StripleKind for Rsa2048Sha512 {
  type D = SHA512KD;
  type S = Rsa2048;
  fn get_algo_key() -> &'static [u8] {
      match *stripledata::KINDIDS {
        Some (ref kinds) => {
          &kinds.rsa2048_sha512[..]
        },
        None => stripledata::RSA2048SHA512KEY,
      }
  }

}

#[test]
fn test_rsa2048sha512kind(){
  test_striple_kind::<Rsa2048Sha512> (256, false);
}

#[test]
fn test_chaining() {
  chaining_test::<Rsa2048Sha512, Rsa2048Sha512> () 
}


#[test]
#[cfg(feature="public_openssl")]
fn test_chaining_multi() {
  chaining_test::<Rsa2048Sha512, PubSha512> () 
}



