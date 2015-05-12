//! striple kind combining Openssl primitive for RSA 2048 and key
//! representation or content signing hash as SHA-512 of rsa key or original content.

extern crate openssl;

use std::fmt::Debug;
use std::marker::PhantomData;
use striple::SignatureScheme;
use striple::IDDerivation;
use striple::StripleKind;
use striple::PublicScheme;
use self::openssl::crypto::hash::{Hasher,Type};
use self::openssl::crypto::pkey::{PKey};
use std::io::Write;
use stripledata;

#[cfg(test)]
use striple::test::{test_striple_kind,chaining_test};

static RSA_SIZE : usize = 2048;
static HASH_SIGN : Type = Type::SHA512;

/// Key derivation using SHA-512
pub struct SHA512KD;

/// key is same as signature (case where signature does not need to be serialize)
impl IDDerivation for SHA512KD {
  /// id
  #[inline]
  fn derive_id(sig : &[u8]) -> Vec<u8> {
    // TODO len to 512 when test ok
    if sig.len() < 1 {
      Vec::new()
    } else {
      let mut digest = Hasher::new(HASH_SIGN);
      digest.write_all(sig);
      digest.finish()
    }
  }
}


#[derive(Debug,Clone)]
struct Rsa2048;

/// generic public signature scheme
impl SignatureScheme for Rsa2048 {
  /// hash of content and from key (pri)
  fn sign_content(pri : &[u8], cont : &[u8]) -> Vec<u8> {
    let mut pkey = PKey::new();
    pkey.load_priv(pri);
    let mut digest = Hasher::new(HASH_SIGN);
    digest.write_all(cont);
    pkey.sign_with_hash(&digest.finish()[..], HASH_SIGN)
  }

  /// first parameter is public key, second is content and third is signature
  fn check_content(publ : &[u8], cont : &[u8], sign : &[u8]) -> bool {
    let mut pkey = PKey::new();
    pkey.load_pub(publ);

    let mut digest = Hasher::new(HASH_SIGN);
    digest.write_all(cont);
    pkey.verify_with_hash(&digest.finish()[..], sign, HASH_SIGN)
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
struct Rsa2048Sha512;

impl StripleKind for Rsa2048Sha512 {
  type D = SHA512KD;
  type S = Rsa2048;
  fn get_algo_key() -> &'static [u8] {
    stripledata::RSA2048SHA512KEY 
  }
}

#[test]
fn test_rsa2048sha512kind(){
  // TODO key length to 512 when test with quickcheck
  test_striple_kind::<Rsa2048Sha512> (1, false);
}

#[test]
fn test_chaining() {
  chaining_test::<Rsa2048Sha512, Rsa2048Sha512> () 
}



