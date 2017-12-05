//! striple kind combining Openssl primitive for RSA 2048 and key
//! representation or content signing hash as SHA-512 of rsa key or original content.
//! PKCS#1 structure is used to encode key

extern crate openssl;

use striple::SignatureScheme;
use striple::IDDerivation;
use striple::StripleKind;
use striple::Error;
use striple::Result;
use striple::ErrorKind;
use anystriple::Rsa2048Sha512;
use self::openssl::hash::{Hasher,MessageDigest,hash2};
use self::openssl::pkey::{PKey};
use self::openssl::rsa::{Rsa};
use self::openssl::error::ErrorStack;
use self::openssl::sign::{
  Signer,
  Verifier,
};
use std::io::Write;
use std::io::Read;
use stripledata;

use anystriple::PubSha512;


#[cfg(test)]
use striple::test::{test_striple_kind,chaining_test};

static RSA_SIZE : u32 = 2048;

static HASH_BYTE_SIZE : usize = 512 / 8;


/// Key derivation using SHA-512
#[allow(dead_code)]
pub struct SHA512KD;

/// key is same as signature (case where signature does not need to be serialize)
impl IDDerivation for SHA512KD {
  /// id
  #[inline]
  fn derive_id(sig : &[u8]) -> Result<Vec<u8>> {
    Ok(if sig.len() < 1 {
      Vec::new()
    } else {
      hash2(MessageDigest::sha512(), sig)?.to_vec() // TODO use result
    })
  }
}


#[derive(Debug,Clone)]
pub struct Rsa2048;

/// generic public signature scheme
impl SignatureScheme for Rsa2048 {
  /// hash of content and from key (pri)
  fn sign_content(pri : &[u8], cont : &mut Read) -> Result<Vec<u8>> {
    // TODO rsa in struct ??
    let rsa = Rsa::private_key_from_der(pri)?;
    let mut digest = Hasher::new(MessageDigest::sha512())?;
    let mut vbuff = vec!(0;HASH_BYTE_SIZE);
    let buff = &mut vbuff[..];

    loop {
      let end = cont.read(buff)?;
      if end == 0 {
         break
      };
      if end != HASH_BYTE_SIZE {
        digest.update(&buff[0 .. end])?;
      } else {
        digest.update(buff)?;
      };
    };

    //digest.write_all(cont).unwrap();
    let tosig = digest.finish()?;
    //println!("TOSIG {:?} : {:?}",tosig.len(),tosig);
    // TODO might not need any more to hash beforehand !!!! TODO compare with java impl
    let pk = PKey::from_rsa(rsa)?;
    let mut s = Signer::new(MessageDigest::sha512(),&pk)?;
    s.write_all(&tosig)?;
    Ok(s.finish()?)
  }

  /// first parameter is public key, second is content and third is signature
  fn check_content(publ : &[u8], cont : &mut Read, sign : &[u8]) -> Result<bool> {

    let rsa = Rsa::public_key_from_der(publ)?;
    let mut digest = Hasher::new(MessageDigest::sha512())?;
    let mut vbuff = vec!(0;HASH_BYTE_SIZE);
    let buff = &mut vbuff[..];
    {
    loop {
      let end = cont.read(buff)?;
      if end == 0 {
        break
      };
      if end != HASH_BYTE_SIZE {
        digest.write(&buff[0 .. end])?;
      } else {
        digest.write(buff)?;
      };
    };
    }
    let pk = PKey::from_rsa(rsa)?;
    let mut ver = Verifier::new(MessageDigest::sha512(), &pk)?;

    let tosig = digest.finish()?;
    ver.write_all(&tosig)?;
    let r = ver.finish(sign)?;
    Ok(r)
    //res.map(|_| pkey.verify_with_hash(&digest.finish(), sign, MessageDigest::sha512())).unwrap_or(false)
  }

  /// create keypair (first is public, second is private)
  fn new_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
    // TODO store rsa directly!!!??
    let pkey = Rsa::generate(RSA_SIZE)?;

    let private = pkey.private_key_to_der()?;
    let public  = pkey.public_key_to_der()?;

    Ok((public, private))
  }
}




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



