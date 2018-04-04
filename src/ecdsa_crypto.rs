//! striple kind combining rust-crypto primitive for ecdsa (ED25519) and key
//! representation or content signing hash as RIPEMD-160 of rsa key or original content.

//extern crate rand;
extern crate rand42_proxy as rand42;
extern crate rand;
extern crate sha2;
extern crate ed25519_dalek;
extern crate ripemd160;
use striple::SignatureScheme;
use striple::IDDerivation;
use striple::StripleKind;
use striple::Error;
use striple::ErrorKind;
use striple::Result;

use self::sha2::Sha512;
use self::ripemd160::Digest;
use self::ripemd160::Ripemd160;
use self::ed25519_dalek::{
  Keypair,
  PublicKey,
  Signature,
  DecodingError,
};
use stripledata;
use self::rand::Rng;
use self::rand::os::OsRng;
use self::rand42::Rng as Rng42;
use self::rand42::os::OsRng as OsRng42;
use std::io::Read;
use std::io::Cursor;
use anystriple::EcdsaRipemd160;

#[cfg(test)]
use anystriple::PubRipemd;

#[cfg(test)]
use striple::test::{test_striple_kind,chaining_test};

/// Key derivation using ripemd160
pub struct RIPEMD160KD;

/// key is same as signature (case where signature does not need to be serialize)
impl IDDerivation for RIPEMD160KD {
  const EXPECTED_SIZE : Option<usize> = Some(160/8);
  /// id
  #[inline]
  fn derive_id(sig : &[u8]) -> Result<Vec<u8>> {
    // TODO len to 512 when test ok
    if sig.len() < 1 {
      Ok(Vec::new())
    } else {
      hash_buf_crypto::<Ripemd160>(&mut Cursor::new(sig))
    }
  }
}

impl From<DecodingError> for Error {
  fn from(de : DecodingError) -> Self {
    Error(format!("Ed25519 : {}",de),ErrorKind::DecodingError,None)
  }
}
#[derive(Debug,Clone)]
pub struct Ecdsa;

/// generic public signature scheme
impl SignatureScheme for Ecdsa {
  /// hash of content and from key (pri)
  fn sign_content(pri : &[u8], cont : &mut Read) -> Result<Vec<u8>> {
    let chash = hash_buf_crypto::<Ripemd160>(cont)?;

    let kp = Keypair::from_bytes(pri)?;
 
    let sig = kp.sign::<Sha512>(&chash[..]).to_bytes();
    Ok(sig.to_vec())
  }

  /// first parameter is public key, second is content and third is signature
  fn check_content(publ : &[u8], cont : &mut Read, sign : &[u8]) -> Result<bool> {
    Ok(if sign.len() != 64 {
      false
    } else {
      let chash = hash_buf_crypto::<Ripemd160>(cont)?;

      let kp = PublicKey::from_bytes(publ)?;
      let sig = Signature::from_bytes(sign)?;
      kp.verify::<Sha512>(&chash[..],&sig)
    })
  }

  /// create keypair (first is public, second is private)
  fn new_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
   // let seed = sec_random_bytes(32);
    let mut cspring: OsRng42 = OsRng42::new().unwrap();
    let keypair: Keypair = Keypair::generate::<Sha512>(&mut cspring);
    //let (pr, pu) = ed25519::keypair(&seed);
    Ok((keypair.public.to_bytes().to_vec(), keypair.to_bytes().to_vec()))
  }
}

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
/*
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
}*/

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


#[inline]
fn hash_buf_crypto<D : Digest>(r : &mut Read) -> Result<Vec<u8>> {
  let rvec = <D as Digest>::digest_reader(r)?;
  Ok(rvec.to_vec())
}


/*fn sec_random_bytes(size : usize) -> Vec<u8> {
   let mut bytes = vec![0; size];
   rng.fill(&mut bytes[..]);
   bytes
}*/

#[cfg(test)]
fn random_bytes(size : usize) -> Vec<u8> {
   let mut rng = rand::thread_rng();
   let mut bytes = vec![0; size];
   rng.fill(&mut bytes[..]);
   bytes
}

