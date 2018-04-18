//! Module for public striple usage. Those Striple could be use by anyone because the
//! signing/validation does not involve a private key.
//! Scheme combine unique id (to ensure different key for same content) and hash for key derivation.
extern crate rand;

use self::rand::{
  Rng,
  RngCore,
  thread_rng,
};
use std::fmt::Debug;
use std::marker::PhantomData;
use striple::SignatureScheme;
use striple::PublicScheme;
use striple::Error;
use striple::Result;
use std::io::Read;
use anystriple::PubRipemd;

/// Technical trait
pub trait CHash : Debug + Clone {
  fn hash (from : &[u8], content : &mut Read) -> Result<Vec<u8>>;
  fn len () -> usize;
}

#[derive(Debug,Clone)]
pub struct PubSign<H : CHash>(PhantomData<H>);

/// generic public signature scheme
impl<H : CHash> SignatureScheme for PubSign<H> {
  /// hash of content and from key (pri)
  fn sign_content(pri : &[u8], cont : &mut Read) -> Result<Vec<u8>> {
    H::hash(pri, cont)
  }

  /// first parameter is public key, second is content and third is signature
  fn check_content(publ : &[u8], cont : &mut Read, sig : &[u8]) -> Result<bool> {
    Ok(Self::sign_content(publ, cont)? == sig)
  }

  /// create keypair (first is public, second is private)
  /// TODO size shoud depend on hash length (num biguint?)
  fn new_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
    let mut rng = thread_rng();

    let mut bytes = [0; 16];
    rng.fill_bytes(&mut bytes);


//    let id = Uuid::new_v4().as_bytes().to_vec();
    Ok((bytes.to_vec(),bytes.to_vec()))
  }
}


/// Public signature scheme are public
impl<H : CHash> PublicScheme for PubSign<H> {}


#[cfg(feature="public_crypto")]
pub mod public_crypto {
  extern crate ripemd160;
  use striple::{StripleKind,IdentityKD,Result};
  use stripledata;
  use self::ripemd160::Digest;
  use self::ripemd160::Ripemd160;
  use super::{PubSign,CHash};
  use std::io::Read;
  use std::io::Cursor;
  use anystriple::PubRipemd;

  #[cfg(test)]
  use striple::test::{test_striple_kind,chaining_test};


  impl StripleKind for PubRipemd {
    type D = IdentityKD;
    type S = PubSign<Ripemd>;
    
    fn get_algo_key() -> &'static [u8] {
      match *stripledata::KINDIDS {
        Some (ref kinds) => {
          &kinds.pubripemd[..]
        },
        None => stripledata::PUBRIPEMKEY,
      }
    }
  }

  #[derive(Debug,Clone)]
  pub struct Ripemd;

  impl CHash for Ripemd {

    fn hash(buff1 : &[u8], buff2 : &mut Read) -> Result<Vec<u8>> {
      hash_crypto::<Ripemd160>(buff1, buff2)
    }
    fn len() -> usize {
      160
    }
  }

  fn hash_crypto<H : Digest>(buff1 : &[u8], buff2 : &mut Read) -> Result<Vec<u8>> {
    let mut r = Cursor::new(buff1).chain(buff2);
    let rvec = <H as Digest>::digest_reader(&mut r)?;
    Ok(rvec.to_vec())
  }
 
  #[test]
  fn test_pub_ripemdkind(){
    test_striple_kind::<PubRipemd> (20, true);
  }

  #[test]
  fn test_chaining() {
    chaining_test::<PubRipemd, PubRipemd> (); 
  }

}

#[cfg(feature="public_openssl")]
pub mod public_openssl {
  extern crate openssl;
  use self::openssl::hash::{Hasher,MessageDigest};
  use std::io::Write;
  use std::io::Read;
  use std::io::Cursor;
  #[cfg(test)]
  use striple::test::{test_striple_kind,chaining_test};
  use stripledata;
  use striple::{StripleKind,IdentityKD,Result};
  use super::{PubSign,CHash};
  use anystriple::PubRipemd;
  use anystriple::PubSha512;
  use anystriple::PubSha256;
 
fn hash_openssl(buff1 : &[u8], buff2 : &mut Read, typ : MessageDigest, blen : usize) -> Result<Vec<u8>> {
  //println!("{:?}",buff1);
  let mut r = Cursor::new(buff1).chain(buff2);
  let mut digest = Hasher::new(typ)?;
  //println!("bufflen {:?}", bbytes);
  let mut vbuff = vec!(0;blen);
  let buff = &mut vbuff[..];
  loop {
    let end = r.read(buff)?;
    if end == 0 {
      break
    };
    if end != blen {
     digest.write(&buff[0 .. end])?;
    } else {
      digest.write(buff)?;
    };
  };
  Ok(digest.finish()?.to_vec())
}




  #[cfg(not(feature="public_crypto"))]
  impl StripleKind for PubRipemd {
    type D = IdentityKD;
    type S = PubSign<Ripemd>;
    fn get_algo_key() -> &'static [u8] {
      match *stripledata::KINDIDS {
        Some (ref kinds) => {
          &kinds.pubripemd[..]
        },
        None => stripledata::PUBRIPEMKEY,
      }
    }
  }

  impl StripleKind for PubSha512 {
    type D = IdentityKD;
    type S = PubSign<Sha512>;
     fn get_algo_key() -> &'static [u8] {
      match *stripledata::KINDIDS {
        Some (ref kinds) => {
          &kinds.pubsha512[..]
        },
        None => stripledata::PUBSHA512KEY,
      }
    }

  }

  impl StripleKind for PubSha256 {
    type D = IdentityKD;
    type S = PubSign<Sha256>;
     fn get_algo_key() -> &'static [u8] {
      match *stripledata::KINDIDS {
        Some (ref kinds) => {
          &kinds.pubsha256[..]
        },
        None => stripledata::PUBSHA256KEY,
      }
    }

  }


  #[derive(Debug,Clone)]
  pub struct Ripemd;
  #[derive(Debug,Clone)]
  pub struct Sha512;
  #[derive(Debug,Clone)]
  pub struct Sha256;


  impl CHash for Ripemd {
    fn hash(buff1 : &[u8], buff2 : &mut Read) -> Result<Vec<u8>> {
      hash_openssl(buff1, buff2, MessageDigest::ripemd160(),Self::len()/8)
    }
    fn len() -> usize {
      160
    }
  }
  impl CHash for Sha512 {
    fn hash(buff1 : &[u8], buff2 : &mut Read) -> Result<Vec<u8>> {
      hash_openssl(buff1, buff2, MessageDigest::sha512(),Self::len()/8)
    }
    fn len() -> usize {
      512
    }
  }
  impl CHash for Sha256 {
    fn hash(buff1 : &[u8], buff2 : &mut Read) -> Result<Vec<u8>> {
      hash_openssl(buff1, buff2, MessageDigest::sha256(),Self::len()/8)
    }
    fn len() -> usize {
      256
    }
  }

  #[test]
  fn test_pub_ripemdkind() {
    test_striple_kind::<PubRipemd> (20, true);
  }

  #[test]
  fn test_pub_sha512kind() {
    test_striple_kind::<PubSha512> (64, true);
  }

  #[test]
  fn test_pub_sha256kind() {
    test_striple_kind::<PubSha256> (32, true);
  }

  #[test]
  fn test_chaining() {
    chaining_test::<PubSha256, PubSha512> () 
  }

}

