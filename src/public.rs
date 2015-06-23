//! Module for public striple usage. Those Striple could be use by anyone because the
//! signing/validation does not involve a private key.
//! Scheme combine unique id (to ensure different key for same content) and hash for key derivation.

extern crate uuid;
use self::uuid::Uuid;
use std::fmt::Debug;
use std::marker::PhantomData;
use striple::SignatureScheme;
use striple::PublicScheme;
use striple::Error;
use std::io::Read;

/// Technical trait
pub trait CHash : Debug + Clone {
  fn hash (from : &[u8], content : &mut Read) -> Vec<u8>;
  fn len () -> usize;
}

#[derive(Debug,Clone)]
pub struct PubSign<H : CHash>(PhantomData<H>);

/// generic public signature scheme
impl<H : CHash> SignatureScheme for PubSign<H> {
  /// hash of content and from key (pri)
  fn sign_content(pri : &[u8], cont : &mut Read) -> Result<Vec<u8>,Error> {
    Ok(H::hash(pri, cont))
  }

  /// first parameter is public key, second is content and third is signature
  fn check_content(publ : &[u8], cont : &mut Read, sig : &[u8]) -> bool {
    Self::sign_content(publ, cont).map(|s|s == sig).unwrap_or(false)
  }

  /// create keypair (first is public, second is private)
  /// TODO size shoud depend on hash length (num biguint?)
  fn new_keypair() -> (Vec<u8>, Vec<u8>) {
    let id = Uuid::new_v4().as_bytes().to_vec();
    (id.clone(),id)
  }
}


/// Public signature scheme are public
impl<H : CHash> PublicScheme for PubSign<H> {}


#[cfg(feature="public_crypto")]
pub mod public_crypto {
  extern crate crypto;
  use striple::{StripleKind,IdentityKD};
  use stripledata;
  use self::crypto::digest::Digest;
  use self::crypto::ripemd160::Ripemd160;
  use super::{PubSign,CHash};
  use std::io::Read;
  use std::io::Cursor;

  #[cfg(test)]
  use striple::test::{test_striple_kind,chaining_test};

  #[derive(Debug,Clone)]
  pub struct PubRipemd;

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

  fn hash(buff1 : &[u8], buff2 : &mut Read) -> Vec<u8> {
    let digest = Ripemd160::new();
    hash_crypto(buff1, buff2, digest)
  }
  // TODO test rand buff2 and 1 hash compare to their cat with empty buff
  fn len() -> usize {
    160
  }
  }

  fn hash_crypto<H : Digest>(buff1 : &[u8], buff2 : &mut Read, mut digest : H) -> Vec<u8> {
    let mut r = Cursor::new(buff1).chain(buff2);

    let bbytes = digest.block_size();
//    let bbytes = (bsize+7)/8;
    let ressize = digest.output_bits();
    let outbytes = (ressize+7)/8;
    debug!("{:?}:{:?}", bbytes,ressize);
 
    let mut vbuf = vec!(0;bbytes);
    let buff = &mut vbuf[..];
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

    //  digest.input(&buf[(nbiter -1)*bbytes .. ]);
    let mut rvec : Vec<u8> = vec![0; outbytes];
    let rbuf = &mut rvec;
    digest.result(rbuf);
    rbuf.to_vec()
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
  use self::openssl::crypto::hash::{Hasher,Type};
  use std::io::Write;
  use std::io::Read;
  use std::io::Cursor;
  #[cfg(test)]
  use striple::test::{test_striple_kind,chaining_test};
  use stripledata;
  use striple::{StripleKind,IdentityKD};
  use super::{PubSign,CHash};

 
fn hash_openssl(buff1 : &[u8], buff2 : &mut Read, typ : Type) -> Vec<u8> {
  //println!("{:?}",buff1);
  let mut r = Cursor::new(buff1).chain(buff2);
  let mut digest = Hasher::new(typ);
  let bbytes = typ.md_len();
  //println!("bufflen {:?}", bbytes);
  let mut vbuff = vec!(0;bbytes);
  let buff = &mut vbuff[..];
  loop {
    let end = r.read(buff).unwrap();
    if end == 0 {
      break
    };
    if end != bbytes {
     digest.write(&buff[0 .. end]).unwrap();
    } else {
      digest.write(buff).unwrap();
    };
  };
  digest.finish()
}

  #[derive(Debug,Clone)]
  pub struct PubRipemd;
  #[derive(Debug,Clone)]
  pub struct PubSha512;
  #[derive(Debug,Clone)]
  pub struct PubSha256;



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
    fn hash(buff1 : &[u8], buff2 : &mut Read) -> Vec<u8> {
      hash_openssl(buff1, buff2, Type::RIPEMD160)
    }
    fn len() -> usize {
      160
    }
  }
  impl CHash for Sha512 {
    fn hash(buff1 : &[u8], buff2 : &mut Read) -> Vec<u8> {
      hash_openssl(buff1, buff2, Type::SHA512)
    }
    fn len() -> usize {
      512
    }
  }
  impl CHash for Sha256 {
    fn hash(buff1 : &[u8], buff2 : &mut Read) -> Vec<u8> {
      hash_openssl(buff1, buff2, Type::SHA256)
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

