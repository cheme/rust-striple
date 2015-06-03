//! Module for public striple usage. Those Striple could be use by anyone because the
//! signing/validation does not involve a private key.
//! Scheme combine unique id (to ensure different key for same content) and hash for key derivation.

extern crate uuid;
use self::uuid::Uuid;
use std::fmt::Debug;
use std::marker::PhantomData;
use striple::SignatureScheme;
use striple::PublicScheme;

/// Technical trait
pub trait CHash : Debug + Clone {
  fn hash (from : &[u8], content : &[u8]) -> Vec<u8>;
  fn len () -> usize;
}

#[derive(Debug,Clone)]
pub struct PubSign<H : CHash>(PhantomData<H>);

/// generic public signature scheme
impl<H : CHash> SignatureScheme for PubSign<H> {
  /// hash of content and from key (pri)
  fn sign_content(pri : &[u8], cont : &[u8]) -> Vec<u8> {
    H::hash(pri, cont)
  }

  /// first parameter is public key, second is content and third is signature
  fn check_content(publ : &[u8],cont : &[u8],sig : &[u8]) -> bool {
    Self::sign_content(publ, cont) == sig
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
  use stripledata::PUBRIPEMKEY;
  use self::crypto::digest::Digest;
  use self::crypto::ripemd160::Ripemd160;
  use super::{PubSign,CHash};

  #[cfg(test)]
  use striple::test::{test_striple_kind,chaining_test};

  #[derive(Debug,Clone)]
  pub struct PubRipemd;

  impl StripleKind for PubRipemd {
    type D = IdentityKD;
    type S = PubSign<Ripemd>;
    
    fn get_algo_key() -> &'static [u8] {
      PUBRIPEMKEY
    }
  }

  #[derive(Debug,Clone)]
  pub struct Ripemd;

  impl CHash for Ripemd {

  fn hash(buff1 : &[u8], buff2 : &[u8]) -> Vec<u8> {
    let digest = Ripemd160::new();
    hash_crypto(buff1, buff2, digest)
  }
  // TODO test rand buff2 and 1 hash compare to their cat with empty buff
  fn len() -> usize {
    160
  }
  }

  fn hash_crypto<H : Digest>(buff1 : &[u8], buff2 : &[u8], mut digest : H) -> Vec<u8> {
    let bsize = digest.block_size();
    let bbytes = (bsize+7)/8;
    let ressize = digest.output_bits();
    let outbytes = (ressize+7)/8;
    debug!("{:?}:{:?}", bsize,ressize);
    let mut tmpvec = Vec::new();
    let nbiter1 = (buff1.len() -1) / bbytes;
    for i in (0 .. nbiter1) {
      let end = (i+1) * bbytes;
      if end < buff1.len() {
        digest.input(&buff1[i * bbytes .. end]);
      } else {
        digest.input(&buff1[i * bbytes ..]);
      };
    };
    tmpvec.push_all(&buff1[(nbiter1) * bbytes..]);
    let adj = bbytes - tmpvec.len();
    tmpvec.push_all(&buff2[0 .. adj]);
    digest.input(&tmpvec);

    let bufff2 = &buff2[adj..];
    let nbiter2 = if bufff2.len() == 0 {
      0
    }else {
      (bufff2.len() - 1) / bbytes
    };
    for i in (0 .. nbiter2 + 1) {
      let end = (i+1) * bbytes;
      if end < bufff2.len() {
        digest.input(&bufff2[i * bbytes .. end]);
      } else {
        digest.input(&bufff2[i * bbytes ..]);
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
  #[cfg(test)]
  use striple::test::{test_striple_kind,chaining_test};
  use stripledata;
  use striple::{StripleKind,IdentityKD};
  use super::{PubSign,CHash};



fn hash_openssl(buf1 : &[u8], buf2 : &[u8], typ : Type) -> Vec<u8> {
  let mut digest = Hasher::new(typ);
  digest.write_all(buf1).unwrap();
  digest.write_all(buf2).unwrap();
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
    fn hash(buff1 : &[u8], buff2 : &[u8]) -> Vec<u8> {
      hash_openssl(buff1, buff2, Type::RIPEMD160)
    }
    fn len() -> usize {
      160
    }
  }
  impl CHash for Sha512 {
    fn hash(buff1 : &[u8], buff2 : &[u8]) -> Vec<u8> {
      hash_openssl(buff1, buff2, Type::SHA512)
    }
    fn len() -> usize {
      512
    }
  }
  impl CHash for Sha256 {
    fn hash(buff1 : &[u8], buff2 : &[u8]) -> Vec<u8> {
      hash_openssl(buff1, buff2, Type::SHA256)
    }
    fn len() -> usize {
      256
    }
  }

  #[test]
  fn test_pub_ripemdkind(){
    test_striple_kind::<PubRipemd> (20, true);
  }

  #[test]
  fn test_pub_sha512kind(){
    test_striple_kind::<PubSha512> (64, true);
  }

  #[test]
  fn test_pub_sha256kind(){
    test_striple_kind::<PubSha256> (32, true);
  }

  #[test]
  fn test_chaining() {
    chaining_test::<PubSha256, PubSha512> () 
  }

}

