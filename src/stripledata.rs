


//! striple directly internally use by the api.
//! TODO multiple IDs
//! TODO loading full striple seems useless at this point : remove structs
//!

use striple::Striple;
use striple::{StripleKind,NoKind};
use striple::{StripleIf};
use striple::{OwnedStripleIf,UnsafeOwnedStripleDisp,ref_builder_id_copy};
use std::marker::PhantomData;

use std::fs::File;
use anystriple::{AnyStriple, copy_builder_any};
use storage::{FileStripleIterator,init_noread_key};
use std::io::Result as IOResult;
use std::env;

#[cfg(feature="serialize")]
use std::fmt::Result as FmtResult;
#[cfg(feature="serialize")]
use std::fmt::{Display,Formatter};

#[cfg(feature="opensslrsa")]
use rsa_openssl::Rsa2048Sha512;
#[cfg(feature="cryptoecdsa")]
use ecdsa_crypto::EcdsaRipemd160;
#[cfg(feature="public_crypto")]
use public::public_crypto::PubRipemd;
#[cfg(feature="public_openssl")]
use public::public_openssl::PubSha512;



  // TODO key in share location + true striple!!!
/// reference to base_striple of lib
#[derive(Debug,Clone)]
pub struct BaseStriples<K : StripleKind + Sized> {
  pub root : (Striple<K>, Vec<u8>),
  pub libcat : (Striple<K>, Vec<u8>),
  pub libkind : (Striple<K>, Vec<u8>),
}
#[derive(Debug,Clone)]
pub struct KindStriples<K : StripleKind + Sized>{
  pub kind : (Striple<K>, Vec<u8>),
  pub pubripemd : (Striple<K>, Vec<u8>),
  pub pubsha512 : (Striple<K>, Vec<u8>),
  pub pubsha256 : (Striple<K>, Vec<u8>),
  pub rsa2048_sha512 : (Striple<K>, Vec<u8>),
  pub ecdsaripemd160 : (Striple<K>, Vec<u8>),
}
#[derive(Debug,Clone)]
pub struct KindStriplesIDs {
  pub pubripemd : Vec<u8>,
  pub pubsha512 : Vec<u8>,
  pub pubsha256 : Vec<u8>,
  pub rsa2048_sha512 : Vec<u8>,
  pub ecdsaripemd160 : Vec<u8>,
}




#[cfg(feature="serialize")]
impl<K : StripleKind> Display for KindStriples<K> {
  fn fmt(&self, ftr : &mut Formatter) -> FmtResult {
    // TODO nice display in base64
    ftr.debug_struct("")
    .field("kind", &format!("{}",UnsafeOwnedStripleDisp(&self.kind)))
    .field("pubripemd", &format!("{}",UnsafeOwnedStripleDisp(&self.pubripemd)))
    .field("pubsha512", &format!("{}",UnsafeOwnedStripleDisp(&self.pubsha512)))
    .field("pubsha256", &format!("{}",UnsafeOwnedStripleDisp(&self.pubsha256)))
    .field("rsa2048_sha512", &format!("{}",UnsafeOwnedStripleDisp(&self.rsa2048_sha512)))
    .field("ecdsaripemd160", &format!("{}",UnsafeOwnedStripleDisp(&self.ecdsaripemd160)))
    .finish()
  }
}
#[cfg(feature="serialize")]
impl<K : StripleKind> Display for BaseStriples<K> {
  fn fmt(&self, ftr : &mut Formatter) -> FmtResult {
    // TODO nice display in base64
    ftr.debug_struct("")
    .field("root", &format!("{}",UnsafeOwnedStripleDisp(&self.root)))
    .field("libcategory", &format!("{}",UnsafeOwnedStripleDisp(&self.libcat)))
    .field("libkind", &format!("{}",UnsafeOwnedStripleDisp(&self.libkind)))
    .finish()
  }
}

#[cfg(feature="opensslrsa")]
lazy_static!{
pub static ref BASE : Option<BaseStriples<Rsa2048Sha512>> = init_base_striple();
pub static ref KIND : Option<KindStriples<Rsa2048Sha512>> = init_kind_striple();
}
#[cfg(not(feature="opensslrsa"))]
#[cfg(feature="cryptoecdsa")]
lazy_static!{
pub static ref BASE : Option<BaseStriples<EcdsaRipemd160>> = init_base_striple();
pub static ref KIND : Option<KindStriples<EcdsaRipemd160>> = init_kind_striple();
}
#[cfg(not(feature="opensslrsa"))]
#[cfg(not(feature="cryptoecdsa"))]
lazy_static!{
pub static ref BASE : Option<BaseStriples<NoKind>> = init_base_striple();
pub static ref KIND : Option<KindStriples<NoKind>> = init_kind_striple();
}

#[cfg(feature="public_openssl")]
lazy_static!{
pub static ref PUBKIND : Option<KindStriples<PubSha512>> = None;   
}
#[cfg(not(feature="public_openssl"))]
#[cfg(feature="public_crypto")]
lazy_static!{
pub static ref PUBKIND : Option<KindStriples<PubRipemd>> = None;
}
#[cfg(not(feature="public_openssl"))]
#[cfg(not(feature="public_crypto"))]
lazy_static!{
pub static ref PUBKIND : Option<KindStriples<NoKind>> = None;   
}

lazy_static!{
pub static ref KINDIDS : Option<KindStriplesIDs> = init_kind_striple_ids();
}

pub static PUBRIPEMKEY : &'static [u8] = &[128, 136, 74, 231, 134, 102, 111, 168, 123, 102, 154, 32, 53, 15, 250, 179, 54, 171, 54, 65, 184, 110, 152, 28, 84, 80, 17, 123, 79, 150, 127, 183, 17, 70, 236, 170, 236, 87, 252, 42, 15, 88, 218, 133, 203, 53, 151, 68, 175, 32, 221, 4, 68, 51, 208, 114, 235, 117, 1, 245, 2, 96, 25, 1];
pub static PUBSHA512KEY : &'static [u8] = &[88, 245, 150, 98, 43, 39, 41, 192, 133, 100, 60, 217, 26, 84, 198, 156, 232, 249, 118, 12, 248, 27, 218, 227, 234, 2, 180, 129, 35, 11, 121, 103, 2, 40, 60, 248, 53, 200, 121, 22, 18, 197, 194, 107, 114, 17, 210, 100, 36, 109, 179, 73, 84, 66, 27, 251, 16, 49, 253, 205, 61, 159, 64, 108];
pub static PUBSHA256KEY : &'static [u8] = &[122, 43, 209, 100, 41, 177, 153, 216, 58, 115, 121, 167, 37, 62, 227, 206, 8, 69, 210, 159, 206, 196, 58, 71, 132, 174, 233, 151, 91, 190, 132, 30, 188, 200, 108, 148, 169, 99, 23, 191, 46, 23, 9, 239, 236, 73, 179, 54, 223, 209, 109, 193, 72, 243, 227, 81, 209, 194, 155, 61, 67, 170, 43, 224];
pub static RSA2048SHA512KEY : &'static [u8] = &[86, 139, 16, 216, 242, 57, 38, 17, 66, 247, 128, 160, 222, 3, 60, 76, 108, 12, 64, 158, 237, 232, 35, 207, 98, 23, 159, 236, 165, 92, 25, 215, 133, 198, 73, 205, 35, 153, 182, 56, 222, 254, 251, 222, 168, 201, 235, 18, 10, 136, 251, 203, 47, 243, 58, 205, 83, 222, 251, 87, 111, 230, 74, 240];
pub static ECDSARIPEMD160KEY : &'static [u8] = &[45, 47, 149, 98, 71, 114, 204, 219, 38, 171, 163, 48, 251, 99, 44, 29, 103, 192, 30, 151, 244, 233, 229, 55, 61, 42, 114, 207, 78, 67, 246, 216, 77, 200, 42, 239, 90, 182, 25, 222, 198, 79, 182, 246, 223, 216, 168, 181, 181, 193, 252, 33, 51, 10, 167, 198, 82, 67, 111, 121, 187, 250, 221, 50];

/// init base striple from file in env var
pub fn init_base_striple<SK : StripleKind> () -> Option<BaseStriples<SK>> {
  None
}
/// init base striple from file in env var
pub fn init_kind_striple<SK : StripleKind> () -> Option<KindStriples<SK>> {
  None
}


/// init base striple from file in env var
pub fn init_kind_striple_ids () -> Option<KindStriplesIDs> {

  env::var("STRIPLE_BASE").ok().and_then(|path| match File::open(&path) {
    Ok(datafile) => {
      // get striple without key and without Kind (as we define it)
      let rit : IOResult<FileStripleIterator<NoKind,Striple<NoKind>,_,_,_>> = FileStripleIterator::init(datafile, ref_builder_id_copy , &init_noread_key, ());
      let res = rit.and_then(|mut it|{
        for _ in 0..6 {
          try!(it.skip_striple());
        };
        let pubripemd = it.next().unwrap().0.get_id().to_vec();
        let pubsha512 = it.next().unwrap().0.get_id().to_vec();
        let pubsha256 = it.next().unwrap().0.get_id().to_vec();
        let rsa2048_sha512 = it.next().unwrap().0.get_id().to_vec();
        let ecdsaripemd160 = it.next().unwrap().0.get_id().to_vec();

      Ok( KindStriplesIDs {
         pubripemd : pubripemd,
         pubsha512 : pubsha512,
         pubsha256 : pubsha256,
         rsa2048_sha512 : rsa2048_sha512,
         ecdsaripemd160 : ecdsaripemd160,
      })
      });
      res.ok()
    },
    Err(_) => {
      error!("File not available when loading env var STRIPLE_BASE file : {}", path);
      println!("File not available when loading env var STRIPLE_BASE file : {}", path);
      // TODO should we panic??
      None
    },
  })
}
