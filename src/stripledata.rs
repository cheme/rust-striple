


//! striple directly internally use by the api.
//! TODO multiple IDs
//! TODO loading full striple seems useless at this point : remove structs
//!
//! TODO change get_algo definition to include an index allowing more generic definition of id
//! loading and therefore additional anytype scheme in external libraries!!!
//!

use striple::Striple;
use striple::{StripleKind,NoKind};
use striple::{StripleIf};
use striple::{ref_builder_id_copy};
#[cfg(feature="serialize")]
use striple::{UnsafeOwnedStripleDisp};

use std::fs::File;
use storage::{FileStripleIterator,init_noread_key};
use std::env;

#[cfg(feature="serialize")]
use std::fmt::Result as FmtResult;
#[cfg(feature="serialize")]
use std::fmt::{Display,Formatter};

#[cfg(feature="opensslrsa")]
use rsa_openssl::Rsa2048Sha512;
#[cfg(not(feature="opensslrsa"))]
#[cfg(feature="cryptoecdsa")]
use ecdsa_crypto::EcdsaRipemd160;
#[cfg(not(feature="public_openssl"))]
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

pub static PUBRIPEMKEY : &'static [u8] = &[73, 90, 215, 66, 44, 149, 161, 92, 107, 78, 148, 106, 215, 87, 129, 116, 62, 244, 33, 236, 84, 165, 176, 116, 86, 238, 126, 181, 94, 238, 82, 100, 110, 190, 109, 151, 252, 33, 98, 195, 27, 70, 152, 140, 215, 64, 117, 233, 157, 106, 181, 231, 226, 0, 34, 102, 120, 171, 235, 157, 121, 114, 207, 98];
pub static PUBSHA512KEY : &'static [u8] = &[47, 72, 77, 220, 196, 219, 0, 90, 244, 218, 2, 142, 183, 206, 183, 196, 110, 227, 15, 151, 239, 9, 184, 102, 197, 90, 77, 34, 70, 188, 103, 215, 184, 203, 19, 34, 166, 179, 219, 105, 144, 15, 198, 9, 29, 197, 121, 127, 21, 13, 192, 134, 145, 222, 219, 31, 215, 40, 143, 114, 239, 39, 200, 16];
pub static PUBSHA256KEY : &'static [u8] = &[59, 240, 107, 33, 144, 162, 215, 253, 232, 129, 27, 205, 90, 155, 111, 24, 6, 28, 214, 191, 45, 246, 234, 193, 62, 27, 122, 24, 206, 2, 68, 75, 105, 6, 128, 160, 66, 106, 169, 42, 58, 248, 51, 193, 200, 207, 162, 112, 106, 167, 56, 144, 111, 62, 198, 100, 105, 139, 11, 241, 187, 162, 18, 78];
pub static RSA2048SHA512KEY : &'static [u8] = &[127, 167, 178, 248, 64, 157, 233, 139, 30, 84, 124, 56, 254, 241, 210, 136, 250, 200, 19, 181, 165, 0, 97, 125, 193, 101, 42, 146, 20, 72, 12, 3, 248, 130, 9, 25, 20, 89, 236, 225, 143, 194, 182, 198, 24, 107, 94, 69, 140, 17, 62, 186, 219, 73, 203, 255, 208, 106, 249, 117, 195, 120, 146, 10];
pub static ECDSARIPEMD160KEY : &'static [u8] = &[251, 114, 205, 46, 70, 161, 171, 177, 56, 170, 59, 8, 204, 229, 188, 224, 139, 16, 21, 57, 14, 247, 89, 116, 30, 97, 158, 236, 42, 57, 183, 61, 232, 205, 150, 170, 179, 75, 20, 165, 39, 140, 83, 167, 178, 188, 171, 118, 233, 65, 107, 89, 221, 13, 68, 27, 44, 186, 93, 82, 233, 175, 236, 25];

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
      let rit : Result<FileStripleIterator<NoKind,Striple<NoKind>,_,_,_>,_> = FileStripleIterator::init(datafile, ref_builder_id_copy , &init_noread_key, ());
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
