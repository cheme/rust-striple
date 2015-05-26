


//! striple directly internally use by the api.
//! TODO load from conf and true val

use striple::Striple;
use striple::{StripleKind,NoKind};
use striple::{StripleIf};
use striple::{OwnedStripleIf,UnsafeOwnedStripleDisp};
use std::marker::PhantomData;

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
  pub rsa2048Sha512 : (Striple<K>, Vec<u8>),
  pub ecdsaripemd160 : (Striple<K>, Vec<u8>),
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
    .field("rsa2048Sha512", &format!("{}",UnsafeOwnedStripleDisp(&self.rsa2048Sha512)))
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
pub static ref BASE : Option<BaseStriples<Rsa2048Sha512>> = None;   
pub static ref KIND : Option<KindStriples<Rsa2048Sha512>> = None;
}
#[cfg(not(feature="opensslrsa"))]
#[cfg(feature="cryptoecdsa")]
lazy_static!{
pub static ref BASE : Option<BaseStriples<EcdsaRipemd160>> = None;
pub static ref KIND : Option<KindStriples<EcdsaRipemd160>> = None;
}
#[cfg(not(feature="opensslrsa"))]
#[cfg(not(feature="cryptoecdsa"))]
lazy_static!{
pub static ref BASE : Option<BaseStriples<NoKind>> = None;   
pub static ref KIND : Option<KindStriples<NoKind>> = None;   
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

pub static PUBRIPEMKEY : &'static [u8] = &[253, 225, 57, 162, 221, 187, 133, 50, 66, 142, 220, 128, 84, 161, 21, 210, 86, 43, 15, 31, 215, 8, 198, 120, 215, 113, 180, 92, 108, 82, 176, 20, 24, 134, 189, 41, 129, 232, 11, 196, 65, 14, 178, 134, 74, 138, 82, 202, 11, 60, 57, 59, 22, 61, 47, 170, 244, 220, 134, 247, 210, 240, 201, 187];
pub static PUBSHA512KEY : &'static [u8] = &[47, 245, 12, 2, 143, 49, 58, 142, 237, 239, 215, 127, 38, 136, 87, 30, 37, 237, 107, 175, 50, 44, 62, 57, 3, 160, 11, 129, 186, 101, 173, 10, 46, 186, 109, 158, 174, 87, 254, 175, 178, 85, 12, 134, 242, 183, 188, 11, 6, 125, 197, 241, 10, 3, 242, 166, 208, 81, 4, 184, 24, 167, 66, 79];
pub static PUBSHA256KEY : &'static [u8] = &[60, 141, 19, 108, 7, 228, 63, 219, 215, 78, 123, 9, 95, 155, 136, 124, 84, 111, 105, 6, 92, 33, 245, 189, 160, 190, 119, 202, 202, 40, 118, 49, 248, 87, 41, 215, 182, 207, 202, 189, 193, 66, 229, 223, 110, 82, 67, 135, 164, 62, 242, 110, 144, 129, 72, 33, 209, 27, 29, 222, 98, 62, 130, 186];
pub static RSA2048SHA512KEY : &'static [u8] = &[188, 67, 9, 228, 219, 111, 146, 89, 142, 193, 199, 232, 3, 246, 31, 145, 255, 202, 52, 184, 111, 192, 91, 129, 95, 203, 40, 138, 65, 104, 90, 70, 78, 36, 83, 84, 69, 136, 249, 169, 94, 91, 63, 149, 77, 56, 41, 99, 33, 63, 82, 186, 236, 129, 58, 163, 104, 156, 103, 136, 154, 240, 142, 69];
pub static ECDSARIPEMD160KEY : &'static [u8] = &[52, 118, 150, 110, 121, 229, 135, 47, 95, 100, 91, 167, 25, 37, 146, 209, 80, 178, 114, 107, 16, 219, 65, 145, 96, 98, 204, 220, 162, 20, 97, 186, 212, 150, 35, 162, 20, 10, 124, 249, 134, 207, 131, 173, 12, 116, 131, 8, 43, 5, 253, 135, 186, 151, 77, 190, 171, 239, 185, 93, 81, 36, 240, 106];

