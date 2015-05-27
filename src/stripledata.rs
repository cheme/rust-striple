


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

pub static PUBRIPEMKEY : &'static [u8] = &[131, 158, 16, 201, 240, 160, 172, 224, 207, 159, 116, 31, 191, 198, 192, 43, 78, 171, 24, 180, 183, 201, 237, 71, 217, 232, 249, 144, 77, 225, 41, 10, 157, 59, 145, 101, 235, 154, 95, 136, 216, 72, 65, 99, 200, 52, 20, 120, 20, 65, 60, 84, 178, 127, 141, 106, 196, 126, 36, 195, 88, 242, 123, 93];
pub static PUBSHA512KEY : &'static [u8] = &[171, 21, 71, 31, 182, 64, 250, 16, 97, 68, 201, 98, 227, 190, 62, 74, 19, 93, 165, 98, 118, 17, 189, 93, 93, 128, 2, 126, 121, 255, 44, 202, 109, 183, 159, 127, 200, 184, 75, 89, 188, 66, 223, 217, 251, 123, 187, 172, 119, 204, 150, 104, 140, 214, 164, 227, 190, 95, 242, 145, 178, 83, 202, 95];
pub static PUBSHA256KEY : &'static [u8] = &[25, 10, 108, 202, 192, 185, 24, 238, 203, 196, 34, 198, 65, 244, 12, 135, 0, 175, 255, 53, 191, 128, 220, 177, 12, 83, 215, 169, 237, 31, 193, 203, 159, 152, 230, 105, 40, 178, 23, 238, 14, 114, 101, 182, 85, 115, 215, 9, 160, 254, 112, 100, 152, 114, 130, 217, 192, 193, 141, 128, 184, 153, 37, 171];
pub static RSA2048SHA512KEY : &'static [u8] = &[216, 233, 21, 81, 76, 58, 81, 215, 56, 16, 193, 244, 39, 156, 13, 33, 215, 67, 79, 130, 179, 245, 104, 24, 45, 6, 197, 51, 89, 66, 147, 57, 18, 171, 207, 243, 198, 248, 145, 190, 68, 149, 44, 203, 146, 155, 30, 132, 229, 228, 93, 184, 101, 10, 52, 27, 177, 20, 145, 216, 4, 53, 173, 153];
pub static ECDSARIPEMD160KEY : &'static [u8] = &[106, 59, 17, 211, 187, 4, 5, 150, 249, 143, 65, 107, 199, 36, 186, 16, 10, 72, 61, 176, 187, 131, 109, 196, 84, 250, 254, 2, 23, 225, 202, 231, 84, 82, 180, 121, 96, 203, 190, 186, 171, 131, 166, 157, 190, 215, 205, 130, 247, 240, 116, 81, 29, 252, 49, 137, 134, 232, 118, 52, 61, 131, 127, 2];

