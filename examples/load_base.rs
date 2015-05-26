//! load base striple from a file
//! this is an example of how to resolve types if they are not known at launch.
extern crate striple;

use std::fs::File;
use std::io::Read;
use std::io::Result as IOResult;
use striple::storage::FileStripleIterator;
use striple::striple::NoKind;
use striple::striple::Striple;
use striple::striple::StripleIf;
#[cfg(feature="public_crypto")]
use striple::striple_kind::public::crypto::PubRipemd;
#[cfg(feature="public_openssl")]
use striple::striple_kind::public::openssl::{PubSha512,PubSha256};
#[cfg(not(feature="public_openssl"))]
#[cfg(feature="public_crypto")]
use striple::striple_kind::public::openssl::PubRipemd;
#[cfg(feature="opensslrsa")]
use striple::striple_kind::Rsa2048Sha512;
#[cfg(feature="cryptoecdsa")]
use striple::striple_kind::EcdsaRipemd160;


fn main() {
  let mut datafile = File::open("./baseperm.data").unwrap();
  let mut rit : IOResult<FileStripleIterator<NoKind,_>> = FileStripleIterator::init(datafile);
  let mut ix = 0;
  for striple in rit.unwrap() {
    // TODO resolve kind
    // TODO check

    println!("a striple");
  }
 



  print!("hello");


}

/*
#[cfg(feature="opensslrsa")]
pub type StripleRSA = StripleIf<Rsa2048Sha512>;
#[cfg(not(feature="opensslrsa"))]
pub type StripleRSA = StripleIf<NoKind>;
#[cfg(feature="cryptoecdsa")]
pub type StripleECDSA = StripleIf<EcdsaRipemd160>;
#[cfg(not(feature="opensslrsa"))]
pub type StripleECDSA = StripleIf<NoKind>;
#[cfg(feature="public_openssl")]
pub type StriplePSha512 = StripleIf<PubSha512>;
#[cfg(not(feature="public_openssl"))]
pub type StriplePSha512 = StripleIf<NoKind>;
#[cfg(feature="public_openssl")]
pub type StriplePSha256 = StripleIf<PubSha256>;
#[cfg(not(feature="public_openssl"))]
pub type StriplePSha256 = StripleIf<NoKind>;
#[cfg(feature="public_openssl")]
pub type StriplePRIP = StripleIf<PubRipemd>;
#[cfg(not(feature="public_openssl"))]
#[cfg(feature="public_crypto")]
pub type StriplePRIP = StripleIf<PubRipemd>;
#[cfg(not(feature="public_openssl"))]
#[cfg(not(feature="public_crypto"))]
pub type StriplePRIP = StripleIf<NoKind>;



/// enum to load any basic lib supported striple
pub enum AnyStriple {
  StripleRsa(StripleRSA),
  StripleECDSA(StripleECDSA),
  StriplePSha512(StriplePSha512),
  StriplePSha256(StriplePSha256),
  StriplePRIP(StriplePRIP),
  StripleNOKEY(StripleIf<NoKind>),
}
*/
