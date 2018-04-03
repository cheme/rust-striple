//! Lib to manipulate striple (Signed-Triples) in Rust.
//!
//! It ensures standard exchange format of striple as bytes.
//! It provide interface to striple for any struct.
//! 
//! Several feature implements validation scheme (signature, verification and key derivation).
//! Others add optional traits implementation such as serialize.
//!

/*
#![feature(no_std)]
#![no_std]
*/


#[macro_use] extern crate lazy_static;
#[macro_use] extern crate log;

#[cfg(feature="serialize")]
extern crate serde;

#[cfg(feature="serialize")]
extern crate base64;

#[cfg(feature="for_c")]
extern crate libc;



pub mod striple;
pub mod anystriple;
pub mod storage;
#[cfg(feature="public_crypto")]
mod public;
#[cfg(feature="public_openssl")]
#[cfg(not(feature="public_crypto"))]
mod public;
pub mod stripledata; 

#[cfg(feature="opensslrsa")]
mod rsa_openssl;
pub mod keyder {
  #[cfg(feature="opensslrsa")]
  pub use rsa_openssl::SHA512KD;
  #[cfg(feature="cryptoecdsa")]
  pub use ecdsa_crypto::RIPEMD160KD;
  pub use striple::IdentityKD;
  pub use striple::NoIDDer;

}

#[cfg(feature="cryptoecdsa")]
mod ecdsa_crypto;

#[cfg(any(feature="opensslrsa",feature="public_openssl",feature="opensslpbkdf2"))]
mod openssl_common {
  extern crate openssl;
  use self::openssl::error::ErrorStack;
  use striple::Error;
  use striple::ErrorKind;
  impl From<ErrorStack> for Error {
    #[inline]
    fn from(e : ErrorStack) -> Error {
      Error(e.to_string(), ErrorKind::IOError, Some(Box::new(e)))
    }
  }
}

pub mod striple_kind {
  pub use striple::NoKind;

  pub use anystriple::Rsa2048Sha512;
  pub use anystriple::EcdsaRipemd160;
  pub use anystriple::PubRipemd;
  pub use anystriple::PubSha512;
  pub use anystriple::PubSha256;


}






#[cfg(feature="for_c")]
pub mod for_c;

