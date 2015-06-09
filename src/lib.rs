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
#![feature(collections)]
#![feature(core)]

#![feature(debug_builders)]
/*
#[cfg(not(for_c))]
#[macro_use] extern crate std;
/* for_c config : fake std reexport from core TODO
 **/
*/

#[macro_use] extern crate lazy_static;
#[macro_use] extern crate log;
extern crate num;

#[cfg(feature="serialize")]
extern crate rustc_serialize;

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
#[cfg(feature="cryptoecdsa")]
mod ecdsa_crypto;


pub mod striple_kind {
  pub use striple::NoKind;

  pub mod public {
    #[cfg(feature="public_crypto")]
    pub mod crypto {
      pub use public::public_crypto::{PubRipemd};
    }
    #[cfg(feature="public_openssl")]
    pub mod openssl {
      pub use public::public_openssl::{PubRipemd,PubSha512,PubSha256};
    }
  }

  #[cfg(feature="opensslrsa")]
  pub use rsa_openssl::Rsa2048Sha512;
  #[cfg(feature="cryptoecdsa")]
  pub use ecdsa_crypto::EcdsaRipemd160;
}

