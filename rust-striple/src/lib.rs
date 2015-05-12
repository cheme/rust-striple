//! Lib to manipulate striple (Signed-Triples) in Rust.
//!
//! It ensures standard exchange format of striple as bytes.
//! It provide interface to striple for any struct.
//! 
//! Several feature implements validation scheme (signature, verification and key derivation).
//! Others add optional traits implementation such as serialize.
//!

#![feature(collections)]

#[macro_use] extern crate log;
extern crate num;

#[cfg(feature="serialize")]
extern crate rustc_serialize;

pub mod striple;
pub mod public;
mod stripledata; 


#[cfg(feature="opensslrsa")]
pub mod rsa_openssl;
#[cfg(feature="cryptoecdsa")]
pub mod ecdsa_crypto;


