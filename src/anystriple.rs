//!
//! Enum to return any striple manage by this library.
//! This implementation does not include type defined externally and is very likelly to be
//! overriden in applications.
//!

use stripledata;
use std::io::Read;
use striple::SignatureScheme;
use striple::IDDerivation;
use striple::{
  NoSigCh,
  NoIDDer,
  BCont,
  AsStripleIf,
  Striple,
  StripleRef,
  GenStripleIf,
  Error,
  ref_as_kind,
  StripleKind,
  AsStriple,
  StripleIf,
  StripleDef,
  StripleFieldsIf,
  OwnedStripleIf,
  ErrorKind
};
use striple::NoKind;
use striple::Result;
use std::result::Result as StdResult;


#[cfg(feature="opensslrsa")]
pub type StripleRSA = Striple<Rsa2048Sha512>;
#[cfg(not(feature="opensslrsa"))]
pub type StripleRSA = Striple<NoKind>;
#[cfg(feature="cryptoecdsa")]
pub type StripleECDSA = Striple<EcdsaRipemd160>;
#[cfg(not(feature="cryptoecdsa"))]
pub type StripleECDSA = Striple<NoKind>;
#[cfg(feature="public_openssl")]
pub type StriplePSha512 = Striple<PubSha512>;
#[cfg(not(feature="public_openssl"))]
pub type StriplePSha512 = Striple<NoKind>;
#[cfg(feature="public_openssl")]
pub type StriplePSha256 = Striple<PubSha256>;
#[cfg(not(feature="public_openssl"))]
pub type StriplePSha256 = Striple<NoKind>;
#[cfg(feature="public_openssl")]
pub type StriplePRIP = Striple<PubRipemd>;
#[cfg(not(feature="public_openssl"))]
#[cfg(feature="public_crypto")]
pub type StriplePRIP = Striple<PubRipemd>;
#[cfg(not(feature="public_openssl"))]
#[cfg(not(feature="public_crypto"))]
pub type StriplePRIP = Striple<NoKind>;


#[derive(Debug,Clone)]
pub struct Rsa2048Sha512;
#[derive(Debug,Clone)]
pub struct EcdsaRipemd160;
#[derive(Debug,Clone)]
pub struct PubSha512;
#[derive(Debug,Clone)]
pub struct PubSha256;
#[derive(Debug,Clone)]
pub struct PubRipemd;

/// Only access to its striple but no implementation
#[cfg(not(feature="opensslrsa"))]
impl StripleKind for Rsa2048Sha512 {
  type D = NoIDDer;
  type S = NoSigCh;
  fn get_algo_key() -> &'static [u8] {
    match *stripledata::KINDIDS {
      Some (ref kinds) => {
        &kinds.rsa2048_sha512[..]
      },
      None => stripledata::RSA2048SHA512KEY,
    }
  }
}

#[cfg(not(feature="cryptoecdsa"))]
impl StripleKind for EcdsaRipemd160 {
  type D = NoIDDer;
  type S = NoSigCh;
  fn get_algo_key() -> &'static [u8] {
    match *stripledata::KINDIDS {
      Some (ref kinds) => {
        &kinds.ecdsaripemd160[..]
      },
      None => stripledata::ECDSARIPEMD160KEY,
    }
  }
}

#[cfg(not(feature="public_openssl"))]
#[cfg(not(feature="public_crypto"))]
impl StripleKind for PubRipemd {
    type D = NoIDDer;
    type S = NoSigCh;
    fn get_algo_key() -> &'static [u8] {
      match *stripledata::KINDIDS {
        Some (ref kinds) => {
          &kinds.pubripemd[..]
        },
        None => stripledata::PUBRIPEMKEY,
      }
    }
}

#[cfg(not(feature="public_openssl"))]
impl StripleKind for PubSha512 {
    type D = NoIDDer;
    type S = NoSigCh;
     fn get_algo_key() -> &'static [u8] {
      match *stripledata::KINDIDS {
        Some (ref kinds) => {
          &kinds.pubsha512[..]
        },
        None => stripledata::PUBSHA512KEY,
      }
    }

}

#[cfg(not(feature="public_openssl"))]
impl StripleKind for PubSha256 {
    type D = NoIDDer;
    type S = NoSigCh;
     fn get_algo_key() -> &'static [u8] {
      match *stripledata::KINDIDS {
        Some (ref kinds) => {
          &kinds.pubsha256[..]
        },
        None => stripledata::PUBSHA256KEY,
      }
    }

}



macro_rules! derive_any_striple(($en:ident{ $($st:ident($ty:ty),)* }) => (
#[derive(Debug,Clone)]
pub enum $en {
  $( $st($ty), )*
}
/*
impl AsStripleIf for $en {

  #[inline]
  fn as_striple_if(&self) -> &GenStripleIf {
    match self {
      $( & $en::$st(ref i) => i, )*
    }
  }
}*/

impl StripleFieldsIf for $en {
  #[inline]
  fn get_algo_key(&self) -> &'static [u8] {
    match self {
      $( & $en::$st(ref i) => i.get_algo_key(), )*
    }
  }
  #[inline]
  fn get_enc(&self) -> &[u8] {
    match self {
      $( & $en::$st(ref i) => i.get_enc(), )*
    }
  }
  #[inline]
  fn get_id(&self) -> &[u8] {
    match self {
      $( & $en::$st(ref i) => i.get_id(), )*
    }
  }
  #[inline]
  fn get_from(&self) -> &[u8] {
    match self {
      $( & $en::$st(ref i) => i.get_from(), )*
    }
  }
  #[inline]
  fn get_about(&self) -> &[u8] {
    match self {
      $( & $en::$st(ref i) => i.get_about(), )*
    }
  }
  #[inline]
  fn get_content<'a>(&'a self) -> &'a Option<BCont<'a>> {
    match self {
      $( & $en::$st(ref i) => i.get_content(), )*
    }
  }
  #[inline]
  fn get_content_ids(&self) -> Vec<&[u8]> {
    match self {
      $( & $en::$st(ref i) => i.get_content_ids(), )*
    }
  }
  #[inline]
  fn get_key(&self) -> &[u8] {
    match self {
      $( & $en::$st(ref i) => i.get_key(), )*
    }
  }
  #[inline]
  fn get_sig(&self) -> &[u8] {
    match self {
      $( & $en::$st(ref i) => i.get_sig(), )*
    }
  }
  #[inline]
  fn get_tosig<'a>(&'a self) -> Result<(Vec<u8>,Option<&'a BCont<'a>>)> {
    match self {
      $( & $en::$st(ref i) => i.get_tosig(), )*
    }
  }
  #[inline]
  fn striple_ser_with_def<'a> (&'a self) -> Result<(Vec<u8>,Option<&'a BCont<'a>>)> {
    match self {
      $( & $en::$st(ref i) => i.striple_ser_with_def(), )*
    }
  }
  #[inline]
  fn striple_ser<'a> (&'a self, v : Vec<u8>) -> Result<(Vec<u8>,Option<&'a BCont<'a>>)> {
    match self {
      $( & $en::$st(ref i) => i.striple_ser(v), )*
    }
  }
  #[inline]
  fn striple_def (&self) -> StripleDef {
    match self {
      $( & $en::$st(ref i) => i.striple_def(), )*
    }
  }
}
impl StripleIf for $en {
  #[inline]
  fn check_content<R : Read>(&self, cont : &mut R, sig : &[u8]) -> Result<bool> {
    match self {
      $( & $en::$st(ref i) => i.check_content(cont,sig), )*
    }
  }
  #[inline]
  fn sign_content<R : Read>(&self, a : &[u8], b : &mut R) -> Result<Vec<u8>> {
    match self {
      $( & $en::$st(ref i) => i.sign_content(a,b), )*
    }
  }
  #[inline]
  fn derive_id(&self, sig : &[u8]) -> Result<Vec<u8>> {
    match self {
      $( & $en::$st(ref i) => i.derive_id(sig), )*
    }
  }
  #[inline]
  fn check_id_derivation(&self, sig : &[u8], id : &[u8]) -> Result<bool> {
    match self {
      $( & $en::$st(ref i) => i.check_id_derivation(sig,id), )*
    }
  }
  #[inline]
  fn check<S : StripleIf>(&self, from : &S) -> Result<bool> {
    match self {
      $( & $en::$st(ref i) => i.check(from), )*
    }
  }
  #[inline]
  fn check_sig<S : StripleIf>(&self, from : &S) -> Result<bool> {
    match self {
      $( & $en::$st(ref i) => i.check_sig(from), )*
    }
  }
  #[inline]
  fn check_id<S : StripleIf>(&self, from : &S) -> Result<bool> {
    match self {
      $( & $en::$st(ref i) => i.check_id(from), )*
    }
  }


}

));


/// enum to load any basic lib supported striple
derive_any_striple!(AnyStriple {
  StripleRsa(StripleRSA),
  StripleECDSA(StripleECDSA),
  StriplePSha512(StriplePSha512),
  StriplePSha256(StriplePSha256),
  StriplePRIP(StriplePRIP),
  StripleNOKEY(Striple<NoKind>),
});

/// deserialize to anystriple with checking of key to type and possible advance when nokey (here
/// simply emit unusable NoKind striple.
/// Note that here we only match with library hardcoded ids (or loaded id), but in real application
/// multiple id might be allowed, plus rules based upon striple content for case where id is
/// unknown.
pub fn copy_builder_any(algoid :&[u8], sr : StripleRef<NoKind>) -> Result<AnyStriple> {
  match algoid {
    i if (i == Rsa2048Sha512::get_algo_key()) => Ok(AnyStriple::StripleRsa(ref_as_kind(&sr).as_striple())),
    i if (i == EcdsaRipemd160::get_algo_key()) => Ok(AnyStriple::StripleECDSA(ref_as_kind(&sr).as_striple())),
    i if (i == PubSha512::get_algo_key()) => Ok(AnyStriple::StriplePSha512(ref_as_kind(&sr).as_striple())),
    i if (i == PubSha256::get_algo_key()) => Ok(AnyStriple::StriplePSha256(ref_as_kind(&sr).as_striple())),
    i if (i == PubRipemd::get_algo_key()) => Ok(AnyStriple::StriplePRIP(ref_as_kind(&sr).as_striple())),
    _ => {
      println!("Unknown kind ID, returning Nokind unusable Striple instead of error");
      // TODO replace by error
      Ok(AnyStriple::StripleNOKEY(sr.as_striple()))
      //Err(Error("Bad algo kind for this type of striple".to_string(), ErrorKind::UnexpectedStriple))
    },
  }
}

impl AnyStriple {

  pub fn new_self (
    algoid :&[u8], 
    contentenc : Vec<u8>,
    about: Option<Vec<u8>>,
    contentids : Vec<Vec<u8>>,
    content : Option<BCont<'static>>,
  ) -> Result<(AnyStriple,Vec<u8>)> {
  match algoid {
    i if (i == Rsa2048Sha512::get_algo_key()) => {
      let (s, p) = try!(Striple::new_self(contentenc, about, contentids, content));
      Ok((AnyStriple::StripleRsa(s), p))
    },
    i if (i == EcdsaRipemd160::get_algo_key()) => {
      let (s, p) = try!(Striple::new_self(contentenc, about, contentids, content));
      Ok((AnyStriple::StripleECDSA(s), p))
    },
    i if (i == PubSha512::get_algo_key()) => {
      let (s, p) = try!(Striple::new_self(contentenc, about, contentids, content));
      Ok((AnyStriple::StriplePSha512(s), p))
    },
    i if (i == PubSha256::get_algo_key()) => {
      let (s, p) = try!(Striple::new_self(contentenc, about, contentids, content));
      Ok((AnyStriple::StriplePSha256(s), p))
    },
    i if (i == PubRipemd::get_algo_key()) => {
      let (s, p) = try!(Striple::new_self(contentenc, about, contentids, content));
      Ok((AnyStriple::StriplePRIP(s), p))
    },
    _ => {
      Err(Error("Unresolved kind and no default kind defined".to_string(), ErrorKind::UnexpectedStriple, None))
    },
  }

  }


  /// contstructor over typed striple one
  pub fn new<OST : OwnedStripleIf> (
    algoid :&[u8], 
    contentenc : Vec<u8>,
    from : &OST,
    about: Option<Vec<u8>>,
    contentids : Vec<Vec<u8>>,
    content : Option<BCont<'static>>,
  ) -> Result<(AnyStriple,Vec<u8>)> {
  match algoid {
    i if (i == Rsa2048Sha512::get_algo_key()) => {
      let (s, p) = try!(Striple::new(contentenc, from, about, contentids, content));
      Ok((AnyStriple::StripleRsa(s), p))
    },
    i if (i == EcdsaRipemd160::get_algo_key()) => {
      let (s, p) = try!(Striple::new(contentenc, from, about, contentids, content));
      Ok((AnyStriple::StripleECDSA(s), p))
    },
    i if (i == PubSha512::get_algo_key()) => {
      let (s, p) = try!(Striple::new(contentenc, from, about, contentids, content));
      Ok((AnyStriple::StriplePSha512(s), p))
    },
    i if (i == PubSha256::get_algo_key()) => {
      let (s, p) = try!(Striple::new(contentenc, from, about, contentids, content));
      Ok((AnyStriple::StriplePSha256(s), p))
    },
    i if (i == PubRipemd::get_algo_key()) => {
      let (s, p) = try!(Striple::new(contentenc, from, about, contentids, content));
      Ok((AnyStriple::StriplePRIP(s), p))
    },
    _ => {
      Err(Error("Unresolved kind and no default kind defined".to_string(), ErrorKind::UnexpectedStriple, None))
    },
  }

  }

  /// TODO replace by as_public (&self) -> Option<PubAnyStriple>
  pub fn is_public(&self) -> bool {
    match self {
      &AnyStriple::StriplePSha512(_) => {
        true
      },
      &AnyStriple::StriplePSha256(_) => {
        true
      },
      &AnyStriple::StriplePRIP(_) => {
        true
      },
      _ => {
        false
      }
    }
  }
}
