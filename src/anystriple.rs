//!
//! Enum to return any striple manage by this library.
//! This implementation does not include type defined externally and is very likelly to be
//! overriden in applications.
//!

use striple::{Striple,StripleRef,NoKind,Error,ref_as_kind,StripleKind,AsStriple,StripleIf,OwnedStripleIf, PubStriple,PublicScheme,ErrorKind};
#[cfg(feature="opensslrsa")]
use rsa_openssl::Rsa2048Sha512;
#[cfg(feature="cryptoecdsa")]
use ecdsa_crypto::EcdsaRipemd160;
#[cfg(feature="public_crypto")]
use public::public_crypto::PubRipemd;
#[cfg(feature="public_openssl")]
use public::public_openssl::{PubSha512,PubSha256};
#[cfg(not(feature="public_openssl"))]
#[cfg(feature="public_crypto")]
use public::public_openssl::PubRipemd;


#[cfg(feature="opensslrsa")]
pub type StripleRSA = Striple<Rsa2048Sha512>;
#[cfg(not(feature="opensslrsa"))]
pub type StripleRSA = Striple<NoKind>;
#[cfg(feature="cryptoecdsa")]
pub type StripleECDSA = Striple<EcdsaRipemd160>;
#[cfg(not(feature="opensslrsa"))]
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

macro_rules! derive_any_striple(($en:ident{ $($st:ident($ty:ty),)* }) => (
#[derive(Debug,Clone)]
pub enum $en {
  $( $st($ty), )*
}
impl StripleIf for $en {
  #[inline]
  fn get_algo_key(&self) -> &'static [u8]{
    match self {
      $( & $en::$st(ref i) => i.get_algo_key(), )*
    }
  }
  #[inline]
  fn check_content(&self, cont : &[u8],sig : &[u8]) -> bool {
    match self {
      $( & $en::$st(ref i) => i.check_content(cont, sig), )*
    }
  }
  #[inline]
  fn sign_content(&self, pri : &[u8], con : &[u8]) -> Vec<u8> {
    match self {
      $( & $en::$st(ref i) => i.sign_content(pri, con), )*
    }
  }
  #[inline]
  fn check_id_derivation(&self, sig : &[u8], id : &[u8]) -> bool {
    match self {
      $( & $en::$st(ref i) => i.check_id_derivation(sig,id), )*
    }
  }
  #[inline]
  fn derive_id(&self, sig : &[u8]) -> Vec<u8> {
    match self {
      $( & $en::$st(ref i) => i.derive_id(sig), )*
    }
  }
  #[inline]
  fn striple_ser (&self) -> Vec<u8> {
    match self {
      $( & $en::$st(ref i) => i.striple_ser(), )*
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
  fn get_id(&self) -> &[u8] {
    match self {
      $( & $en::$st(ref i) => i.get_id(), )*
    }
  }
  #[inline]
  fn get_about(&self) -> &[u8] {
    match self {
      $( & $en::$st(ref i) => i.get_about(), )*
    }
  }
  #[inline]
  fn get_from(&self) -> &[u8] {
    match self {
      $( & $en::$st(ref i) => i.get_from(), )*
    }
  }
  #[inline]
  fn get_content(&self) -> &[u8] {
    match self {
      $( & $en::$st(ref i) => i.get_content(), )*
    }
  }
  #[inline]
  fn get_enc(&self) -> &[u8] {
    match self {
      $( & $en::$st(ref i) => i.get_enc(), )*
    }
  }
  #[inline]
  fn get_content_ids(&self) -> Vec<&[u8]> {
    match self {
      $( & $en::$st(ref i) => i.get_content_ids(), )*
    }
  }
  #[inline]
  fn get_tosig(&self) -> Vec<u8> {
    match self {
      $( & $en::$st(ref i) => i.get_tosig(), )*
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
pub fn copy_builder_any(algoid :&[u8], sr : StripleRef<NoKind>) -> Result<AnyStriple, Error> {
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
/// contstructor over typed striple one
  pub fn new<SF : OwnedStripleIf> (
    algoid :&[u8], 
    contentenc : Vec<u8>,
    from : Option<&SF>,
    about: Option<Vec<u8>>,
    contentids : Vec<Vec<u8>>,
    content :    Vec<u8>,
  ) -> Result<(AnyStriple,Vec<u8>), Error> {
  match algoid {
    i if (i == Rsa2048Sha512::get_algo_key()) => {
      let (s, p) = Striple::new(contentenc, from, about, contentids, content);
      Ok((AnyStriple::StripleRsa(s), p))
    },
    i if (i == EcdsaRipemd160::get_algo_key()) => {
      let (s, p) = Striple::new(contentenc, from, about, contentids, content);
      Ok((AnyStriple::StripleECDSA(s), p))
    },
    i if (i == PubSha512::get_algo_key()) => {
      let (s, p) = Striple::new(contentenc, from, about, contentids, content);
      Ok((AnyStriple::StriplePSha512(s), p))
    },
    i if (i == PubSha256::get_algo_key()) => {
      let (s, p) = Striple::new(contentenc, from, about, contentids, content);
      Ok((AnyStriple::StriplePSha256(s), p))
    },
    i if (i == PubRipemd::get_algo_key()) => {
      let (s, p) = Striple::new(contentenc, from, about, contentids, content);
      Ok((AnyStriple::StriplePRIP(s), p))
    },
    _ => {
      Err(Error("Unresolved kind and no default kind defined".to_string(), ErrorKind::UnexpectedStriple))
    },
  }

  }

 
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
