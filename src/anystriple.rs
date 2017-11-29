//!
//! Enum to return any striple manage by this library.
//! This implementation does not include type defined externally and is very likelly to be
//! overriden in applications.
//!
use std::env;
use std::fs::File;
use stripledata;
use storage::{
  FileStripleIterator,
  init_noread_key,
  init_any_cipher_stdin,
};
use std::io::Read;
use striple::IDDerivation;
use striple::{
  SignatureScheme,
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
  ErrorKind,
  from_error,
  from_option,
  ref_builder_id_copy,
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


#[derive(Debug,Clone,PartialEq,Eq)]
pub struct Rsa2048Sha512;
#[derive(Debug,Clone,PartialEq,Eq)]
pub struct EcdsaRipemd160;
#[derive(Debug,Clone,PartialEq,Eq)]
pub struct PubSha512;
#[derive(Debug,Clone,PartialEq,Eq)]
pub struct PubSha256;
#[derive(Debug,Clone,PartialEq,Eq)]
pub struct PubRipemd;

#[derive(Debug,Clone)]
pub struct BaseStriples {
  pub root : (AnyStriple, Option<Vec<u8>>),
  pub pubcat : (AnyStriple, Option<Vec<u8>>),
  pub pubkind : (AnyStriple, Option<Vec<u8>>),
  pub libcat : (AnyStriple, Option<Vec<u8>>),
  pub libkind : (AnyStriple, Option<Vec<u8>>),
  pub libkinds : KindStriples,
  pub pubkinds : KindStriples,
  pub others : Vec<(AnyStriple, Option<Vec<u8>>)>,
}
#[derive(Debug,Clone)]
pub struct KindStriples {
  pub kind : (AnyStriple, Option<Vec<u8>>),
  pub pubripemd : (AnyStriple, Option<Vec<u8>>),
  pub pubsha512 : (AnyStriple, Option<Vec<u8>>),
  pub pubsha256 : (AnyStriple, Option<Vec<u8>>),
  pub rsa2048_sha512 : (AnyStriple, Option<Vec<u8>>),
  pub ecdsaripemd160 : (AnyStriple, Option<Vec<u8>>),
}

/// read base striple panicking on error, to read safely, do not use BASE_STRIPLES static
fn init_base_striple(check : bool) -> Result<BaseStriples> {
  let path = from_error(env::var("STRIPLE_BASE"))?;
  let datafile = from_error(File::open(path))?;
  // get striple without key and without Kind (as we define it)
  let rit : StdResult<FileStripleIterator<NoKind,AnyStriple,_,_,_>,_> = FileStripleIterator::init(datafile, copy_builder_any, &init_any_cipher_stdin, ()); 
  let mut it = rit?;
  let root = from_option(it.next())?;
  let pubcat = from_option(it.next())?;
  let pubkind = from_option(it.next())?;
  let libcat = from_option(it.next())?;
  let libkind = from_option(it.next())?;

  let kind = from_option(it.next())?;
  let pubripemd = from_option(it.next())?;
  let pubsha512 = from_option(it.next())?;
  let pubsha256 = from_option(it.next())?;
  let rsa2048_sha512 = from_option(it.next())?;
  let ecdsaripemd160 = from_option(it.next())?;
  let libkinds = KindStriples {
    kind,
    pubripemd,
    pubsha512,
    pubsha256,
    rsa2048_sha512,
    ecdsaripemd160,
  };
  let kind = from_option(it.next())?;
  let pubripemd = from_option(it.next())?;
  let pubsha512 = from_option(it.next())?;
  let pubsha256 = from_option(it.next())?;
  let rsa2048_sha512 = from_option(it.next())?;
  let ecdsaripemd160 = from_option(it.next())?;
  let pubkinds = KindStriples {
    kind,
    pubripemd,
    pubsha512,
    pubsha256,
    rsa2048_sha512,
    ecdsaripemd160,
  };

  if check {
    let mut ok = true;
    ok &= libcat.0.check(&root.0)?;
    ok &= libcat.0.check(&root.0)?;
    ok &= libkinds.kind.0.check(&root.0)?;
    ok &= libkinds.pubripemd.0.check(&libkinds.kind.0)?;
    ok &= libkinds.pubsha512.0.check(&libkinds.kind.0)?;
    ok &= libkinds.pubsha256.0.check(&libkinds.kind.0)?;
    ok &= libkinds.rsa2048_sha512.0.check(&libkinds.kind.0)?;
    ok &= libkinds.ecdsaripemd160.0.check(&libkinds.kind.0)?;
    ok &= pubkinds.kind.0.check(&root.0)?;
    ok &= pubkinds.pubripemd.0.check(&pubkinds.kind.0)?;
    ok &= pubkinds.pubsha512.0.check(&pubkinds.kind.0)?;
    ok &= pubkinds.pubsha256.0.check(&pubkinds.kind.0)?;
    ok &= pubkinds.rsa2048_sha512.0.check(&pubkinds.kind.0)?;
    ok &= pubkinds.ecdsaripemd160.0.check(&pubkinds.kind.0)?;
    if !ok {
      return Err(Error(format!("Base striples does not check"), ErrorKind::UnexpectedStriple, None))
    }
  }

  Ok(BaseStriples {
    root,
    pubcat, 
    pubkind,
    libcat,
    libkind,
    libkinds,
    pubkinds,
    others : it.collect(),
  })
/*  write_striple_with_enc(&cypher,&pribase.root.0,Some(&pribase.root.1),&mut datafile, &private_enc).unwrap();
  write_striple_with_enc(&cypher,&pubcat,None,&mut datafile, &public_enc).unwrap();
  write_striple_with_enc(&cypher,&pubkind,None,&mut datafile, &public_enc).unwrap();
  write_striple_with_enc(&cypher,&pribase.libcat.0,Some(&pribase.libcat.1),&mut datafile, &private_enc).unwrap();
  write_striple_with_enc(&cypher,&pribase.libkind.0,Some(&pribase.libkind.1),&mut datafile, &private_enc).unwrap();
  write_striple_with_enc(&cypher,&prikinds.kind.0,Some(&prikinds.kind.1),&mut datafile, &private_enc).unwrap();
  write_striple_with_enc(&cypher,&prikinds.pubripemd.0,Some(&prikinds.pubripemd.1),&mut datafile, &private_enc).unwrap();
  write_striple_with_enc(&cypher,&prikinds.pubsha512.0,Some(&prikinds.pubsha512.1),&mut datafile, &private_enc).unwrap();
  write_striple_with_enc(&cypher,&prikinds.pubsha256.0,Some(&prikinds.pubsha256.1),&mut datafile, &private_enc).unwrap();
  write_striple_with_enc(&cypher,&prikinds.rsa2048_sha512.0,Some(&prikinds.rsa2048_sha512.1),&mut datafile, &private_enc).unwrap();
  write_striple_with_enc(&cypher,&prikinds.ecdsaripemd160.0,Some(&prikinds.ecdsaripemd160.1),&mut datafile, &private_enc).unwrap();
  write_striple_with_enc(&cypher,&pubstriples.kind,None,&mut datafile, &public_enc).unwrap();
  write_striple_with_enc(&cypher,&pubstriples.pubripemd,None,&mut datafile, &public_enc).unwrap();
  write_striple_with_enc(&cypher,&pubstriples.pubsha512,None,&mut datafile, &public_enc).unwrap();
  write_striple_with_enc(&cypher,&pubstriples.pubsha256,None,&mut datafile, &public_enc).unwrap();
  write_striple_with_enc(&cypher,&pubstriples.rsa2048_sha512,None,&mut datafile, &public_enc).unwrap();
  write_striple_with_enc(&cypher,&pubstriples.ecdsaripemd160,None,&mut datafile, &public_enc).unwrap();
*/

}
#[cfg(feature="any_base")]
lazy_static!{
pub static ref BASE_STRIPLES : BaseStriples = init_base_striple(true).unwrap();
}
#[cfg(feature="any_base_no_panic")]
lazy_static!{
pub static ref BASE_STRIPLES_NO_PANIC : Result<BaseStriples> = init_base_striple(true);
}

#[cfg(feature="any_base_no_check")]
lazy_static!{
pub static ref BASE_STRIPLES : BaseStriples = init_base_striple(false).unwrap();
}


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
