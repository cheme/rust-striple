//! load base striple from a file
//! this is an example of how to resolve types if they are not known at launch.
extern crate striple;

use std::fs::File;
use std::io::Read;
use std::io::{stdin,BufRead};
use std::io::Result as IOResult;
use striple::storage::FileStripleIterator;
use striple::striple::NoKind;
use striple::striple::Striple;
use striple::striple::StripleRef;
use striple::striple::StripleKind;
use striple::striple::Error;
//use striple::striple::copy_as_kind;
use striple::striple::ref_as_kind;
use striple::striple::ErrorKind;
use striple::striple::AsStriple;
use striple::striple::StripleIf;
use striple::striple::OwnedStripleIf;
use striple::storage::{write_striple_file,NoCypher,RemoveKey,StorageCypher,initAnyCypherStdIn};
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
#[cfg(feature="opensslpbkdf2")]
use striple::storage::Pbkdf2;

/// load base file produced by generate example (privatekey clear).
/// Plus write base file without password or with encrypted password.
fn main() {
  let mut datafile = File::open("./baseperm.data").unwrap();
  let mut rit : IOResult<FileStripleIterator<NoKind,AnyStriple,_,_,_>> = FileStripleIterator::init(datafile, copy_builder_any, initAnyCypherStdIn); 
  let striples : Vec<(AnyStriple,Option<Vec<u8>>)> = rit.unwrap().collect();


  // Doing some check based upon knowned structure
  if (striples[0].1.is_some()){
    println!("doing root checking");
    let ownedroot = (&striples[0].0, &striples[0].1.as_ref().unwrap()[..]);

    // try sign check to check privatekey encryption
    let cont = vec!(56,84,8,46,250,6,8,7);

    let sign = ownedroot.sign_content(&ownedroot.private_key_ref(),&cont[..]);
    assert!(ownedroot.check_content(&cont[..],&sign[..]));


    assert!(striples[1].0.check(&ownedroot) == true);
    assert!(striples[2].0.check(&ownedroot) == true);
  }
  // Doing some public check
   if (striples[9].1.is_none()){
    println!("doing public checking");
    let ownedkind = (&striples[9].0, &[][..]);

    assert!(striples[11].0.check(&ownedkind) == true);
    assert!(striples[12].0.check(&ownedkind) == true);
  }
 
  // rewrite without private key for publishing

  let mut datafile = File::create("./baseperm_nokey.data").unwrap();
  //  let refvec : Vec<(&AnyStriple,Option<&[u8]>)> = striples.iter().map(|i|(&i.0,i.1.as_ref().map(|o|&o[..]))).collect();
  let mut it = striples.iter().map(|i|(&i.0,i.1.as_ref().map(|o|&o[..])));
  // let wr = write_striple_file(&RemoveKey, &mut refvec.iter(), &mut datafile);
  let wr = write_striple_file(&RemoveKey, &mut it, &mut datafile);

  writepkbdf2(&striples);

  print!("hello");


}

#[cfg(feature="opensslpbkdf2")]
fn writepkbdf2(striples : &Vec<(AnyStriple,Option<Vec<u8>>)>) {
  
  let mut datafile = File::create("./baseperm_pbkdf2.data").unwrap();

  let mut it = striples.iter().map(|i|(&i.0,i.1.as_ref().map(|o|&o[..])));

  println!("writing as protected, please input passphrase ?");
  let mut tstdin = stdin();
  let mut stdin = tstdin.lock();
  let mut pass = String::new();
  stdin.read_line(&mut pass);
  // remove terminal \n
  pass.pop();
println!("{}",pass); 
  let pbk = Pbkdf2::new(pass,2000,None);
  let wr = write_striple_file(&pbk, &mut it, &mut datafile);

}

#[cfg(not(feature="opensslpbkdf2"))]
fn writepkbdf2(striples : &Vec<(AnyStriple,Option<Vec<u8>>)>) {
  println!("no pkbdf2 impl activated");
}

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
      Ok(AnyStriple::StripleNOKEY(sr.as_striple()))
      //Err(Error("Bad algo kind for this type of striple".to_string(), ErrorKind::UnexpectedStriple))
    },
  }
}

