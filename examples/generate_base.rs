//! Code used to initiate triples used by the lib (striple kind, root...).
//! Both public and signed version are generated.
#![feature(debug_builders)]
extern crate striple;
use std::fs::File;
use std::io::Write;
use std::io::Result as IoResult;
use std::io::{Cursor,Read,Seek,SeekFrom};
use striple::striple::Striple;
use striple::striple::{PubStriple,PublicScheme};
use striple::striple::{StripleIf,StripleDisp};
use striple::striple::{OwnedStripleIf,UnsafeOwnedStripleDisp};
use striple::striple::StripleKind;
use striple::striple::NoKind;
use striple::striple::{xtendsize,xtendsizeread,read_id,push_id};
use striple::stripledata;
use striple::stripledata::{BaseStriples,KindStriples};
use std::marker::PhantomData;
use striple::storage::{write_striple,NoCypher,StorageCypher, MaybeOwnedStriple};
#[cfg(feature="public_crypto")]
use striple::striple_kind::public::crypto::PubRipemd;
#[cfg(feature="public_openssl")]
use striple::striple_kind::public::openssl::PubSha512;
#[cfg(feature="opensslrsa")]
use striple::striple_kind::Rsa2048Sha512;
#[cfg(feature="cryptoecdsa")]
use striple::striple_kind::EcdsaRipemd160;




fn main() {
  let (pribase,prikinds) = base_gen().unwrap();
  let pubstriples = kind_gen(&pribase).unwrap();

  println!("Writing base to './base.data' and './base.log'");
  let mut datafile = File::create("./base.data").unwrap();
  // try!(datafile.seek(SeekFrom::Start(0)));
  let cypher = NoCypher;
  datafile.write(&NoCypher::get_cypher_header()).unwrap();
  printlog(&pribase,&prikinds,&pubstriples);
  //write_striple::<_,_,_,(Striple<NoKind>,Vec<u8>),_>(&cypher,&MaybeOwnedStriple::Owned(pribase.root,PhantomData),&mut datafile).unwrap();
  
  let baseId = get_base_id(&prikinds);
  println!("base : {:?}",baseId);
  let kindId = get_kind_id(&prikinds);
  println!("base : {:?}",kindId);
  
  write_striple_with_enc::<_,_,Striple<_>,_>(&cypher,&MaybeOwnedStriple::Owned(pribase.root,PhantomData),&mut datafile, &baseId).unwrap();
  write_striple_with_enc::<_,_,Striple<_>,_>(&cypher,&MaybeOwnedStriple::Owned(pribase.libcat,PhantomData),&mut datafile, &baseId).unwrap();
  write_striple_with_enc::<_,_,Striple<_>,_>(&cypher,&MaybeOwnedStriple::Owned(pribase.libkind,PhantomData),&mut datafile, &baseId).unwrap();
  write_striple_with_enc::<_,_,Striple<_>,_>(&cypher,&MaybeOwnedStriple::Owned(prikinds.kind,PhantomData),&mut datafile, &baseId).unwrap();
  write_striple_with_enc::<_,_,Striple<_>,_>(&cypher,&MaybeOwnedStriple::Owned(prikinds.pubripemd,PhantomData),&mut datafile, &baseId).unwrap();
  write_striple_with_enc::<_,_,Striple<_>,_>(&cypher,&MaybeOwnedStriple::Owned(prikinds.pubsha512,PhantomData),&mut datafile, &baseId).unwrap();
  write_striple_with_enc::<_,_,Striple<_>,_>(&cypher,&MaybeOwnedStriple::Owned(prikinds.pubsha256,PhantomData),&mut datafile, &baseId).unwrap();
  write_striple_with_enc::<_,_,Striple<_>,_>(&cypher,&MaybeOwnedStriple::Owned(prikinds.rsa2048Sha512,PhantomData),&mut datafile, &baseId).unwrap();
  write_striple_with_enc::<_,_,Striple<_>,_>(&cypher,&MaybeOwnedStriple::Owned(prikinds.ecdsaripemd160,PhantomData),&mut datafile, &baseId).unwrap();
  write_striple_with_enc::<_,_,_,(Striple<_>,Vec<u8>)>(&cypher,&MaybeOwnedStriple::NoOwn(pubstriples.kind,PhantomData),&mut datafile, &kindId).unwrap();
  write_striple_with_enc::<_,_,_,(Striple<_>,Vec<u8>)>(&cypher,&MaybeOwnedStriple::NoOwn(pubstriples.pubripemd,PhantomData),&mut datafile, &kindId).unwrap();
  write_striple_with_enc::<_,_,_,(Striple<_>,Vec<u8>)>(&cypher,&MaybeOwnedStriple::NoOwn(pubstriples.pubsha512,PhantomData),&mut datafile, &kindId).unwrap();
  write_striple_with_enc::<_,_,_,(Striple<_>,Vec<u8>)>(&cypher,&MaybeOwnedStriple::NoOwn(pubstriples.pubsha256,PhantomData),&mut datafile, &kindId).unwrap();
  write_striple_with_enc::<_,_,_,(Striple<_>,Vec<u8>)>(&cypher,&MaybeOwnedStriple::NoOwn(pubstriples.rsa2048Sha512,PhantomData),&mut datafile, &kindId).unwrap();
  write_striple_with_enc::<_,_,_,(Striple<_>,Vec<u8>)>(&cypher,&MaybeOwnedStriple::NoOwn(pubstriples.ecdsaripemd160,PhantomData),&mut datafile, &kindId).unwrap();


}

#[cfg(feature="serialize")]
fn printlog<K1 : StripleKind, K2 : StripleKind> (pribase : &BaseStriples<K1>, prikind : &KindStriples<K1>, pubstriples : &KindStriples<K2>) {
  // use base64
  let mut logfile = File::create("./base.log").unwrap();
  write!(&mut logfile,"{}", pribase);
  write!(&mut logfile,"{}", prikind);
  write!(&mut logfile,"{}", pubstriples);

}
#[cfg(not(feature="serialize"))]
fn printlog<K1 : StripleKind, K2 : StripleKind> (pribase : &BaseStriples<K1>, prikind : &KindStriples<K1>, pubstriples : &KindStriples<K2>) {
  let mut logfile = File::create("./base.log").unwrap();
  write!(&mut logfile,"{:?}", pribase);
  write!(&mut logfile,"{:?}", prikind);
  write!(&mut logfile,"{:?}", pubstriples);

}

// default to openssl if openssl and rust-crypto are enabled
#[cfg(feature="public_openssl")]
fn kind_gen<K : StripleKind>(pri : &BaseStriples<K>) -> Option<KindStriples<PubSha512>> {
  println!("Generating public sha512 base with openssl dependancy");
  gen_pub::<PubSha512,K>(pri,"Striple Lib Public Kind".to_string())
}
#[cfg(feature="public_openssl")]
fn get_kind_id<K : StripleKind>(pri : &KindStriples<K>) -> Vec<u8> {
  pri.pubsha512.0.get_id().to_vec()
}
 
#[cfg(feature="opensslrsa")]
fn base_gen() -> Option<(BaseStriples<Rsa2048Sha512>,KindStriples<Rsa2048Sha512>)> {
  println!("Generating private RSA2048 of sha512 base with openssl dependancy");
  gen_pri::<Rsa2048Sha512>()
}
#[cfg(feature="opensslrsa")]
fn get_base_id<K : StripleKind>(pri : &KindStriples<K>) -> Vec<u8> {
  pri.rsa2048Sha512.0.get_id().to_vec()
}
 
#[cfg(not(feature="public_openssl"))]
#[cfg(feature="public_crypto")]
fn kind_gen<K : StripleKind>(pri : &BaseStriples<K>) -> Option<KindStriples<PubRipemd>> {
  println!("Generating public ripemd160 base with rust-crypto dependancy");
  gen_pub::<PubRipemd,K>(pri,"Striple Lib Public Kind".to_string());
}

#[cfg(not(feature="public_openssl"))]
#[cfg(feature="public_crypto")]
fn get_kind_id<K : StripleKind>(pri : &KindStriples<K>) -> Vec<u8> {
  pri.pubripem.0.get_id().to_vec()
}
 
#[cfg(not(feature="opensslrsa"))]
#[cfg(feature="cryptoecdsa")]
fn base_gen() -> Option<(BaseStriples<EcdsaRipemd160>,KindStriples<EcdsaRipemd160>)> {
  println!("Generating private ECDSA of ripemd160 with rust-crypto dependancy");
  gen_pri::<EcdsaRipemd160>()
}

#[cfg(not(feature="opensslrsa"))]
#[cfg(feature="cryptoecdsa")]
fn get_base_id<K : StripleKind>(pri : &KindStriples<K>) -> Vec<u8> {
  pri.ecdsaripemd160.0.get_id().to_vec()
}

#[cfg(not(feature="public_openssl"))]
#[cfg(not(feature="public_crypto"))]
fn kind_gen<K : StripleKind>(_ : &BaseStriples<K>) -> Option<KindStriples<NoKind>> {
  println!("No features enabled to  allow public generation.");
  None
}

#[cfg(not(feature="public_openssl"))]
#[cfg(not(feature="public_crypto"))]
fn get_kind_id<K : StripleKind>(pri : &KindStriples<K>) -> Vec<u8> {
  vec!()
}
 
#[cfg(not(feature="opensslrsa"))]
#[cfg(not(feature="cryptoecdsa"))]
fn base_gen() -> Option<(BaseStriples<NoKind>,KindStriples<NoKind>)> {
  println!("No features enabled to allow private generation.");
  None
}
#[cfg(not(feature="opensslrsa"))]
#[cfg(not(feature="cryptoecdsa"))]
fn get_base_id<K : StripleKind>(pri : &KindStriples<K>) -> Vec<u8> {
  vec!()
}



fn gen_pri<K : StripleKind>() -> Option<(BaseStriples<K>,KindStriples<K>)> {
  let typednone : Option<&(Striple<K>, Vec<u8>)> = None;
  let ownedRoot : (Striple<K>, Vec<u8>) = Striple::new(
    // No meta (content encoding def)
    vec!(),
    // recursive from
    typednone,
    // recursive about
    None,
    // no contentids
    vec!(),
    // Easilly identifiable content
    "ROOT".as_bytes().to_vec(),
    );
  let ownedCat : (Striple<K>, Vec<u8>) = Striple::new(
    vec!(),
    Some(&ownedRoot),
    // recursive about // TODO change by public generic kind??
    None,
    vec!(),
    "Striple Lib Categories".as_bytes().to_vec(),
    );
  let ownedKind : (Striple<K>, Vec<u8>) = Striple::new(
    vec!(),
    Some(&ownedRoot),
    // recursive about // TODO change by public generic category??
    None,
    vec!(),
    "Striple Lib Kind".as_bytes().to_vec(),
    );
  let base = BaseStriples {
    root : ownedRoot,
    libcat : ownedCat,
    libkind : ownedKind,
  };
  let kinds = gen_pub(&base, "Striple Lib Verified Kind".to_string());

  Some ((base,kinds.unwrap()))
}

fn gen_pub<K : StripleKind, KF : StripleKind>(pri : &BaseStriples<KF>, catlabel : String) -> Option<KindStriples<K>> {
//fn gen_pub<K : StripleKind, KF : StripleKind>(pri : &BaseStriples<KF>, catlabel : String) -> Option<KindStriples<K>>  where K::S : PublicScheme {

 let ownedVKind : (Striple<K>, Vec<u8>) = Striple::new(
    vec!(),
    Some(&pri.root),
    Some(pri.libcat.0.get_about().to_vec()),
    vec!(),
    catlabel.as_bytes().to_vec(),
    );
 let pubripem : (Striple<K>, Vec<u8>) = Striple::new(
    vec!(),
    Some(&ownedVKind),
    Some(pri.libkind.0.get_about().to_vec()),
    vec!(),
    "Public Ripemd160 derivation".as_bytes().to_vec(),
    );
 let pubsha512 : (Striple<K>, Vec<u8>) = Striple::new(
    vec!(),
    Some(&ownedVKind),
    Some(pri.libkind.0.get_about().to_vec()),
    vec!(),
    "Public Sha512 derivation".as_bytes().to_vec(),
    );
 let pubsha256 : (Striple<K>, Vec<u8>) = Striple::new(
    vec!(),
    Some(&ownedVKind),
    Some(pri.libkind.0.get_about().to_vec()),
    vec!(),
    "Public Sha512 derivation".as_bytes().to_vec(),
    );
 let rsa2048Sha512 : (Striple<K>, Vec<u8>) = Striple::new(
    vec!(),
    Some(&ownedVKind),
    Some(pri.libkind.0.get_about().to_vec()),
    vec!(),
    "RSA 2048 Sha512 derivation".as_bytes().to_vec(),
    );
 let ecdsaripemd160 : (Striple<K>, Vec<u8>) = Striple::new(
    vec!(),
    Some(&ownedVKind),
    Some(pri.libkind.0.get_about().to_vec()),
    vec!(),
    "ECDSA(ED25519) Ripemd160 derivation".as_bytes().to_vec(),
    );
   Some(KindStriples {
     kind : ownedVKind,
     pubripemd : pubripem,
     pubsha512 : pubsha512,
     pubsha256 : pubsha256,
     rsa2048Sha512 : rsa2048Sha512,
     ecdsaripemd160 : ecdsaripemd160,
   })
}




// read and rewrite striple except enc being replace by newone
pub fn write_striple_with_enc
  <SC : StorageCypher, 
   SK : StripleKind,
   S  : StripleIf<SK>,
   OS : OwnedStripleIf<SK>,
    > (cypher : & SC, striple : &MaybeOwnedStriple<SK,OS,S>,  dest : &mut File, enc : &[u8]) -> IoResult<()> {
 
//  write_striple(cypher,striple,dest)

  let mut tmpvec : Vec<u8> = Vec::new();
  let mut buf = &mut Cursor::new(tmpvec);

  try!(write_striple(cypher,striple,buf));


  try!(buf.seek(SeekFrom::Start(0)));
  let tag = &mut [0];
  buf.read(tag);
  try!(dest.write_all(tag));
  let privsize = try!(xtendsizeread(buf, 2));
  try!(dest.write_all(&xtendsize(privsize,2)));
  let mut pkey = vec![0;privsize];
  try!(buf.read(&mut pkey[..]));
  try!(dest.write_all(&pkey));
  let ssize = try!(xtendsizeread(buf, 4));
  let mut st = vec![0;ssize];
  try!(buf.read(&mut st[..]));
  let mut ix = 0;
  // skip old enc_id
  read_id (&st, &mut ix);
  let end = &st[ix..];

  let mut encvec = vec!();
  push_id(&mut encvec, enc);
  
  try!(dest.write_all(&xtendsize(encvec.len()+end.len(),4)));
  try!(dest.write_all(&encvec));
  try!(dest.write_all(end));

  Ok(())

}
