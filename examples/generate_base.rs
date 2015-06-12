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
use striple::striple::BCont;
use striple::striple::{xtendsize,xtendsizeread,read_id,push_id};
use striple::stripledata;
use striple::stripledata::{BaseStriples,KindStriples};
use std::marker::PhantomData;
use striple::storage::{FileMode,write_striple,NoCypher,StorageCypher};
#[cfg(feature="public_crypto")]
use striple::striple_kind::public::crypto::PubRipemd;
#[cfg(feature="public_openssl")]
use striple::striple_kind::public::openssl::PubSha512;
#[cfg(feature="opensslrsa")]
use striple::striple_kind::Rsa2048Sha512;
#[cfg(feature="cryptoecdsa")]
use striple::striple_kind::EcdsaRipemd160;


//tmp
//use striple::striple::IDDerivation;
//use striple::storage::RemoveKey;

fn genselfpublic<K:StripleKind>(content : String, _ : PhantomData<K>) -> Striple<K> 
  where K::S : PublicScheme

{
   let typednone : Option<&Striple<K>> = None;
  // self public
  let pubcat : ( Striple<K>, Vec<u8>) = Striple::new (
    vec!(),
    typednone,
    None,
    vec!(),
    Some(BCont::OwnedBytes(content.as_bytes().to_vec())),
  );
  pubcat.0
}

fn main() {

  let pubcat = genselfpublic("CATEGORY".to_string(), get_public_kind());
  let pubkind = genselfpublic("KIND".to_string(), get_public_kind());
 

  let (pribase,prikinds) = base_gen(pubcat.get_id().to_vec(), pubkind.get_id().to_vec()).unwrap();
  let pubstriples = kind_gen(&pribase).unwrap();

  println!("Writing base to './base.data' and './base.log'");
  let mut datafile = File::create("./base.data").unwrap();
  // try!(datafile.seek(SeekFrom::Start(0)));
  let cypher = NoCypher;
  datafile.write(&cypher.get_cypher_header()).unwrap();
  printlog(&pribase,&prikinds,&pubstriples);
  let privateEnc = get_base_id(&prikinds);
  println!("base : {:?}",privateEnc);
  let publicEnc = get_kind_id(&prikinds);
  println!("base : {:?}",publicEnc);

// Temporary code -------------------------
  /*TODO generate "bitcoin timestamped by ECH" from root, about public cat (should be some others)
  TODO generate "timestamp" from self public, about signed public kind (should be some others)
  TODO generate from previous + 1, about previous, content from file containing hash as byte. calculate and print ripemd of the striple + write striple only in a file to check ripem hash ... & base64*/
    // read 
/*
    let mut commitfile = File::open("./gitcommithash.hash").unwrap();
    let mut hash = Vec::new();
    commitfile.read_to_end(&mut hash);
    let typednone : Option<&Striple<PubSha512>> = None;
    let ts : ( Striple<PubSha512>, Vec<u8>) = Striple::new(
    vec!(),
    typednone,
    Some(pubcat.get_id().to_vec()),
    vec!(),
    "bitcoin github timestamp (sha512 then ripemd160 of commit archive)".as_bytes().to_vec(),
    );

    let personalts : ( Striple<Rsa2048Sha512>, Vec<u8>) = Striple::new(
    vec!(),
    Some(&pribase.root),
    Some(pubcat.get_id().to_vec()),
    vec!(),
    "bitcoin timestamped by ECH".as_bytes().to_vec(),
    );

    let hashstamp : ( Striple<Rsa2048Sha512>, Vec<u8>) = Striple::new(
    vec!(),
    Some(&personalts),
    Some(ts.get_id().to_vec()),
    vec!(),
    hash.clone(), // nrLTWyXuy1493HDX4dD/DhsutEk=
    );
    let hashstamp2 : ( Striple<PubSha512>, Vec<u8>) = Striple::new(
    vec!(),
    Some(&hashstamp),
    None, // TODO description about id : here just some unstructured info signed by the stamp NOte that it is only informational : not well designed (a striple  + should be sha1 byte in content...
    vec!(),
    "Git commit d56fbf24d7eb4a6b924cbde3c369193685d1eb82 sha1".as_bytes().to_vec(),
    );


  let mut stripleonlyfile = File::create("./timestamp_id.data").unwrap();
  stripleonlyfile.write_all(hashstamp.get_id());

  let mut stripleonlyfile2 = File::create("./timestampinfo_id.data").unwrap();
  stripleonlyfile2.write_all(hashstamp2.get_id());

  let cypher2 = NoCypher;
  let mut datafile2 = File::create("./timestamp.data").unwrap();
  datafile2.write(&cypher2.get_cypher_header()).unwrap();
  write_striple_with_enc(&cypher2,&ts.0,None,&mut datafile2, &publicEnc).unwrap();
  write_striple_with_enc(&cypher2,&personalts.0,Some(&personalts.1),&mut datafile2, &privateEnc).unwrap();
  write_striple_with_enc(&cypher2,&hashstamp.0,Some(&hashstamp.1),&mut datafile2, &privateEnc).unwrap();
  write_striple_with_enc(&cypher2,&hashstamp2.0,None,&mut datafile2, &publicEnc).unwrap();
  let cypher3 = RemoveKey;
   let mut datafile3 = File::create("./timestamp_nokey.data").unwrap();
  datafile3.write(&cypher3.get_cypher_header()).unwrap();
  write_striple_with_enc(&cypher3,&ts.0,None,&mut datafile3, &publicEnc).unwrap();
  write_striple_with_enc(&cypher3,&personalts.0,Some(&personalts.1),&mut datafile3, &privateEnc).unwrap();
  write_striple_with_enc(&cypher3,&hashstamp.0,Some(&hashstamp.1),&mut datafile3, &privateEnc).unwrap();
  write_striple_with_enc(&cypher3,&hashstamp2.0,None,&mut datafile3, &publicEnc).unwrap();
 
*/

// End Temporary code ----------------

  write_striple_with_enc(&cypher,&pribase.root.0,Some(&pribase.root.1),&mut datafile, &privateEnc).unwrap();
  write_striple_with_enc(&cypher,&pubcat,None,&mut datafile, &publicEnc).unwrap();
  write_striple_with_enc(&cypher,&pubkind,None,&mut datafile, &publicEnc).unwrap();
 
  write_striple_with_enc(&cypher,&pribase.libcat.0,Some(&pribase.libcat.1),&mut datafile, &privateEnc).unwrap();
  write_striple_with_enc(&cypher,&pribase.libkind.0,Some(&pribase.libkind.1),&mut datafile, &privateEnc).unwrap();
  write_striple_with_enc(&cypher,&prikinds.kind.0,Some(&prikinds.kind.1),&mut datafile, &privateEnc).unwrap();
  write_striple_with_enc(&cypher,&prikinds.pubripemd.0,Some(&prikinds.pubripemd.1),&mut datafile, &privateEnc).unwrap();
  write_striple_with_enc(&cypher,&prikinds.pubsha512.0,Some(&prikinds.pubsha512.1),&mut datafile, &privateEnc).unwrap();
  write_striple_with_enc(&cypher,&prikinds.pubsha256.0,Some(&prikinds.pubsha256.1),&mut datafile, &privateEnc).unwrap();
  write_striple_with_enc(&cypher,&prikinds.rsa2048_sha512.0,Some(&prikinds.rsa2048_sha512.1),&mut datafile, &privateEnc).unwrap();
  write_striple_with_enc(&cypher,&prikinds.ecdsaripemd160.0,Some(&prikinds.ecdsaripemd160.1),&mut datafile, &privateEnc).unwrap();
  write_striple_with_enc(&cypher,&pubstriples.kind,None,&mut datafile, &publicEnc).unwrap();
  write_striple_with_enc(&cypher,&pubstriples.pubripemd,None,&mut datafile, &publicEnc).unwrap();
  write_striple_with_enc(&cypher,&pubstriples.pubsha512,None,&mut datafile, &publicEnc).unwrap();
  write_striple_with_enc(&cypher,&pubstriples.pubsha256,None,&mut datafile, &publicEnc).unwrap();
  write_striple_with_enc(&cypher,&pubstriples.rsa2048_sha512,None,&mut datafile, &publicEnc).unwrap();
  write_striple_with_enc(&cypher,&pubstriples.ecdsaripemd160,None,&mut datafile, &publicEnc).unwrap();

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

#[cfg(feature="public_openssl")]
fn get_public_kind() -> PhantomData<PubSha512> { PhantomData }
#[cfg(not(feature="public_openssl"))]
#[cfg(feature="public_crypto")]
fn get_public_kind() -> PhantomData<PubRipemd> { PhantomData }


// default to openssl if openssl and rust-crypto are enabled
#[cfg(feature="public_openssl")]
fn kind_gen<K : StripleKind>(pri : &BaseStriples<K>) -> Option<KindStriples<PubSha512>> {
  println!("Generating public sha512 base with openssl dependancy");
  gen_kind::<PubSha512,K>(pri,"Striple Lib Public Kind".to_string())
}
#[cfg(feature="public_openssl")]
fn get_kind_id<K : StripleKind>(pri : &KindStriples<K>) -> Vec<u8> {
  pri.pubsha512.0.get_id().to_vec()
}
// TODO rewrite using get_privatekind 
#[cfg(feature="opensslrsa")]
fn base_gen(cat : Vec<u8>, kind : Vec<u8>) -> Option<(BaseStriples<Rsa2048Sha512>,KindStriples<Rsa2048Sha512>)> {
  println!("Generating private RSA2048 of sha512 base with openssl dependancy");
  gen_pri::<Rsa2048Sha512>(cat, kind)
}
#[cfg(feature="opensslrsa")]
fn get_base_id<K : StripleKind>(pri : &KindStriples<K>) -> Vec<u8> {
  pri.rsa2048_sha512.0.get_id().to_vec()
}
 
#[cfg(not(feature="public_openssl"))]
#[cfg(feature="public_crypto")]
fn kind_gen<K : StripleKind>(pri : &BaseStriples<K>) -> Option<KindStriples<PubRipemd>> {
  println!("Generating public ripemd160 base with rust-crypto dependancy");
  gen_kind::<PubRipemd,K>(pri,"Striple Lib Public Kind".to_string());
}

#[cfg(not(feature="public_openssl"))]
#[cfg(feature="public_crypto")]
fn get_kind_id<K : StripleKind>(pri : &KindStriples<K>) -> Vec<u8> {
  pri.pubripem.0.get_id().to_vec()
}
 
#[cfg(not(feature="opensslrsa"))]
#[cfg(feature="cryptoecdsa")]
fn base_gen(cat : Vec<u8>, kind : Vec<u8>) -> Option<(BaseStriples<EcdsaRipemd160>,KindStriples<EcdsaRipemd160>)> {
  println!("Generating private ECDSA of ripemd160 with rust-crypto dependancy");
  gen_pri::<EcdsaRipemd160>(cat, kind)
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
fn base_gen(cat : &[u8], kind : &[u8]) -> Option<(BaseStriples<NoKind>,KindStriples<NoKind>)> {
  println!("No features enabled to allow private generation.");
  None
}
#[cfg(not(feature="opensslrsa"))]
#[cfg(not(feature="cryptoecdsa"))]
fn get_base_id<K : StripleKind>(pri : &KindStriples<K>) -> Vec<u8> {
  vec!()
}



fn gen_pri<K : StripleKind>(cat : Vec<u8>, kind : Vec<u8>) -> Option<(BaseStriples<K>,KindStriples<K>)> {
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
    Some(BCont::OwnedBytes("ROOT".as_bytes().to_vec())),
    );
  let ownedCat : (Striple<K>, Vec<u8>) = Striple::new(
    vec!(),
    Some(&ownedRoot),
    // generic category
    Some(cat),
    vec!(),
    Some(BCont::OwnedBytes("Striple Lib Categories".as_bytes().to_vec())),
    );
  let ownedKind : (Striple<K>, Vec<u8>) = Striple::new(
    vec!(),
    Some(&ownedRoot),
    // generic kind
    Some(kind),
    vec!(),
    Some(BCont::OwnedBytes("Striple Lib Kind".as_bytes().to_vec())),
    );
  let base = BaseStriples {
    root : ownedRoot,
    libcat : ownedCat,
    libkind : ownedKind,
  };
  let kinds = gen_kind(&base, "Striple Lib Verified Kind".to_string());

  Some ((base,kinds.unwrap()))
}

fn gen_kind<K : StripleKind, KF : StripleKind>(pri : &BaseStriples<KF>, catlabel : String) -> Option<KindStriples<K>> {
//fn gen_kind<K : StripleKind, KF : StripleKind>(pri : &BaseStriples<KF>, catlabel : String) -> Option<KindStriples<K>>  where K::S : PublicScheme {

 let ownedVKind : (Striple<K>, Vec<u8>) = Striple::new(
    vec!(),
    Some(&pri.root),
    Some(pri.libcat.0.get_about().to_vec()),
    vec!(),
    Some(BCont::OwnedBytes(catlabel.as_bytes().to_vec())),
    );
 let pubripem : (Striple<K>, Vec<u8>) = Striple::new(
    vec!(),
    Some(&ownedVKind),
    Some(pri.libkind.0.get_about().to_vec()),
    vec!(),
    Some(BCont::OwnedBytes("Public Ripemd160 derivation".as_bytes().to_vec())),
    );
 let pubsha512 : (Striple<K>, Vec<u8>) = Striple::new(
    vec!(),
    Some(&ownedVKind),
    Some(pri.libkind.0.get_about().to_vec()),
    vec!(),
    Some(BCont::OwnedBytes("Public Sha512 derivation".as_bytes().to_vec())),
    );
 let pubsha256 : (Striple<K>, Vec<u8>) = Striple::new(
    vec!(),
    Some(&ownedVKind),
    Some(pri.libkind.0.get_about().to_vec()),
    vec!(),
    Some(BCont::OwnedBytes("Public Sha256 derivation".as_bytes().to_vec())),
    );
 let rsa2048_sha512 : (Striple<K>, Vec<u8>) = Striple::new(
    vec!(),
    Some(&ownedVKind),
    Some(pri.libkind.0.get_about().to_vec()),
    vec!(),
    Some(BCont::OwnedBytes("RSA 2048 Sha512 derivation".as_bytes().to_vec())),
    );
 let ecdsaripemd160 : (Striple<K>, Vec<u8>) = Striple::new(
    vec!(),
    Some(&ownedVKind),
    Some(pri.libkind.0.get_about().to_vec()),
    vec!(),
    Some(BCont::OwnedBytes("ECDSA(ED25519) Ripemd160 derivation".as_bytes().to_vec())),
    );
   Some(KindStriples {
     kind : ownedVKind,
     pubripemd : pubripem,
     pubsha512 : pubsha512,
     pubsha256 : pubsha256,
     rsa2048_sha512 : rsa2048_sha512,
     ecdsaripemd160 : ecdsaripemd160,
   })
}




// read and rewrite striple except enc being replace by newone
pub fn write_striple_with_enc
  <SC : StorageCypher, 
   S  : StripleIf,
    > (cypher : & SC, striple : &S, pkey : Option<&[u8]>, dest : &mut File, enc : &[u8]) -> IoResult<()> {
 
//  write_striple(cypher,striple,dest)

  let mut tmpvec : Vec<u8> = Vec::new();
  let mut buf = &mut Cursor::new(tmpvec);

  try!(write_striple(cypher,striple,pkey,&FileMode::NoFile,buf));


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
