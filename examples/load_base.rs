//! load base striple from a file
//! this is an example of how to resolve types if they are not known at launch.
extern crate striple;
use std::fs::File;
use std::io::{stdin,BufRead};
use std::io::Cursor;
use striple::storage::FileStripleIterator;
use striple::striple::NoKind;
use striple::anystriple::{AnyStriple, copy_builder_any};
//use striple::striple::copy_as_kind;
use striple::striple::{
  StripleIf,
  OwnedStripleIf,
  StripleFieldsIf,
  OwnedStripleFieldsIf,
};

use striple::storage::{FileMode,write_striple_file_ref,RemoveKey,init_any_cipher_stdin};
#[cfg(feature="opensslpbkdf2")]
use striple::storage::Pbkdf2;

/// load base file produced by generate example (privatekey clear).
/// Plus write base file without password or with encrypted password.
fn main() {
  let datafile = File::open("./baseperm.data").unwrap();
  let rit : Result<FileStripleIterator<NoKind,AnyStriple,_,_,_>,_> = FileStripleIterator::init(datafile, copy_builder_any, &init_any_cipher_stdin, ()); 
  let striples : Vec<(AnyStriple,Option<Vec<u8>>)> = rit.unwrap().collect();

  // Doing some check based upon knowned structure
  if striples[0].1.is_some() {
    println!("doing root checking");
    let ownedroot = (&striples[0].0, &striples[0].1.as_ref().unwrap()[..]);

    // try sign check to check privatekey encryption
    let cont = vec!(56,84,8,46,250,6,8,7);

    let sign = ownedroot.sign_content(&ownedroot.private_key_ref(),&mut Cursor::new(&cont[..])).unwrap();
/*    let mut pkey = PKey::new();
    pkey.load_priv (&ownedroot.private_key()[..]);
    let mut pemfile = File::create("./pem.pem").unwrap();
    let mut sigfile = File::create("./sig.sig").unwrap();
    pkey.write_pem(&mut pemfile);
    sigfile.write_all(&sign[..]);
 */   
    println!("SIGN{:?}:{:?}", sign.len(), sign);
    assert!(ownedroot.check_content(&mut Cursor::new(&cont[..]),&sign[..]).unwrap());


    assert!(striples[3].0.check(&ownedroot).unwrap() == true);
    assert!(striples[4].0.check(&ownedroot).unwrap() == true);
  }
  // Doing some public check
   if striples[11].1.is_none() {
    println!("doing public checking");
    let ownedkind = (&striples[11].0, &[][..]);

    assert!(striples[13].0.check(&ownedkind).unwrap() == true);
    assert!(striples[14].0.check(&ownedkind).unwrap() == true);
  }
 
  // rewrite without private key for publishing

  let mut datafile = File::create("./baseperm_nokey.data").unwrap();
  //  let refvec : Vec<(&AnyStriple,Option<&[u8]>)> = striples.iter().map(|i|(&i.0,i.1.as_ref().map(|o|&o[..]))).collect();
  let mut it = striples.iter().map(|i|(&i.0,i.1.as_ref().map(|o|&o[..])));
  // let wr = write_striple_file_ref(&RemoveKey, &mut refvec.iter(), &mut datafile);
  write_striple_file_ref(&RemoveKey, &mut it, &FileMode::NoFile, &mut datafile).unwrap();

  writepkbdf2(&striples);

  print!("hello");


}

#[cfg(feature="opensslpbkdf2")]
fn writepkbdf2(striples : &Vec<(AnyStriple,Option<Vec<u8>>)>) {
  
  let mut datafile = File::create("./baseperm_pbkdf2.data").unwrap();

  let mut it = striples.iter().map(|i|(&i.0,i.1.as_ref().map(|o|&o[..])));

  println!("writing as protected, please input passphrase ?");
  let tstdin = stdin();
  let mut stdin = tstdin.lock();
  let mut pass = String::new();
  stdin.read_line(&mut pass).unwrap();
  // remove terminal \n
  pass.pop();
  let pbk = Pbkdf2::new(pass,2000,Pbkdf2::gen_salt().unwrap()).unwrap();
  write_striple_file_ref(&pbk, &mut it, &FileMode::NoFile, &mut datafile).unwrap();

}

#[cfg(not(feature="opensslpbkdf2"))]
fn writepkbdf2(striples : &Vec<(AnyStriple,Option<Vec<u8>>)>) {
  println!("no pkbdf2 impl activated");
}


