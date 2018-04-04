
#![feature(proc_macro)]

extern crate striple;
#[cfg(target_arch = "wasm32")]
#[macro_use] extern crate stdweb;
#[cfg(target_arch = "wasm32")]
use self::stdweb::{
  js_export,
};
#[cfg(target_arch = "wasm32")]
use self::stdweb::web::{
  Blob,
  TypedArray,
  ArrayBuffer,
};
use std::io::Cursor;
use self::striple::striple::{
  Striple,
  StripleIf,
  StripleFieldsIf,
  OwnedStripleIf,
  OwnedStripleFieldsIf,
  BCont,
  striple_dser_with_def,
  NoKind,
  StripleRef,
  Error,
};
/*#[cfg(target_arch = "wasm32")]
use self::striple::stripledata::{
  wasm_set_base, 
};*/

use self::striple::{
  StripleBug,
};
use self::striple::anystriple::{
  AnyStriple,
  PubRipemd,
  init_wasm_vec,
  copy_builder_any,
};
//use std::mem::transmute;
use self::striple::storage::{
  FileStripleIterator,
  init_any_cipher_stdin,
  AnyCyphers,
};
use std::fs::File;


fn main() {
  // placeholder
}

#[cfg(target_arch = "wasm32")]
#[js_export]
fn init_base(base : TypedArray<u8>) {

  let b : Vec<u8> = base.to_vec();
}

#[cfg(target_arch = "wasm32")]
#[js_export]
fn init_base2(base : ArrayBuffer) {

}
#[cfg(target_arch = "wasm32")]
#[js_export]
fn init_base3(base : String) {

}
#[no_mangle]
pub extern "C" fn test2() {
//  let datafile = Cursor::new(Vec::new());
  // following line fail to link in wasm32
//  let striples : Vec<(AnyStriple,Option<Vec<u8>>)> = init_wasm_vec(datafile);
}
#[no_mangle]
pub extern "C" fn test3() {
  // just this line
  StripleBug::dd ( );
}

 
#[cfg(target_arch = "wasm32")]
#[js_export]
fn test(fp : TypedArray<u8>) {
  console!(log,"test start : ", &fp);
  // code from exemple load base
  let datafile = Cursor::new(fp.to_vec());
  //let datafile = File::open("base.data").unwrap();
  let rit : Result<FileStripleIterator<NoKind,AnyStriple,_,_,_>,_> = FileStripleIterator::init(datafile, copy_builder_any, &init_any_cipher_stdin, ()); 
/*  let striples : Vec<(AnyStriple,Option<Vec<u8>>)> = rit.unwrap().collect();

  // Doing some check based upon knowned structure
  if striples[0].1.is_some() {
    console!(log,"doing root checking");
    let ownedroot = (&striples[0].0, &striples[0].1.as_ref().unwrap()[..]);

    // try sign check to check privatekey encryption
    let cont = vec!(56,84,8,46,250,6,8,7);

    let sign = ownedroot.sign_content(&ownedroot.private_key_ref(),&mut Cursor::new(&cont[..])).unwrap();
    console!(log,format!("SIGN : {:?} {:?}",sign.len(),sign));
    assert!(ownedroot.check_content(&mut Cursor::new(&cont[..]),&sign[..]).unwrap());


    assert!(striples[3].0.check(&ownedroot).unwrap() == true);
    assert!(striples[4].0.check(&ownedroot).unwrap() == true);
  }
  // Doing some public check
   if striples[11].1.is_none() {
    console!(log,"doing public checking");
    let ownedkind = (&striples[11].0, &[][..]);

    assert!(striples[13].0.check(&ownedkind).unwrap() == true);
    assert!(striples[14].0.check(&ownedkind).unwrap() == true);
  }
*/
  console!(log,"test end");
}

