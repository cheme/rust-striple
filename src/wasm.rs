/*

extern crate striple;
/*#[cfg(target_arch = "wasm32")]
use self::striple::stripledata::{
  wasm_set_base, 
};*/

use self::striple::{
  StripleBug,
};
//use std::mem::transmute;


fn main() {
  // placeholder
}

#[no_mangle]
pub extern "C" fn test3() {
  // just this line
  StripleBug::dd ( );
}
*/


#![feature(proc_macro)]
extern crate striple;
#[cfg(target_arch = "wasm32")]
use std::mem;
#[cfg(target_arch = "wasm32")]
#[macro_use] extern crate stdweb;
#[cfg(target_arch = "wasm32")]
use self::stdweb::{
  Value as StdValue,
  js_export,
};

#[cfg(target_arch = "wasm32")]
use std::os::raw::{
  c_char,
  c_void,
};
#[cfg(target_arch = "wasm32")]
use self::stdweb::unstable::{
  TryFrom,
};
#[cfg(target_arch = "wasm32")]
use self::stdweb::web::{
  Blob,
  TypedArray,
  ArrayBuffer,
};
use self::striple::stripledata::{
 init_kind_striple_ids,
 init_base_striple,
 KINDIDS,
};
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
use std::io::Cursor;
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
fn test(fp : TypedArray<u8>) -> i32 {
  console!(log,"test start : ", &fp);
  // code from exemple load base
  let datafile = Cursor::new(fp.to_vec());
  //let datafile = File::open("base.data").unwrap();
  let rit : Result<FileStripleIterator<NoKind,AnyStriple,_,_,_>,_> = FileStripleIterator::init(datafile, copy_builder_any, &init_any_cipher_stdin, ());
  let striples : Vec<(AnyStriple,Option<Vec<u8>>)> = rit.unwrap().collect();

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

  let kind = KINDIDS.as_ref().unwrap();
    //init_kind_striple_ids().unwrap();
  // build from pub striple
  let (st,st_priv) = AnyStriple::new(
    &kind.ecdsaripemd160[..],
    Vec::new(), // contentenc : 
    &(&striples[11].0,&Vec::new()[..]), // from
    Some(striples[0].0.get_id().to_vec()), // about
    Vec::new(), // contentids
    None, // content
  ).unwrap();
  console!(log,format!("ecdsa striple : {:?}",&st));
  // fail on rand of uuid v4!!
  let (st,st_priv) = AnyStriple::new(
    &kind.pubripemd[..],
    Vec::new(), // contentenc : 
    &(&striples[11].0,&Vec::new()[..]), // from
    Some(striples[0].0.get_id().to_vec()), // about
    Vec::new(), // contentids
    None, // content
  ).unwrap();

  console!(log,format!("pub ripem striple : {:?}",&st));
  console!(log,"test end");
  let b = Box::new(striples[0].0.clone());
  Box::into_raw(b) as i32
}

// TODO see alternative for box reference
#[cfg(target_arch = "wasm32")]
#[js_export]
fn striple_check(st : i32, from : i32) -> bool {
  let st_ob = unsafe { Box::from_raw(st as *mut AnyStriple) };
  let res = st_ob.get_key().len() == from as usize;
  mem::forget(st_ob);
  res
//  let from_ob = unsafe { Box::from_raw(from as *mut AnyStriple) };
//  st_ob.check(from_ob.as_ref()).unwrap()
}
#[cfg(target_arch = "wasm32")]
#[js_export]
fn striple_len(st : i32) -> i32 {
  let st_ob = unsafe { Box::from_raw(st as *mut AnyStriple) };
  let res = st_ob.get_key().len() as i32;
  mem::forget(st_ob);
  res
//  let from_ob = unsafe { Box::from_raw(from as *mut AnyStriple) };
//  st_ob.check(from_ob.as_ref()).unwrap()
}


/*
pub unsafe extern "C" fn striple_check(st : striple_ptr, from : striple_ptr) -> bool {
  let s : &AnyStriple = transmute(st.0);
  let f : &AnyStriple = transmute(from);
  //let s : &StripleIf = transmute(st);
  //let f : &StripleIf = transmute(from);
  s.check(f).unwrap_or(false)
}

*/
