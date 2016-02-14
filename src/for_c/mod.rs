//! External C interface.
//!
//! Currently all striples are AnyStriple, allowing monomorphism in constructor TODO swith
//! constructor to use trait param for from??
//! 
//! Lot of missing usecase.
//!
//! Std should be prohibited (here there seems to be no pb, but it may occurs (for instance CString
//! usage results in segfault when dropped).
//!
//! TODO lot of read error under valgrind
//! TODO Free fn seems useless 
//! TODO Construct of striple not tested (probably not working (replace option by nullable pointers))
//!


use striple::{StripleIf,OwnedStripleIf,BCont,striple_dser,NoKind,StripleRef,Error};
use anystriple::{AnyStriple,copy_builder_any};
use std::mem::transmute;
use storage::{FileStripleIterator,init_any_cipher_stdin,AnyCyphers};
use std::fs::File;
use libc::{size_t,c_char,strlen};
use std::ptr;
use std::slice;

#[repr(C)]
pub type striple_ptr = *const AnyStriple;
//pub type striple_ptr = *const StripleIf;

#[repr(C)]
pub type owned_striple_ptr = *const (AnyStriple, Vec<u8>);
//pub type owned_striple_ptr = *const OwnedStripleIf;

#[repr(C)]
pub struct either_owned {
    s : striple_ptr,
    os : owned_striple_ptr,
}


pub type CIfIter = FileStripleIterator<NoKind,AnyStriple,File,AnyCyphers,fn(&[u8], StripleRef<NoKind>) -> Result<AnyStriple, Error> >;

// TODO find a way to get rid of this useless B (refact api?to trait param)
//#[repr(C)]
//pub struct striple_iter (*mut FileStripleIterator<NoKind,AnyStriple,File,AnyCyphers,fn(&[u8], StripleRef<NoKind>) -> Result<AnyStriple, Error> >);
#[repr(C)]
pub type striple_iter = *mut CIfIter;

//fn(&[u8], StripleRef<'_, NoKind>) -> Result<AnyStriple, Error> {copy_builder_any}
#[repr(C)]
pub struct striple_bytes {
  bytes : *const u8,
  length : size_t,
}

#[repr(C)]
pub struct striple_bytes_array {
  sb : *const striple_bytes,
  length : size_t,
}

#[repr(C)]
pub struct striple_bcont {
  bytes : *const u8,
  length : size_t,
  ispath : bool,
}

#[no_mangle]
pub unsafe extern "C" fn free_iter(st : striple_iter) {
  drop(st)
}
#[no_mangle]
pub unsafe extern "C" fn free_striple(st : striple_ptr) {
  drop(st)
}
#[no_mangle]
pub unsafe extern "C" fn free_owned_striple(st : owned_striple_ptr) {
  drop(st)
}
#[no_mangle]
pub unsafe extern "C" fn free_sba(st : striple_bytes_array) {
  drop(st)
}
#[no_mangle]
pub unsafe extern "C" fn free_sb(st : striple_bytes) {
  drop(st)
}
#[no_mangle]
pub unsafe extern "C" fn free_bcont(st : striple_bcont) {
  drop(st)
}


#[no_mangle]
pub unsafe extern "C" fn striple_check(st : striple_ptr, from : striple_ptr) -> bool {
  let s : &AnyStriple = transmute(st);
  let f : &AnyStriple = transmute(from);
  //let s : &StripleIf = transmute(st);
  //let f : &StripleIf = transmute(from);
  s.check(f)
}

macro_rules! getter(($en:ident) => (

#[no_mangle]
pub unsafe extern "C" fn $en(st : striple_ptr) -> striple_bytes {
  //let s : &StripleIf = transmute(st);
  let disp : *const () = transmute(st);
  println!("get from : {:?}",disp);
  let s : &AnyStriple = transmute(st); // Note that it is also somehow fine for (AnyStriple,Vec<u8>), but in most case we should convert owned striple to its striple (no polymorphism here).
  let b = s.$en();
  striple_bytes{
    bytes : transmute(b.as_ptr()),
    length : b.len() as size_t,
  }
}

)
);
 

getter!(get_enc);
getter!(get_id);
getter!(get_about);
getter!(get_key);
getter!(get_algo_key);
getter!(get_sig);


#[no_mangle]
pub unsafe extern "C" fn private_key(st : owned_striple_ptr) -> striple_bytes {
  //let s : &OwnedStripleIf = transmute(st);
  let s : &(AnyStriple, Vec<u8>) = transmute(st);
  let b = s.private_key_ref();
  striple_bytes {
    bytes : transmute(b.as_ptr()),
    length : b.len() as size_t,
  }
}

// TODO not fully tested (only ownedbytes)
#[no_mangle]
pub unsafe extern "C" fn get_content(st : striple_ptr) -> striple_bcont {
  //let s : &StripleIf = transmute(st);
  let s : &AnyStriple = transmute(st);
  let os = s.get_content();
  os.as_ref().map(|s|
  match s {
    &BCont::OwnedBytes(ref b) => {
      striple_bcont {
        bytes : transmute((&b[..]).as_ptr()),
        length : b.len() as size_t,
        ispath : false,
      }
    },
    &BCont::NotOwnedBytes(ref b) => {
      let bb = Box::new(b);
      striple_bcont {
        bytes : transmute(&(*bb)),
        length : b.len() as size_t,
        ispath : false,
      }
    },
    &BCont::LocalPath(ref path) => {
      let b = path.to_str().unwrap().as_bytes();
      let bb = Box::new(b);
      striple_bcont {
        bytes : transmute(&(*bb)),
        length : b.len() as size_t,
        ispath : true,
      }
    },
  }).unwrap_or(
    striple_bcont {
        bytes : ptr::null(),
        length : 0,
        ispath : false,
      }
  )
}


// Not tested shoud fail
#[no_mangle]
pub unsafe extern "C" fn get_content_ids(st : striple_ptr) -> striple_bytes_array {
  //let s : &StripleIf = transmute(st);
  let s : &AnyStriple = transmute(st);
  let bs = s.get_content_ids();
  let c : Vec<striple_bytes> = *Box::new(bs.iter().map(|b|
  striple_bytes {
    bytes : transmute(b.as_ptr()),
    length : b.len() as size_t,
  }).collect());
  striple_bytes_array {
    sb : transmute(c.as_ptr()),
    length : c.len() as size_t,
  }
}


// init from c byte buffer using any striple
// TODO bcont as optional parameter!!!
// TODO untested
#[no_mangle]
pub unsafe extern "C" fn any_parse_striple(input : *mut u8, input_length : size_t) -> striple_ptr {
  let len = input_length as usize;
  let invec = Vec::from_raw_parts(input, len, len);
  let typednone : Option<&AnyStriple> = None; 
  match striple_dser(&invec[..], None, typednone, copy_builder_any) {
    Ok(st) => {
      // not need heap allocate, maybe with a anystriple version ref ???
      let h = Box::new(st);
      &(*h)
    },
    Err(_) => ptr::null(),
  }
}

// TODO init from all fields (Striple) + id for any or a constructor per type
#[no_mangle]
pub unsafe extern "C" fn new_striple(
  algoid : *mut u8, 
  algo_l : size_t,
  contentenc : *mut u8,
  cenc_l : size_t,
  from : Option<owned_striple_ptr>,
  about : Option<*mut u8>,
  about_l : size_t,
  _ : Option<striple_bytes_array>,
  _ : Option<striple_bcont>,
  ) -> Option<owned_striple_ptr> {
/*
 *  pub fn new<SF : OwnedStripleIf> (
    algoid :&[u8], 
    contentenc : Vec<u8>,
    from : Option<&SF>,
    about: Option<Vec<u8>>,
    contentids : Vec<Vec<u8>>,
    content : Option<BCont<'static>>,
  ) -> Result<(AnyStriple,Vec<u8>), Error> {
 
 *
 **/
  
  let algo = Vec::from_raw_parts(algoid, algo_l as usize , algo_l as usize);
  let enc = Vec::from_raw_parts(contentenc, cenc_l as usize , cenc_l as usize);
  let rfrom : Option<&OwnedStripleIf> = match from {
    Some(ptr) => {
      let ef : &(AnyStriple, Vec<u8>) = transmute(ptr);
      Some(&(*ef))
    },
    None => None,
  };
  let rabout = about.map(|a|Vec::from_raw_parts(a, about_l as usize, about_l as usize));
 
  let oany = AnyStriple::new(
    &algo[..],
    enc,
    rfrom,
    rabout,
    // no contentids TODO complete !!!
    vec!(),
    // Bcont TODO complete!!!
    None,
    ).ok();
    match oany {
      Some(a) => {
        Some(&a)
      },
      None => None,
    }
 
}
 
//fn(&[u8], StripleRef<'_, NoKind>) -> Result<AnyStriple, Error> {copy_builder_any}
// TODO init from file (storage)

#[no_mangle]
pub unsafe extern "C" fn file_iter(cpath : *const c_char) -> striple_iter {
  println!("Start file iter");
//  let path = CString::from_ptr(cpath);
//  let rpath = String::from_utf8_lossy(path.as_bytes());
  let len = strlen(cpath);
  let cpathu8 : *const u8 = transmute(cpath);

  let rpath = slice::from_raw_parts(cpathu8, len as usize);
  let spath = String::from_utf8_lossy(rpath);
//  let rpath = "./baseperm.data".to_string();
  println!("Path is {:?}",rpath);
  let datafile = File::open(&(*spath)).ok();
  let r = if datafile.is_none(){
    ptr::null_mut()
  } else {
    let f = datafile.unwrap();
    let ptrfnbuild : fn(&[u8], StripleRef<NoKind>) -> Result<AnyStriple, Error> = copy_builder_any ;

    let rit : Result<CIfIter,Error> = FileStripleIterator::init(f, ptrfnbuild, init_any_cipher_stdin, ());
    match rit {
      Ok(mut it) => {


        let tmptrit : *mut CIfIter = &mut it;
        println!("ptr st in rust : {:?}", tmptrit);
        let h = Box::new(it);
        let mptrit : *mut CIfIter = Box::into_raw(h);
        println!("ptr hea in rust : {:?}", mptrit);
        mptrit
//        tmptrit
      },
      Err(_) => ptr::null_mut(),
    }
  };
/*  println!("call now");
  iter_next(r);
  iter_next(r);
  println!("call now ok");*/
  r
}
#[no_mangle]
pub unsafe extern "C" fn dispptr(iter : *const ())  {
        println!("ptr st in next : {:?}", iter);

}
  
#[no_mangle]
pub unsafe extern "C" fn iter_next(iter : striple_iter) -> *const either_owned {
        println!("ptr st in next : {:?}", iter);
  let iter : &mut CIfIter = transmute(iter);
  println!("bef match");
  match iter.next() {
    Some(v) => match v.1 {
      Some(_) => {
  println!("in some");
        let st = Box::new((v.0, vec!()));
        &(*Box::new(either_owned {
          s : ptr::null(),
          os : &(*st),
        }))
      },
      None => {
        if v.0.is_public() {
//          let disp : *const AnyStriple = transmute (&v.0);
//          println!("debug public ptr rust : {:?}",disp);
        println!("res owned");
        let st = Box::new((v.0, vec!()));
        let disp : *const () = transmute(&(* st));
        println!("ret pt : {:?}",disp);
        &(*Box::new(either_owned {
          s : ptr::null(),
          os : &(*st),
        }))
 
        } else {
          let st = Box::new(v.0);
          let disp : *const AnyStriple = transmute (&(*st));
          println!("debug ptr rust : {:?}",disp);
        &(*Box::new(either_owned {
          s : &(*st),
          os : ptr::null(),
        }))
        }
      },
    },
    None => 
      ptr::null(),
  }

 
}
