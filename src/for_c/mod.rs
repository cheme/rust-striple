//! External C interface.
//!
//! Currently all striples are AnyStriple, allowing monomorphism in constructor TODO swith
//! constructor to use trait param for from??
//! 
//! Lot of missing usecase.
//! TODO


use striple::{StripleIf,OwnedStripleIf,BCont,striple_dser,NoKind,StripleRef,Error};
use anystriple::{AnyStriple,copy_builder_any};
use std::mem::transmute;
use storage::{FileStripleIterator,init_any_cipher_stdin,AnyCyphers};
use std::ffi::CString;
use std::fs::File;
use libc::{size_t};
use std::path::Path;

#[repr(C)]
pub type striple_ptr = *const StripleIf;

#[repr(C)]
pub type owned_striple_ptr = *const OwnedStripleIf;

// TODO find a way to get rid of this useless B (refact api?to trait param)
//#[repr(C)]
//pub struct striple_iter (*mut FileStripleIterator<NoKind,AnyStriple,File,AnyCyphers,fn(&[u8], StripleRef<NoKind>) -> Result<AnyStriple, Error> >);
#[repr(C)]
pub type striple_iter = *mut FileStripleIterator<NoKind,AnyStriple,File,AnyCyphers,fn(&[u8], StripleRef<NoKind>) -> Result<AnyStriple, Error> >;

//fn(&[u8], StripleRef<'_, NoKind>) -> Result<AnyStriple, Error> {copy_builder_any}
#[repr(C)]
pub struct striple_bytes {
  bytes : *const u8,
  length : size_t,
}

#[repr(C)]
pub struct striple_bytes_array {
  bytes : *const striple_bytes,
  length : size_t,
}

#[repr(C)]
pub struct striple_bcont {
  bytes : *const u8,
  length : size_t,
  ispath : bool,
}

#[no_mangle]
pub unsafe extern "C" fn free_iter<B>(st : striple_iter) {
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
  let s : &StripleIf = transmute(st);
  let f : &StripleIf = transmute(from);
  s.check(f)
}

macro_rules! getter(($en:ident) => (

#[no_mangle]
pub unsafe extern "C" fn $en(st : striple_ptr) -> striple_bytes {
  let s : &StripleIf = transmute(st);
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
pub unsafe extern "C" fn private_key(st : striple_ptr) -> striple_bytes {
  let s : &OwnedStripleIf = transmute(st);
  let b = s.private_key_ref();
  striple_bytes {
    bytes : transmute(b.as_ptr()),
    length : b.len() as size_t,
  }
}

#[no_mangle]
pub unsafe extern "C" fn get_content(st : striple_ptr) -> Option<striple_bcont> {
  let s : &StripleIf = transmute(st);
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
      striple_bcont {
        bytes : transmute(b.as_ptr()),
        length : b.len() as size_t,
        ispath : false,
      }
    },
    &BCont::LocalPath(ref path) => {
      let b = path.as_os_str().to_bytes().unwrap();
      striple_bcont {
        bytes : transmute(b.as_ptr()),
        length : b.len() as size_t,
        ispath : true,
      }
    },
  })
}

#[no_mangle]
pub unsafe extern "C" fn get_content_ids(st : owned_striple_ptr) -> striple_bytes_array {
  let s : &StripleIf = transmute(st);
  let bs = s.get_content_ids();
  let c : Vec<striple_bytes> = bs.iter().map(|b|
  striple_bytes {
    bytes : transmute(b.as_ptr()),
    length : b.len() as size_t,
  }).collect();
  striple_bytes_array {
    bytes : transmute(c.as_ptr()),
    length : c.len() as size_t,
  }
}


// init from c byte buffer using any striple
// TODO bcont as optional parameter!!!
#[no_mangle]
pub unsafe extern "C" fn any_parse_striple(input : *mut u8, input_length : size_t) -> Option<striple_ptr> {
  let len = input_length as usize;
  let invec = Vec::from_raw_parts(input, len, len);
  let typednone : Option<&AnyStriple> = None; 
  match striple_dser(&invec[..], None, typednone, copy_builder_any) {
    Ok(st) => {
      // TODO might probably need heap alloc!!!
      //let h = Box::new(st);
      //Some (&(*h))
      Some (&st)
    },
    Err(_) => None,
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
  contentids : Option<striple_bytes_array>,
  content : Option<striple_bcont>,
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
      let ef = transmute(ptr);
      Some(ef)
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
pub unsafe extern "C" fn file_iter(path : CString) -> Option<striple_iter> {
  let rpath = String::from_utf8_lossy(path.as_bytes());
  let mut datafile = File::open(&(*rpath)).ok();
  datafile.and_then(|f|{
    let ptrfnbuild : fn(&[u8], StripleRef<NoKind>) -> Result<AnyStriple, Error> = copy_builder_any ; 
    let mut rit : Result<FileStripleIterator<NoKind,AnyStriple,_,_,_>,_> = FileStripleIterator::init(f, ptrfnbuild, &init_any_cipher_stdin, ());
    match rit {
      Ok(mut it) => {
        let ptrit : *mut FileStripleIterator<NoKind,AnyStriple,File,AnyCyphers,fn(&[u8], StripleRef<NoKind>) -> Result<AnyStriple, Error>>  = &mut it;
        Some(ptrit)
      },
      Err(_) => None,
    }

  })
}

