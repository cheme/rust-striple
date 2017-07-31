//! basic storage for Striple and OwnedStriple to file
//! TODO add pbk challenge (rand byte two time encoded) 
//! in header to fail on open or only rd byte encoded 
//! (see if two time same thing) TODO find better scheme 
//! (byte jumping to a given 0 byte (random n time)).
//!

#[cfg(feature="opensslpbkdf2")]
extern crate openssl;

extern crate rand;

use std::cmp::{min};
use std::fmt::{Debug};
use std::iter::Iterator;
use std::io::{Read,Write,Seek,SeekFrom,Error,ErrorKind};
use std::io::{stdin,BufRead,Cursor};
use std::env;
use std::fs::File;
use std::fs::metadata;
use striple::{StripleIf,StripleKind,xtendsize,xtendsizeread,xtendsizeread_foralloc,StripleRef};
use std::marker::PhantomData;
use striple::Error as StripleError;
use striple::ErrorKind as StripleErrorKind;
//use striple::striple_copy_dser;
use striple::striple_dser;
use striple::BCont;
use std::path::PathBuf;
use striple::{
  Result,
  from_error,
  from_option,
};
use std::io::Result as IOResult;
use num::traits::ToPrimitive;

#[cfg(feature="opensslpbkdf2")]
use self::openssl::pkcs5::pbkdf2_hmac;
#[cfg(feature="opensslpbkdf2")]
use self::openssl::hash::MessageDigest;
#[cfg(feature="opensslpbkdf2")]
use self::openssl::symm::{Cipher,Crypter,Mode};

use self::rand::Rng;
use self::rand::os::OsRng;
use std::fmt::Result as FmtResult;
use std::fmt::{Formatter};

const BUFF_WRITE : usize = 512;
const PKITER_LENGTH : usize = 2;
const PKKS_LENGTH : usize = 2;
const CIPHTYPE_LENGTH : usize = 1;
const STORAGEPK_LENGTH : usize = 2;
const STORAGEST_LENGTH : usize = 4;
const STORAGEPATH_LENGTH : usize = 2;

const STRIPLE_TAG_BYTE : u8 = 0;
const STRIPLE_TAG_FILE : u8 = 1;

const CIPHER_TAG_NOCYPHER : usize = 0;
const CIPHER_TAG_PBKDF2 : usize = 1;


#[derive(Debug,Clone)]
/// when content is big or when content is already a file
/// it may be attached as a file.
/// A treshold is applied for BCont of size sup to 512 byte in order to determine if a file should
/// be created.
pub enum FileMode {
  /// no change
  Idem,
  /// no attached file all is include in store
  NoFile,
  /// path of file is relative
  Relative(Option<usize>),
  /// path of file is absolute
  Absolute(Option<usize>),
  /// Copy file to folder in pathbuf
  Managed(Option<usize>, PathBuf),
  /// Add simlink to file in pathbuf
  ManagedSim(Option<usize>, PathBuf),
}

pub trait StorageCypher : Debug {
  /// encoding identifier (first byte of file/stream as xtendsize)
  fn get_id_val (&self) -> usize;
  /// encoding identifier and possible serialized parameters
  fn get_cypher_header (&self) -> Vec<u8> {
    // one byte encode of id
    xtendsize(self.get_id_val(),CIPHTYPE_LENGTH)
  }
  fn encrypt (&self, &[u8]) -> Result<Vec<u8>>;
  fn decrypt (&self, &[u8]) -> Result<Vec<u8>>;
}

macro_rules! derive_any_cypher(($en:ident{ $($st:ident($ty:ty),)* }) => (
#[derive(Debug)]
pub enum $en {
  $( $st($ty), )*
}

impl StorageCypher for $en {
  #[inline]
  fn get_cypher_header (&self) -> Vec<u8> {
    match self {
      $( & $en::$st(ref i) => i.get_cypher_header(), )*
    }
  }
  #[inline]
  fn get_id_val (&self) -> usize {
    match self {
      $( & $en::$st(ref i) => i.get_id_val(), )*
    }
  }
  #[inline]
  fn encrypt (&self, cont : &[u8]) -> Result<Vec<u8>> {
    match self {
      $( & $en::$st(ref i) => i.encrypt(cont), )*
    }
  }
  #[inline]
  fn decrypt (&self, cont : &[u8]) -> Result<Vec<u8>> {
    match self {
      $( & $en::$st(ref i) => i.decrypt(cont), )*
    }
  }
}
));

#[cfg(feature="opensslpbkdf2")]
derive_any_cypher!(AnyCyphers {
  NoCypher(NoCypher),
  Pbkdf2(Pbkdf2),
});

#[cfg(not(feature="opensslpbkdf2"))]
derive_any_cypher!(AnyCyphers {
  NoCypher(NoCypher),
});



#[derive(Debug)]
/// Not encrypted key, should be use with caution
pub struct NoCypher;

#[derive(Debug)]
/// Remove key, all owned striple lose their info
pub struct RemoveKey;

#[cfg(feature="opensslpbkdf2")]
/// cypher key with pbkdf2 hmac sha1 and AES-256-CBC
/// Note a different salt is used for every striples
pub struct Pbkdf2 {
  //pass : String,
  iter : usize,
  keylength : usize,
  ivlength : usize,
  salt : Vec<u8>,
  cipher : Cipher,
  key : Vec<u8>,
}
 
#[cfg(feature="opensslpbkdf2")]
impl Debug for Pbkdf2 {
    fn fmt(&self, ftr : &mut Formatter) -> FmtResult {
      ftr.debug_struct("")
      .field("pass", &"******")
      .field("iter", &self.iter)
      .field("keylength", &self.keylength)
      .field("ivlength", &self.ivlength)
      .field("salt", &self.salt)
//      .field("keytodel", &self.key)
      .finish()
 
    }
}
fn read_pbkdf2_header<R : Read> (file : &mut R) -> Result<(usize,usize,Vec<u8>)> {
  let iter = try!(xtendsizeread(file, PKITER_LENGTH));

  let saltlength = try!(xtendsizeread_foralloc(file, PKKS_LENGTH));
  let mut salt = vec![0; saltlength];
  try!(file.read(&mut salt));
  Ok((iter,saltlength,salt))
    /*
     *    let mut res = xtendsize(self.get_id_val(),CIPHTYPE_LENGTH);
    res.append(&mut xtendsize(self.iter,PKITER_LENGTH));
    res.append(&mut xtendsize(self.keylength,PKKS_LENGTH));
    res.append(&mut self.salt.to_vec());*/
 
}


#[cfg(feature="opensslpbkdf2")]
impl Pbkdf2 {
  pub fn gen_salt() -> Result<Vec<u8>> {
    let cipher = Cipher::aes_256_cbc();
    let kl = cipher.key_len();
    let ivl = cipher.iv_len().unwrap_or(0);
 
    // gen salt
    let mut rng = OsRng::new()?;
    let mut s = vec![0; ivl];
    rng.fill_bytes(&mut s);
    Ok(s)
  }
  pub fn new (pass : String, iter : usize, salt : Vec<u8>) -> Result<Pbkdf2> {
    let cipher = Cipher::aes_256_cbc();
    let kl = cipher.key_len();
    let ivl = cipher.iv_len().unwrap_or(0);
    let mut key = vec![0;kl];
    pbkdf2_hmac (
       &pass.into_bytes()[..], 
       &salt[..], 
       iter,
       MessageDigest::sha1(), 
       &mut key
    )?; // TODO return error from new!!
    // TODO reuse of salt bad??
    Ok(Pbkdf2 {
      //pass : pass,
      iter : iter, 
      keylength : kl,
      ivlength : ivl,
      salt : salt,
      cipher : cipher,
      key : key,
    })
  }
}


#[cfg(feature="opensslpbkdf2")]
impl StorageCypher for Pbkdf2 {
  #[inline]
  fn get_id_val (&self) -> usize { CIPHER_TAG_PBKDF2 }
  fn get_cypher_header (&self) -> Vec<u8> {
    let mut res = xtendsize(self.get_id_val(),CIPHTYPE_LENGTH);
    res.append(&mut xtendsize(self.iter,PKITER_LENGTH));
    res.append(&mut xtendsize(self.salt.len(),PKKS_LENGTH));
    res.append(&mut self.salt.to_vec());
    res
  }
  // TODO very fishy (one cripter per content)
  fn encrypt (&self, pk : &[u8]) -> Result<Vec<u8>> {
    // gen salt
    let mut rng = OsRng::new()?;
    let buflen = self.cipher.block_size();
    let mut buff = vec![0; buflen + self.cipher.block_size()];
 
    rng.fill_bytes(&mut buff[..self.ivlength]);
//    self.crypter.init(Mode::Encrypt,&self.key[..],iv.clone());
    let mut crypter = Crypter::new(
      self.cipher,
      //Cipher::aes_256_cbc(),
      Mode::Encrypt, 
      &self.key[..],
      Some(&buff[..self.ivlength])
      //Some(&self.salt[..self.ivlength])
    )?;
    crypter.pad(true);
    let mut result = Vec::new();
    //let mut result = Vec::with_capacity(self.ivlength + self.keylength);
    result.extend_from_slice(&buff[..self.ivlength]);
    let mut to_enc = &pk[..];
    while {
      let insize = min(to_enc.len(),buflen);
      let i = crypter.update(&to_enc[..insize], &mut buff)?;
      to_enc = &to_enc[insize..];
      result.extend_from_slice(&buff[..i]);
      to_enc.len() > 0
    } {};
    let i = crypter.finalize(&mut buff)?;
    result.extend_from_slice(&buff[..i]);

    Ok(result)
  }
  // TODO no way of knowing if decrypt fail until trying to sign
  // That's bad design!! TODO maybe include an encrypted stuff in header to check key on load
  //
  fn decrypt (&self, pk : &[u8]) -> Result<Vec<u8>> {
    let iv = &pk[..self.ivlength];
//    let iv = &self.salt[..self.ivlength];
    let enc = &pk[self.ivlength..];
    let mut crypter = Crypter::new(
      self.cipher, 
      //Cipher::aes_256_cbc(),
      Mode::Decrypt, 
      &self.key[..],
      Some(&iv[..])
    )?;
    crypter.pad(true);
    let buflen = self.cipher.block_size();
    let mut buff = vec![0; buflen + self.cipher.block_size()];
    let mut result = Vec::new();
    //let mut to_dec = enc;
    let mut to_dec = &enc[..];
    while {
      let insize = min(to_dec.len(),buflen);
      let i = crypter.update(&to_dec[..insize], &mut buff)?;
      to_dec = &to_dec[insize..];
      result.extend_from_slice(&buff[..i]);
      to_dec.len() > 0
    } {};
    let i = crypter.finalize(&mut buff)?;
    result.extend_from_slice(&buff[..i]);
 
    Ok(result)
  }
}


impl StorageCypher for RemoveKey {
  #[inline]
  fn get_id_val (&self) -> usize { CIPHER_TAG_NOCYPHER }
  fn encrypt (&self, _ : &[u8]) -> Result<Vec<u8>> {
    Ok(vec!())
  }
  fn decrypt (&self, _ : &[u8]) -> Result<Vec<u8>> {
    Ok(vec!())
  }
}



impl StorageCypher for NoCypher {
  #[inline]
  fn get_id_val (&self) -> usize { CIPHER_TAG_NOCYPHER }
  fn encrypt (&self, pk : &[u8]) -> Result<Vec<u8>> {
    Ok(pk.to_vec())
  }
  fn decrypt (&self, pk : &[u8]) -> Result<Vec<u8>> {
    Ok(pk.to_vec())
  }
}


fn writetorandfile(cont : &[u8], _ : &mut Write) -> IOResult<String> {
   // using random 64bit int as name
   let mut id = rand::thread_rng().next_u64();
   let mut try = 0;
   let mut fname = format!("./{}_.stref",id);
   loop {
     if metadata(&fname).is_err(){
       break
     };
     id = rand::thread_rng().next_u64();
     fname = format!("./{}_.stref",id);
     try += 1;
     if try > 500 {
       return Err(Error::new(ErrorKind::Other, "Problem creating temporary file, there may be too many"));
       //panic!("Problem creating temporary file");
     }
   }
   let mut f = try!(File::create(&fname));
   try!(f.write_all(cont));
   Ok(fname)
}
 
// return true if content need to be added at the end of entry
fn writebcontheader(cont : &[u8], fm : &FileMode, dest : &mut Write) -> Result<bool> {
  match fm {
    &FileMode::Idem => {
      try!(dest.write(&[STRIPLE_TAG_BYTE]));
      Ok(true)
    },
    &FileMode::NoFile => {
      try!(dest.write(&[STRIPLE_TAG_BYTE]));
      Ok(true)
    },
 
    &FileMode::Relative(ref otresh) => {
      otresh.map(|ref tresh|{
        if cont.len() > *tresh {
          let path = try!(writetorandfile(cont,dest));
          let pathb = path.as_bytes(); 
          try!(dest.write(&[STRIPLE_TAG_FILE])); 
          try!(dest.write(&xtendsize(pathb.len(),STORAGEPATH_LENGTH)));
          try!(dest.write(pathb));
          Ok(false)
        } else {
         try!(dest.write(&[STRIPLE_TAG_BYTE]));
         Ok(true)
        }
      }).unwrap_or_else(||{
        try!(dest.write(&[STRIPLE_TAG_BYTE]));
        Ok(true)
      })
    },
    &FileMode::Absolute(ref otresh) => {
      otresh.map(|ref tresh|{
        if cont.len() > *tresh {
          let relpath = try!(writetorandfile(cont,dest));
          let cur = try!(env::current_dir());
          let path = cur.join(relpath);
          let pathb = from_option(path.to_str())?.as_bytes();
          dest.write(&[STRIPLE_TAG_FILE])?;
          dest.write(&xtendsize(pathb.len(),STORAGEPATH_LENGTH))?;
          dest.write(&pathb)?;
          Ok(false)
        } else {
         try!(dest.write(&[STRIPLE_TAG_BYTE]));
         Ok(true)
        }
      }).unwrap_or_else(||{
        try!(dest.write(&[STRIPLE_TAG_BYTE]));
        Ok(true)
      })
    },
    &FileMode::Managed(_, ref path) => {
      panic!("TODO imp managed {:?}", path)
    },
    &FileMode::ManagedSim(_, ref path) => {
      panic!("TODO imp managed {:?}", path)
    },
  }
}
fn writelocalpathheader(path : &PathBuf, fm : &FileMode, dest : &mut Write) -> Result<bool> {
  // TODO check file presence??
  match fm {
    &FileMode::Idem => {
        try!(dest.write(&[STRIPLE_TAG_FILE]));
        let pathb = path.to_str().unwrap().as_bytes();
        try!(dest.write(&xtendsize(pathb.len(),STORAGEPATH_LENGTH)));
        try!(dest.write(pathb));
        Ok(false)
    },
    &FileMode::NoFile => {
      try!(dest.write(&[STRIPLE_TAG_BYTE]));
      Ok(true)
    },
    &FileMode::Relative(_) => {
      try!(dest.write(&[STRIPLE_TAG_FILE]));
      let cur = try!(env::current_dir());
      let pathtmp = if path.is_relative() {
        path
      } else {
        // TODO wait for #23284 resolution to get an allcase working fn without panic
        match path.strip_prefix(&cur) {
          Ok(p) => p,
          Err(e) => panic!("Trying to make relative file to non child directory : {}", e)
        }
      };

      let pathb = pathtmp.to_string_lossy();
      let pb = pathb.as_bytes();
      try!(dest.write(&xtendsize(pb.len(),STORAGEPATH_LENGTH)));
      try!(dest.write(pb));
      Ok(false)
    },
    &FileMode::Absolute(_) => {
      try!(dest.write(&[STRIPLE_TAG_FILE]));
      if path.is_absolute() {
        let pathb = path.to_string_lossy();
        let pb = pathb.as_bytes();
        try!(dest.write(&xtendsize(pb.len(),STORAGEPATH_LENGTH)));
        try!(dest.write(pb));
      } else {
        let cur = try!(env::current_dir());
        let pathtmp = cur.join(path);
        let pathb = pathtmp.to_string_lossy();
        let pb = pathb.as_bytes();
        try!(dest.write(&xtendsize(pb.len(),STORAGEPATH_LENGTH)));
        try!(dest.write(pb));
      };
      Ok(false)
    },
    &FileMode::Managed(_, ref path) => {
      panic!("TODO imp managed {:?}", path)
    },
    &FileMode::ManagedSim(_, ref path) => {
      panic!("TODO imp simlink {:?}", path)
    },
  }
}


pub fn write_striple
  <SC : StorageCypher, 
   S  : StripleIf,
   W  : Write,
    > (cypher : & SC, striple : &S, owned : Option<&[u8]>, fm : &FileMode,  dest : &mut W) -> Result<()> {
      let (to_ser, ocont) = striple.striple_ser()?;
      let appendocont = match ocont {
        None => {
          try!(dest.write(&[STRIPLE_TAG_BYTE])); false
        },
        Some(bcont) => {
          match bcont {
            &BCont::OwnedBytes(ref b) => {
              try!(writebcontheader(&b[..], fm, dest))
            },
            &BCont::NotOwnedBytes(ref b) => {
              try!(writebcontheader(&b[..], fm, dest))
            },
            &BCont::LocalPath(ref p,_) => {
              try!(writelocalpathheader(p, fm, dest))
            },
 
          }
        },
      };
 
      match owned {
        Some(pri) => {
          let encprikey = cypher.encrypt(pri)?;
          dest.write(&xtendsize(encprikey.len(),STORAGEPK_LENGTH))?;
          dest.write(&encprikey)?;
        },
        None => {
          try!(dest.write(&xtendsize(0,STORAGEPK_LENGTH)));
        },
      };
      if appendocont {
      let oaddedcont = match ocont {
        Some(ref bc) =>  bc.copy_ser()?.1,
        None => 0,
      };
        try!(dest.write(&xtendsize(to_ser.len() + oaddedcont,STORAGEST_LENGTH)));
      } else {
        try!(dest.write(&xtendsize(to_ser.len(),STORAGEST_LENGTH)));
      }
      try!(dest.write(&to_ser));
      if appendocont {
        match ocont {
          Some (ref bc) => {
            match bc.get_readable() {
              Ok(mut r) => {
                let mut buff = &mut [0;BUFF_WRITE];
                let mut from = r.trait_read();
                loop {
                  let end = try!(from.read(buff));
                  if end == 0 {
                    break
                  };
                  if end < BUFF_WRITE {
                    try!(dest.write(&buff[0..end]));
                  } else {
                    try!(dest.write(buff));
                  };
                };
              },
              Err(r) => return Err(r),
            }
          },
          None => (),
        }
      };
 
      Ok(())
}


pub fn read_striple
  <SC : StorageCypher, 
   SK : StripleKind,
   T  : StripleIf,
   R  : Read,
   B,
    > (cypher : &SC, from : &mut R, copy_builder : B) -> Result<Option<(T,Option<Vec<u8>>)>>
  where B : Fn(&[u8], StripleRef<SK>) -> Result<T> {

  let tag = &mut [STRIPLE_TAG_BYTE];

  if from.read(tag)? == 0 {
    return Ok(None)
  }
  let bcon = match tag[0] {
    STRIPLE_TAG_BYTE => {
      None
    },
    STRIPLE_TAG_FILE => {
      let pathsize = try!(xtendsizeread_foralloc(from, STORAGEPATH_LENGTH));
      let mut bpath= vec![0;pathsize];
      try!(from.read(&mut bpath[..]));
//      let path = try!(String::from_utf8(bpath)); TODO use our error type to implement custom
//      from!!!
      let path = PathBuf::from(String::from_utf8_lossy(&bpath[..]).to_string());
      // check file existance
      let meta = try!(metadata(&path));
      if !meta.is_file() {
        let msg = format!("Missing underlying file for a striple entry : {:?}",&path);
        return Err(StripleError(msg, StripleErrorKind::MissingFile, None))
      };
      let s = meta.len() as usize;
      
      Some(BCont::LocalPath(path,s))
    },
 
    _ => return Err(StripleError("Unknown striple tag".to_string(), StripleErrorKind::KindImplementationNotFound, None)),
  };
  let privsize = try!(xtendsizeread_foralloc(from, STORAGEPK_LENGTH));
  let mpkey = if privsize > 0 {
    let mut pkey = vec![0;privsize];
    try!(from.read(&mut pkey[..]));
    Some(cypher.decrypt(&pkey)?)
  } else {
    None
  };

  let ssize = xtendsizeread_foralloc(from, STORAGEST_LENGTH)?;
  debug!("storage ssize : {:?}",ssize);
  let mut st = vec![0;ssize];
  from.read(&mut st[..])?;
  debug!("in st : {:?}", st);
  let typednone : Option<&T> = None;

  striple_dser(&st[..], bcon, typednone, copy_builder).map(|s|Some((s,mpkey)))
}

/*
// Old read_striple involving two copies, kept for possible change of lifetimes
pub fn read_striple_copy
  <SC : StorageCypher, 
   SK : StripleKind,
   T  : StripleIf,
   R  : Read,
   B,
    > (cypher : &SC, from : &mut R, copy_builder : B) -> Result<(T,Option<Vec<u8>>)>
  where B : Fn(&[u8], Striple<SK>) -> Result<T, StripleError>{
  let tag = &mut [0];
  try!(from.read(tag));
  if tag[0] != 0 {
    return Err(Error::new(ErrorKind::InvalidInput, "unknown striple tag"));
  };
  let privsize = try!(xtendsizeread(from, STORAGEPK_LENGTH));
  let mpkey = if privsize > 0 {
    let mut pkey = vec![0;privsize];
    try!(from.read(&mut pkey[..]));
    Some(cypher.decrypt(&pkey))
  } else {
    None
  };

  let ssize = try!(xtendsizeread(from, STORAGEST_LENGTH));
  let mut st = vec![0;ssize];
  try!(from.read(&mut st[..]));
  debug!("in st : {:?}", st);
  let typednone : Option<&T> = None;
  match striple_copy_dser(&st[..],typednone,copy_builder) {
    Ok(s) => 
      Ok((s,mpkey)),
    Err(e) => {
      Err(Error::new(ErrorKind::InvalidInput, e))
    }
  }
}
*/

/// write some striple to a file overwriting it.
pub fn write_striple_file_ref
  <'a,
   SC : StorageCypher, 
   S  : 'a + StripleIf,
   IT : Iterator<Item=(&'a S, Option<&'a[u8]>)>,
   W  : Write + Seek,
    > (cypher : & SC, striples : &'a mut  IT, fm : &FileMode, mut file : W) -> Result<()> 
    {
  try!(file.seek(SeekFrom::Start(0)));
  try!(file.write(&cypher.get_cypher_header()));
  for mos in striples {
    try!(write_striple(cypher,mos.0,mos.1,fm,&mut file));
  };

  Ok(())
}
pub fn write_striple_file
  <'a,
   SC : StorageCypher, 
   S  : 'a + StripleIf,
   IT : Iterator<Item=(S, Option<Vec<u8>>)>,
   W  : Write + Seek,
    > (cypher : & SC, striples : &'a mut  IT, fm : &FileMode, mut file : W) -> Result<()> 
    {
  try!(file.seek(SeekFrom::Start(0)));
  try!(file.write(&cypher.get_cypher_header()));
  for mos in striples {
    try!(write_striple(cypher,&mos.0,mos.1.as_ref().map(|pk|&pk[..]), fm, &mut file));
  };

  Ok(())
}

/// To read striple only, do not use for writing striple as possible loss of key
/// TODO skip when pbk
pub fn init_noread_key<R : Read> (file : &mut R, _ : ()) -> Result<RemoveKey> {
  let idcypher = try!(xtendsizeread(file, CIPHTYPE_LENGTH));
  match idcypher {
    CIPHER_TAG_PBKDF2 => {
      try!(read_pbkdf2_header (file));
      Ok(RemoveKey)
    },
    _ => Ok(RemoveKey)
  }
}

pub fn init_no_cipher<R : Read> (file : &mut R, _ : ()) -> Result<NoCypher> {
  let idcypher = try!(xtendsizeread(file, CIPHTYPE_LENGTH));
  match idcypher {
      CIPHER_TAG_NOCYPHER => Ok(NoCypher),
      _ => Err(StripleError("Non supported cypher type".to_string(), StripleErrorKind::KindImplementationNotFound, None)),
  }
}
#[cfg(feature="opensslpbkdf2")]
pub fn init_any_cipher_stdin<R: Read> (file : &mut R, _ : ()) -> Result<AnyCyphers> {
  let idcypher = try!(xtendsizeread(file, CIPHTYPE_LENGTH));
  match idcypher {
      CIPHER_TAG_NOCYPHER => Ok(AnyCyphers::NoCypher(NoCypher)),
      CIPHER_TAG_PBKDF2 => {
        println!("Reading protected storage, please input passphrase ?");
        let mut pass = String::new();
        let tstdin = stdin();
        let mut stdin = tstdin.lock();
 
        try!(stdin.read_line(&mut pass));
        // remove terminal \n
        pass.pop();
 
        let (iter, _, salt) = try!(read_pbkdf2_header (file));
        let pbk = Pbkdf2::new(pass,iter,salt)?;
        Ok(AnyCyphers::Pbkdf2(pbk))
      },
      _ => Err(StripleError("Non supported cypher type".to_string(), StripleErrorKind::KindImplementationNotFound, None)),
  }
}
#[cfg(not(feature="opensslpbkdf2"))]
pub fn init_any_cypher_with_pass<R: Read> (file : &mut R, pass : String) -> Result<AnyCyphers> {
  let idcypher = try!(xtendsizeread(file, CIPHTYPE_LENGTH));
  match idcypher {
      0 => Ok(AnyCyphers::NoCypher(NoCypher)),
      _ => Err(StripleError("Non supported cypher type".to_string(), StripleErrorKind::KindImplementationNotFound, None)),
  }
}
#[cfg(feature="opensslpbkdf2")]
pub fn init_any_cypher_with_pass<R: Read> (file : &mut R, pass : String) -> Result<AnyCyphers> {
  let idcypher = try!(xtendsizeread(file, CIPHTYPE_LENGTH));
  match idcypher {
      0 => Ok(AnyCyphers::NoCypher(NoCypher)),
      1 => {
        let (iter, _, salt) = try!(read_pbkdf2_header (file));
        let pbk = Pbkdf2::new(pass,iter,salt)?;
        Ok(AnyCyphers::Pbkdf2(pbk))
      },
      _ => Err(StripleError("Non supported cypher type".to_string(), StripleErrorKind::KindImplementationNotFound, None)),
  }
}

#[cfg(not(feature="opensslpbkdf2"))]
pub fn init_any_cipher_stdin<R: Read> (file : &mut R, _ : ()) -> Result<AnyCyphers> {
  let idcypher = try!(xtendsizeread(file, CIPHTYPE_LENGTH));
  match idcypher {
      CIPHER_TAG_NOCYPHER => Ok(AnyCyphers::NoCypher(NoCypher)),
      _ => Err(StripleError("Non supported cypher type".to_string(), StripleErrorKind::KindImplementationNotFound, None)),
  }
}



// TODO switch to associated types
pub struct FileStripleIterator<SK : StripleKind, T : StripleIf, R : Read + Seek, C : StorageCypher, B> (pub R, pub C, pub B, PhantomData<SK>, pub u64)
  where B : Fn(&[u8], StripleRef<SK>) -> Result<T>;
  //where B : Fn(&[u8], Striple<SK>) -> Result<T, StripleError>;

impl<SK : StripleKind, T : StripleIf, R : Read + Seek, B, C : StorageCypher> FileStripleIterator<SK, T, R, C, B>
  where B : Fn(&[u8], StripleRef<SK>) -> Result<T> {

  pub fn init<IC, P> (mut file :  R, cbuilder : B, initcypher : IC, extra : P)  -> Result<FileStripleIterator<SK, T, R, C, B>>
    where IC : Fn(&mut R, P) -> Result<C> {
    try!(file.seek(SeekFrom::Start(0)));
    let cyph = initcypher(&mut file, extra);
    let pos = try!(file.seek(SeekFrom::Current(0)));
    cyph.map(|c|FileStripleIterator(file, c, cbuilder, PhantomData,pos as u64))
  }

  /// get entry at a position (slow method but less than using iterator for one entry only)
  pub fn get (&mut self, ix : usize) -> Result<(T, Option<Vec<u8>>)>  {
    let posstart = try!(self.0.seek(SeekFrom::Current(0)));
    try!(self.0.seek(SeekFrom::Start(self.4)));
    for _ in 0..ix {
      try!(self.skip_striple());
    }

    let res = read_striple::<_,SK,_,_,_>(&self.1, &mut self.0, &self.2)?;
    self.0.seek(SeekFrom::Start(posstart))?;
    match res {
      Some(r) => Ok(r),
      None => Err(StripleError("could not reach ix".to_string(), StripleErrorKind::MissingIx,None)),
    }
  }

pub fn skip_striple (&mut self) -> IOResult<()> {
  let from = &mut self.0;
 
  let tag = &mut [0];
  try!(from.read(tag));

  match tag[0] {
    STRIPLE_TAG_BYTE => (),
    STRIPLE_TAG_FILE => {
      let pathsize = try!(xtendsizeread(from, STORAGEPATH_LENGTH));
      try!(from.seek(SeekFrom::Current(pathsize as i64)));
    },
    _ => return Err(Error::new(ErrorKind::InvalidInput, "unknown striple tag")),
  }


  let privsize = try!(xtendsizeread(from, STORAGEPK_LENGTH));
  try!(from.seek(SeekFrom::Current(privsize as i64)));
  let ssize = try!(xtendsizeread(from, STORAGEST_LENGTH));
  try!(from.seek(SeekFrom::Current(ssize as i64)));
  Ok(())
}


  /// get entry at a position without parsing
  pub fn get_asbyte (&mut self, ix : usize) -> IOResult<Vec<u8>> {
    let posstart = try!(self.0.seek(SeekFrom::Current(0)));
    let poslengt = try!(self.get_entryposlength(ix));

    let mut from = &mut self.0;
    let mut res = vec![0; poslengt.1];
    try!(from.seek(SeekFrom::Start(poslengt.0)));
    try!(from.read(&mut res));

    try!(from.seek(SeekFrom::Start(posstart)));
    Ok(res)
  }

  /// get entry length full
  pub fn get_entryposlength (&mut self, ix : usize) -> IOResult<(u64,usize)> {
    //let posstart = try!(self.0.seek(SeekFrom::Current(0)));
    try!(self.0.seek(SeekFrom::Start(self.4)));
    for _ in 0..ix {
      try!(self.skip_striple());
    }

    let posret = try!(self.0.seek(SeekFrom::Current(0)));
    try!(self.skip_striple());
    let posend = try!(self.0.seek(SeekFrom::Current(0)));

    Ok((posret, (posend - posret) as usize))
  }

}

/// rewrite an entry pass (usefull to avoid entry parsing)
/// TODO not use (see example copy), should be use to avoid loading striple in command when
/// copying, to an other file : untested
pub fn recode_entry<C1 : StorageCypher, C2 : StorageCypher> (entrybytes : &[u8], from : &C1, to : &C2) -> Result<Vec<u8>> {
  let mut entry = Cursor::new(entrybytes);
  let tag = &mut [STRIPLE_TAG_BYTE];
  entry.read(tag)?;
  let head = match tag[0] {
    STRIPLE_TAG_BYTE => {
      None
    },
    STRIPLE_TAG_FILE => {
      let s = xtendsizeread_foralloc(&mut entry, STORAGEPATH_LENGTH)?;
      Some(s)
    },
    _ => return Err(StripleError("Unknown striple tag(recode)".to_string(), StripleErrorKind::KindImplementationNotFound, None)),
  };
 
  let privsize = xtendsizeread_foralloc(&mut entry, STORAGEPK_LENGTH)?;

  let mut bufpri = vec![0;privsize];
  entry.read(&mut bufpri[..])?;
  let mut newpriv = to.encrypt(&from.decrypt(&bufpri[..])?)?;
  let mut newprivsize = xtendsize(newpriv.len(), STORAGEPK_LENGTH);

  let mut result = Vec::new();
  match head {
    None => result.push(STRIPLE_TAG_BYTE),
    Some(s) => {
      result.push(STRIPLE_TAG_BYTE);
      result.append(&mut xtendsize(s,STORAGEPATH_LENGTH));
    },
  }
  result.append(&mut newprivsize);
  result.append(&mut newpriv);
  entry.read_to_end(&mut result)?;

  Ok(result) 

}

impl<SK : StripleKind, T : StripleIf, R : Read + Seek, B, C : StorageCypher> Iterator for FileStripleIterator<SK, T, R, C, B>
  where B : Fn(&[u8], StripleRef<SK>) -> Result<T> {
  type Item = (T,Option<Vec<u8>>);

  fn next(&mut self) -> Option<Self::Item> {
    println!("start next");
    let res = read_striple::<_,SK,_,_,_>(&self.1, &mut self.0, &self.2);
    println!("{:?}",res);
        
    res.unwrap_or(None)
  }
}




// TODO  PBKDF2-HMAC-SHA1 and AES-256 with openssl and crypto warn no pass in debug





#[cfg(test)]
pub mod test {

  use striple::Striple;
//  use striple::copy_builder_id;
  use striple::ref_builder_id_copy;
  use striple::NoKind;
  use striple::Result;
  use storage::{FileMode,NoCypher,write_striple,read_striple,write_striple_file_ref,FileStripleIterator,init_any_cypher_with_pass};
  use striple::test::{sample_striple1,sample_striple2,sample_striple3,sample_striple4,random_bytes,compare_striple};
  use std::io::{Cursor,Seek,SeekFrom};

  #[cfg(feature="opensslpbkdf2")]
  use storage::{Pbkdf2,StorageCypher};

  #[cfg(feature="opensslpbkdf2")]
  #[test]
  fn test_pbkdf2 () {
    let content = random_bytes(48);
    let salt = Pbkdf2::gen_salt().unwrap();
    let cw = Pbkdf2::new("apass".to_string(), 2000,salt.clone()).unwrap();
    let rw = Pbkdf2::new("apass".to_string(), 2000,salt).unwrap();
    assert!(cw.iter == rw.iter);
    assert!(cw.keylength == rw.keylength);
    assert!(cw.ivlength == rw.ivlength);
    assert!(cw.salt == rw.salt);
//    assert!(cw.cipher == rw.cipher);
    assert!(cw.key == rw.key);

    let ec = cw.encrypt(&content[..]).unwrap();
    let dc = cw.decrypt(&ec[..]).unwrap();
    assert!(dc == content, "{:?}\n{:?}\n{:?}",ec,dc, content);

  }

  #[test]
  fn test_striple_enc_dec () {
    striple_enc_dec (&FileMode::Idem);
    striple_enc_dec (&FileMode::NoFile);
    striple_enc_dec (&FileMode::Relative(Some(530)));
    striple_enc_dec (&FileMode::Absolute(Some(530)));
    striple_enc_dec (&FileMode::Absolute(Some(650)));
    striple_enc_dec (&FileMode::Relative(None));
    striple_enc_dec (&FileMode::Absolute(None));
  }

  fn striple_enc_dec (fm : &FileMode) {
    let tmpvec : Vec<u8> = Vec::new();
    let mut buf = Cursor::new(tmpvec);
    let striple1 = sample_striple1();
    let striple2 = sample_striple2();
    // long content striple
    let striple3 = sample_striple3();
    // file attached
    let striple4 = sample_striple4();
    let pkey = random_bytes(18);
    debug!("{:?}", buf);
    let mut wr = write_striple(&NoCypher, &striple1, None, fm, &mut buf);
    debug!("{:?}", buf);
    assert!(wr.is_ok());
    wr = write_striple(&NoCypher, &striple2,Some(&pkey), fm, &mut buf);
    assert!(wr.is_ok());
    wr = write_striple(&NoCypher, &striple3,Some(&pkey), fm, &mut buf);
    assert!(wr.is_ok());
    wr = write_striple(&NoCypher, &striple4,Some(&pkey), fm, &mut buf);
    assert!(wr.is_ok());



    assert!(buf.seek(SeekFrom::Start(0)).is_ok());
    
    debug!("{:?}", buf);
    let readstriple1  = read_striple::<_,NoKind,Striple<NoKind>,_,_>(&NoCypher, &mut buf, ref_builder_id_copy);
    debug!("{:?}", readstriple1);
    assert!(readstriple1.is_ok());
    assert!(compare_striple(&readstriple1.unwrap().unwrap().0,&striple1));
    let readstriple2res = read_striple::<_,NoKind,Striple<NoKind>,_,_>(&NoCypher, &mut buf, ref_builder_id_copy);
    debug!("{:?}", readstriple2res);
    assert!(readstriple2res.is_ok());
    let (readstriple2, readpkey) = readstriple2res.unwrap().unwrap();
    assert!(compare_striple(&striple2,&readstriple2));
    assert!(readpkey.unwrap() == pkey);
    let readstriple3res = read_striple::<_,NoKind,Striple<NoKind>,_,_>(&NoCypher, &mut buf, ref_builder_id_copy);
    debug!("{:?}", readstriple3res);
    assert!(readstriple3res.is_ok());
    let (readstriple3, readpkey) = readstriple3res.unwrap().unwrap();
    assert!(compare_striple(&striple3,&readstriple3));
    assert!(readpkey.unwrap() == pkey);
    let readstriple4res = read_striple::<_,NoKind,Striple<NoKind>,_,_>(&NoCypher, &mut buf, ref_builder_id_copy);
    debug!("{:?}", readstriple4res);
    println!("{:?}", readstriple4res);
    assert!(readstriple4res.is_ok());
    let (readstriple4, readpkey) = readstriple4res.unwrap().unwrap();
    assert!(compare_striple(&striple4,&readstriple4));
    assert!(readpkey.unwrap() == pkey);
  }

  #[test]
  fn test_striple_enc_dec_file () {
    let tmpvec : Vec<u8> = Vec::new();
    let mut buf = Cursor::new(tmpvec);
    let striple1 = sample_striple1();
    let striple2 = sample_striple2();
    let pkey = random_bytes(18);
    let mut vecst : Vec<(&Striple<NoKind>,Option<&[u8]>)> = Vec::new();
    vecst.push((&striple1,None));
    vecst.push((&striple2,Some(&pkey[..])));
    let wr = write_striple_file_ref(&NoCypher, &mut vecst.iter().map(|p|(p.0,p.1)), &FileMode::NoFile, &mut buf);
    assert!(wr.is_ok());
    let rit : Result<FileStripleIterator<NoKind,Striple<NoKind>,_,_,_>> = FileStripleIterator::init(buf, ref_builder_id_copy, init_any_cypher_with_pass, "pass".to_string()); 
    assert!(rit.is_ok());
    let mut it = rit.unwrap();
 


    let st2bis = it.get(1);
    assert!(st2bis.is_ok());
    assert!(compare_striple(&striple2,&st2bis.unwrap().0));
  
     let st1bis = it.get(0);
    assert!(st1bis.is_ok());
    assert!(compare_striple(&striple1,&st1bis.unwrap().0));
   
   let st1 = it.next();
    assert!(st1.is_some());

    assert!(compare_striple(&st1.unwrap().0,&striple1));
    // to lose position
    it.get(0).unwrap();

    let st2 = it.next();
    assert!(st2.is_some());
   let (readstriple2, readpkey) = st2.unwrap();
    assert!(compare_striple(&striple2,&readstriple2));
    assert!(readpkey.unwrap() == pkey);
    let st3 = it.next();
    assert!(st3.is_none());
  }

}
