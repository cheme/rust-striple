//! basic storage for Striple and OwnedStriple to file

#[cfg(feature="opensslpbkdf2")]
extern crate openssl;

#[cfg(feature="opensslpbkdf2")]
extern crate rand;

use std::fmt::{Debug};
use std::iter::Iterator;
use std::marker::PhantomData;
use std::fs::File;
use std::io::{Write,Read,Seek,SeekFrom,Result,Error,ErrorKind};
use std::io::{stdin,BufRead};
use striple::{Striple,OwnedStripleIf,StripleIf,StripleKind,xtendsize,xtendsizeread,xtendsizedec,AsStriple,StripleRef};
use striple::Error as StripleError;
use striple::striple_copy_dser;
use striple::striple_dser;
//use striple::copy_builder_id;
use striple::ref_builder_id_copy;
use std::ptr::copy_nonoverlapping;
use std::result::Result as StdResult;
use num::traits::ToPrimitive;

#[cfg(feature="opensslpbkdf2")]
use self::openssl::crypto::pkcs5::pbkdf2_hmac_sha1;
#[cfg(feature="opensslpbkdf2")]
use self::openssl::crypto::symm::{Crypter,Mode,Type};

#[cfg(feature="opensslpbkdf2")]
use self::rand::Rng;
#[cfg(feature="opensslpbkdf2")]
use self::rand::os::OsRng;
use std::fmt::Result as FmtResult;
use std::fmt::{Formatter};

pub trait StorageCypher : Debug {
  /// encoding identifier (first byte of file/stream as xtendsize)
  fn get_id_val (&self) -> usize;
  /// encoding identifier and possible serialized parameters
  fn get_cypher_header (&self) -> Vec<u8> {
    // one byte encode of id
    xtendsize(self.get_id_val(),1)
  }
  fn encrypt (&self, &[u8]) -> Vec<u8>;
  fn decrypt (&self, &[u8]) -> Vec<u8>;
}

macro_rules! derive_any_cypher(($en:ident{ $($st:ident($ty:ty),)* }) => (
#[derive(Debug)]
pub enum $en {
  $( $st($ty), )*
}

impl StorageCypher for $en {
  #[inline]
  fn get_id_val (&self) -> usize {
    match self {
      $( & $en::$st(ref i) => i.get_id_val(), )*
    }
  }
  #[inline]
  fn encrypt (&self, cont : &[u8]) -> Vec<u8> {
    match self {
      $( & $en::$st(ref i) => i.encrypt(cont), )*
    }
  }
  #[inline]
  fn decrypt (&self, cont : &[u8]) -> Vec<u8> {
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

#[cfg(feature="not(opensslpbkdf2)")]
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
  pass : String,
  iter : usize,
  keylength : usize,
  salt : Vec<u8>,
  crypter : Crypter,
  key : Vec<u8>,
}
 
impl Debug for Pbkdf2 {
    fn fmt(&self, ftr : &mut Formatter) -> FmtResult {
      ftr.debug_struct("")
      .field("pass", &"******")
      .field("iter", &self.iter)
      .field("keylength", &self.keylength)
      .field("salt", &self.salt)
      .finish()
 
    }
}
impl Pbkdf2 {
  /// Pbkdf2 param in header
  fn read_pbkdf2_header<R : Read> (file : &mut R) -> Result<(usize,usize,Vec<u8>)> {
    let iter = try!(xtendsizeread(file, 2));

    let keylength = try!(xtendsizeread(file, 2));
    let mut salt = vec![0; keylength];
    try!(file.read(&mut salt));
    Ok((iter,keylength,salt))
  }

  pub fn new (pass : String, iter : usize, osalt : Option<Vec<u8>>) -> Pbkdf2 {
    let mut crypter = Crypter::new(Type::AES_256_CBC);
    let salt = match osalt {
      Some(s) => s,
      None => {
        // gen salt
        let mut rng = OsRng::new().unwrap();
        let mut s = vec![0; 256 /8];
        rng.fill_bytes(&mut s);
        s
      },
    };
    let kl = 256 / 8;
    let key = pbkdf2_hmac_sha1(&pass[..], &salt[..], iter, kl);
    crypter.pad(true);
    Pbkdf2 {
      pass : pass,
      iter : iter, 
      keylength : kl,
      salt : salt,
      crypter : crypter,
      key : key,
    }
  }
}


#[cfg(feature="opensslpbkdf2")]
impl StorageCypher for Pbkdf2 {
  #[inline]
  fn get_id_val (&self) -> usize { 1 }
  fn get_cypher_header (&self) -> Vec<u8> {
    let mut res = xtendsize(self.get_id_val(),1);
    res.push_all(&xtendsize(self.iter,2)[..]);
    res.push_all(&xtendsize(self.keylength,2)[..]);
    res.push_all(&self.salt[..]);
    res
  }
  fn encrypt (&self, pk : &[u8]) -> Vec<u8> {
    // gen salt
    let mut rng = OsRng::new().unwrap();
    let mut iv = vec![0; self.keylength];
    rng.fill_bytes(&mut iv);
 
    self.crypter.init(Mode::Encrypt,&self.key[..],iv.clone());
    let mut result = iv;
    result.push_all(&self.crypter.update(pk));
    result.push_all(&self.crypter.finalize());
    result
  }
  fn decrypt (&self, pk : &[u8]) -> Vec<u8> {
    let iv = &pk[..self.keylength];
    let enc = &pk[self.keylength..];
    self.crypter.init(Mode::Decrypt,&self.key[..],iv.to_vec());
    let mut result = self.crypter.update(enc);
    result.push_all(&self.crypter.finalize());
    result
  }
}

impl StorageCypher for RemoveKey {
  #[inline]
  fn get_id_val (&self) -> usize { 0 }
  fn encrypt (&self, pk : &[u8]) -> Vec<u8> {
    vec!()
  }
  fn decrypt (&self, pk : &[u8]) -> Vec<u8> {
    vec!()
  }
}



impl StorageCypher for NoCypher {
  #[inline]
  fn get_id_val (&self) -> usize { 0 }
  fn encrypt (&self, pk : &[u8]) -> Vec<u8> {
    pk.to_vec()
  }
  fn decrypt (&self, pk : &[u8]) -> Vec<u8> {
    pk.to_vec()
  }
}

pub fn write_striple
  <SC : StorageCypher, 
   S  : StripleIf,
   W  : Write,
    > (cypher : & SC, striple : &S, owned : Option<&[u8]>,  dest : &mut W) -> Result<()> {
      // Tag as normal writing
      dest.write(&[0]);
      match owned {
        Some(pri) => {
          let encprikey = cypher.encrypt(pri);
          try!(dest.write(&xtendsize(encprikey.len(),2)));
          try!(dest.write(&encprikey));
        },
        None => {
          try!(dest.write(&xtendsize(0,2)));
        },
      };
      let to_ser = striple.striple_ser();
      try!(dest.write(&xtendsize(to_ser.len(),4)));
      try!(dest.write(&to_ser));
      Ok(())
}

pub fn read_striple
  <SC : StorageCypher, 
   SK : StripleKind,
   T  : StripleIf,
   R  : Read,
   B,
    > (cypher : &SC, from : &mut R, copy_builder : B) -> Result<(T,Option<Vec<u8>>)>
  where B : Fn(&[u8], StripleRef<SK>) -> StdResult<T, StripleError> {
  let tag = &mut [0];
  from.read(tag);
  if tag[0] != 0 {
    return Err(Error::new(ErrorKind::InvalidInput, "unknown striple tag"));
  };
  let privsize = try!(xtendsizeread(from, 2));
  let mpkey = if privsize > 0 {
    let mut pkey = vec![0;privsize];
    try!(from.read(&mut pkey[..]));
    Some(cypher.decrypt(&pkey))
  } else {
    None
  };

  let ssize = try!(xtendsizeread(from, 4));
  let mut st = vec![0;ssize];
  try!(from.read(&mut st[..]));
  debug!("in st : {:?}", st);
  let typednone : Option<&T> = None;
  match striple_dser(&st[..],typednone,copy_builder) {
    Ok(s) => 
      Ok((s,mpkey)),
    Err(e) => {
      Err(Error::new(ErrorKind::InvalidInput, e))
    }
  }
}


// TODO switch to striple error + fn gen to StripleImpl
// Old read_striple involving two copies, kept for possible change of lifetimes
pub fn read_striple_copy
  <SC : StorageCypher, 
   SK : StripleKind,
   T  : StripleIf,
   R  : Read,
   B,
    > (cypher : &SC, from : &mut R, copy_builder : B) -> Result<(T,Option<Vec<u8>>)>
  where B : Fn(&[u8], Striple<SK>) -> StdResult<T, StripleError>{
  let tag = &mut [0];
  from.read(tag);
  if tag[0] != 0 {
    return Err(Error::new(ErrorKind::InvalidInput, "unknown striple tag"));
  };
  let privsize = try!(xtendsizeread(from, 2));
  let mpkey = if privsize > 0 {
    let mut pkey = vec![0;privsize];
    try!(from.read(&mut pkey[..]));
    Some(cypher.decrypt(&pkey))
  } else {
    None
  };

  let ssize = try!(xtendsizeread(from, 4));
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


/// write some striple to a file overwriting it.
pub fn write_striple_file_ref
  <'a,
   SC : StorageCypher, 
   S  : 'a + StripleIf,
   IT : Iterator<Item=(&'a S, Option<&'a[u8]>)>,
   W  : Write + Seek,
    > (cypher : & SC, striples : &'a mut  IT, mut file : W) -> Result<()> 
    {
  try!(file.seek(SeekFrom::Start(0)));
  try!(file.write(&cypher.get_cypher_header()));
  for mos in striples {
    try!(write_striple(cypher,mos.0,mos.1,&mut file));
  };

  Ok(())
}
pub fn write_striple_file
  <'a,
   SC : StorageCypher, 
   S  : 'a + StripleIf,
   IT : Iterator<Item=(S, Option<Vec<u8>>)>,
   W  : Write + Seek,
    > (cypher : & SC, striples : &'a mut  IT, mut file : W) -> Result<()> 
    {
  try!(file.seek(SeekFrom::Start(0)));
  try!(file.write(&cypher.get_cypher_header()));
  for mos in striples {
    try!(write_striple(cypher,&mos.0,mos.1.as_ref().map(|pk|&pk[..]),&mut file));
  };

  Ok(())
}

/// To read striple only, do not use for writing striple as possible loss of key
pub fn initNoReadKey<R : Read> (file : &mut R, _ : ()) -> Result<RemoveKey> {
  let _ = try!(xtendsizeread(file, 1));
  Ok(RemoveKey)
}

pub fn initNoCypher<R : Read> (file : &mut R, _ : ()) -> Result<NoCypher> {
  let idcypher = try!(xtendsizeread(file, 1));
  match idcypher {
      0 => Ok(NoCypher),
      _ => Err(Error::new(ErrorKind::InvalidInput, "Non supported cypher type".to_string())),
  }
}
#[cfg(feature="opensslpbkdf2")]
pub fn initAnyCypherStdIn<R: Read> (file : &mut R, _ : ()) -> Result<AnyCyphers> {
  let idcypher = try!(xtendsizeread(file, 1));
  match idcypher {
      0 => Ok(AnyCyphers::NoCypher(NoCypher)),
      1 => {
        println!("Reading protected storage, please input passphrase ?");
        let mut pass = String::new();
        let mut tstdin = stdin();
        let mut stdin = tstdin.lock();
 
        stdin.read_line(&mut pass);
        // remove terminal \n
        pass.pop();
 
        let (iter, keylength, salt) = try!(Pbkdf2::read_pbkdf2_header (file));
        let pbk = Pbkdf2::new(pass,iter,Some(salt));
        Ok(AnyCyphers::Pbkdf2(pbk))
      },
      _ => Err(Error::new(ErrorKind::InvalidInput, "Non supported cypher type".to_string())),
  }
}
#[cfg(feature="opensslpbkdf2")]
pub fn initAnyCypherWithPass<R: Read> (file : &mut R, pass : String) -> Result<AnyCyphers> {
  let idcypher = try!(xtendsizeread(file, 1));
  match idcypher {
      0 => Ok(AnyCyphers::NoCypher(NoCypher)),
      1 => {
        let (iter, keylength, salt) = try!(Pbkdf2::read_pbkdf2_header (file));
        let pbk = Pbkdf2::new(pass,iter,Some(salt));
        Ok(AnyCyphers::Pbkdf2(pbk))
      },
      _ => Err(Error::new(ErrorKind::InvalidInput, "Non supported cypher type".to_string())),
  }
}

#[cfg(not(feature="opensslpbkdf2"))]
pub fn initAnyCypherStdIn<R: Read> (file : &mut R, _ : ()) -> Result<AnyCyphers> {
  let idcypher = try!(xtendsizeread(file, 1));
  match idcypher {
      0 => Ok(AnyCyphers::NoCypher(NoCypher)),
      _ => Err(Error::new(ErrorKind::InvalidInput, "Non supported cypher type".to_string())),
  }
}


// TODO switch to associated types
pub struct FileStripleIterator<SK : StripleKind, T : StripleIf, R : Read + Seek, C : StorageCypher, B> (pub R, pub C, B, PhantomData<SK>, pub u64)
  where B : Fn(&[u8], StripleRef<SK>) -> StdResult<T, StripleError>;
  //where B : Fn(&[u8], Striple<SK>) -> StdResult<T, StripleError>;

impl<SK : StripleKind, T : StripleIf, R : Read + Seek, B, C : StorageCypher> FileStripleIterator<SK, T, R, C, B>
  where B : Fn(&[u8], StripleRef<SK>) -> StdResult<T, StripleError> {

  pub fn init<IC, P> (mut file :  R, cbuilder : B, initcypher : IC, extra : P)  -> Result<FileStripleIterator<SK, T, R, C, B>>
    where IC : Fn(&mut R, P) -> Result<C> {
    try!(file.seek(SeekFrom::Start(0)));
    let cyph = initcypher(&mut file, extra);
    let pos = try!(file.seek(SeekFrom::Current(0)));
    cyph.map(|c|FileStripleIterator(file, c, cbuilder, PhantomData,pos.to_u64().unwrap()))
  }

  /// get entry at a position (slow method but less than using iterator for one entry only)
  pub fn get (&mut self, ix : usize) -> Result<(T, Option<Vec<u8>>)>  {
    let posstart = try!(self.0.seek(SeekFrom::Current(0)));
    try!(self.0.seek(SeekFrom::Start(self.4)));
    for _ in 0..ix {
      try!(self.skip_striple());
    }

    let res = read_striple::<_,SK,_,_,_>(&self.1, &mut self.0, &self.2);
    try!(self.0.seek(SeekFrom::Start(posstart)));
    res
  }

pub fn skip_striple (&mut self) -> Result<()> {
  let from = &mut self.0;
 
  let tag = &mut [0];
  from.read(tag);
  if tag[0] != 0 {
    return Err(Error::new(ErrorKind::InvalidInput, "unknown striple tag"));
  };
  let privsize = try!(xtendsizeread(from, 2));
  try!(from.seek(SeekFrom::Current(privsize.to_i64().unwrap())));
  let ssize = try!(xtendsizeread(from, 4));
  try!(from.seek(SeekFrom::Current(ssize.to_i64().unwrap())));
  Ok(())
}


  /// get entry at a position without parsing
  pub fn get_asbyte (&mut self, ix : usize) -> Result<Vec<u8>> {
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
  pub fn get_entryposlength (&mut self, ix : usize) -> Result<(u64,usize)> {
    let posstart = try!(self.0.seek(SeekFrom::Current(0)));
    try!(self.0.seek(SeekFrom::Start(self.4)));
    for _ in 0..ix {
      try!(self.skip_striple());
    }

    let mut from = &mut self.0;
    let posret = try!(from.seek(SeekFrom::Current(0)));
    let tag = &mut [0];
    from.read(tag);
    if tag[0] != 0 {
      return Err(Error::new(ErrorKind::InvalidInput, "unknown striple tag"));
    };
    let privsize = try!(xtendsizeread(from, 2));
    from.seek(SeekFrom::Current(privsize.to_i64().unwrap()));
    let ssize = try!(xtendsizeread(from, 4));
    let posend = try!(from.seek(SeekFrom::Current(0)));
    try!(from.seek(SeekFrom::Start(posstart)));

    Ok((posret, (posend - posret).to_usize().unwrap() + ssize))
  }

}

/// rewrite an entry pass (usefull to avoid entry parsing)
/// TODO should use reader to avoid putting content in mem
pub fn recode_entry<C1 : StorageCypher, C2 : StorageCypher> (entry : &[u8], from : &C1, to : &C2) -> Result<Vec<u8>> {
  let mut pos = 0;
  if entry[0] != 0 {
      return Err(Error::new(ErrorKind::InvalidInput, "unknown striple tag"));
  };
  pos += 1;
  let privsize = xtendsizedec(entry, &mut pos, 2);
  let newpriv = to.encrypt(&from.decrypt(&entry[pos..pos + privsize])[..]);
  let remain = &entry[pos + privsize..];
  let newprivsize = xtendsize(newpriv.len(), 2);

  let mut result = Vec::new();
  result.push(0);
  result.push(0);
  result.push_all(&newprivsize[..]);
  result.push_all(&newpriv[..]);
  result.push_all(remain);

  Ok(result) 

}

impl<SK : StripleKind, T : StripleIf, R : Read + Seek, B, C : StorageCypher> Iterator for FileStripleIterator<SK, T, R, C, B>
  where B : Fn(&[u8], StripleRef<SK>) -> StdResult<T, StripleError> {
  type Item = (T,Option<Vec<u8>>);

  fn next(&mut self) -> Option<Self::Item> {
    let res = read_striple::<_,SK,_,_,_>(&self.1, &mut self.0, &self.2);
//    println!("{:?}",res);
        
    res.ok()
  }
}




// TODO  PBKDF2-HMAC-SHA1 and AES-256 with openssl and crypto warn no pass in debug





#[cfg(test)]
pub mod test {
  use striple::Striple;
//  use striple::copy_builder_id;
  use striple::ref_builder_id_copy;
  use striple::StripleIf;
  use striple::AsStriple;
  use striple::StripleKind;
  use striple::NoKind;
  use striple::IDDerivation;
  use striple::SignatureScheme;
  use storage::{NoCypher,write_striple,read_striple,write_striple_file_ref,FileStripleIterator,initNoCypher,initAnyCypherWithPass};
  use striple::test::{sampleStriple1,sampleStriple2,random_bytes,compare_striple};
  use std::io::{Write,Read,Cursor,Seek,SeekFrom};
  use std::marker::PhantomData;
  use std::slice::Iter;
  use std::io::Result as IOResult;

  #[test]
  fn test_striple_enc_dec () {
    let mut tmpvec : Vec<u8> = Vec::new();
    let mut buf = Cursor::new(tmpvec);
    let striple1 = sampleStriple1();
    let striple2 = sampleStriple2();
    let pkey = random_bytes(18);
    debug!("{:?}", buf);
    let mut wr = write_striple(&NoCypher, &striple1, None, &mut buf);
    debug!("{:?}", buf);
    assert!(wr.is_ok());
    wr = write_striple(&NoCypher, &striple2,Some(&pkey), &mut buf);
    assert!(wr.is_ok());

    assert!(buf.seek(SeekFrom::Start(0)).is_ok());
    
    debug!("{:?}", buf);
    let readstriple1  = read_striple::<_,NoKind,Striple<NoKind>,_,_>(&NoCypher, &mut buf, ref_builder_id_copy);
    debug!("{:?}", readstriple1);
    assert!(readstriple1.is_ok());
    assert!(compare_striple(&readstriple1.unwrap().0,&striple1));
    let readstriple2res = read_striple::<_,NoKind,Striple<NoKind>,_,_>(&NoCypher, &mut buf, ref_builder_id_copy);
    debug!("{:?}", readstriple2res);
    assert!(readstriple2res.is_ok());
    let (readstriple2, readpkey) = readstriple2res.unwrap();
    assert!(compare_striple(&striple2,&readstriple2));
    assert!(readpkey.unwrap() == pkey);
  }

  #[test]
  fn test_striple_enc_dec_file () {
    let mut tmpvec : Vec<u8> = Vec::new();
    let mut buf = Cursor::new(tmpvec);
    let striple1 = sampleStriple1();
    let striple2 = sampleStriple2();
    let pkey = random_bytes(18);
    let mut vecst : Vec<(&Striple<NoKind>,Option<&[u8]>)> = Vec::new();
    vecst.push((&striple1,None));
    vecst.push((&striple2,Some(&pkey[..])));
    let wr = write_striple_file_ref(&NoCypher, &mut vecst.iter().map(|p|(p.0,p.1)), &mut buf);
    assert!(wr.is_ok());
    let mut rit : IOResult<FileStripleIterator<NoKind,Striple<NoKind>,_,_,_>> = FileStripleIterator::init(buf, ref_builder_id_copy, initAnyCypherWithPass, "pass".to_string()); 
    //let mut rit : IOResult<FileStripleIterator<NoKind,Striple<NoKind>,_,_,_>> = FileStripleIterator::init(buf, ref_builder_id_copy, initNoCypher, ()); 
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
    it.get(0);

    let st2 = it.next();
    assert!(st2.is_some());
   let (readstriple2, readpkey) = st2.unwrap();
    assert!(compare_striple(&striple2,&readstriple2));
    assert!(readpkey.unwrap() == pkey);
    let st3 = it.next();
    assert!(st3.is_none());
  }

}
