//! basic storage for Striple and OwnedStriple to file

use std::fmt::{Debug};
use std::iter::Iterator;
use std::marker::PhantomData;
use std::fs::File;
use std::io::{Write,Read,Seek,SeekFrom,Result,Error,ErrorKind};
use striple::{Striple,OwnedStripleIf,StripleIf,StripleKind,xtendsize,xtendsizeread,AsStriple,StripleRef};
use striple::Error as StripleError;
use striple::striple_copy_dser;
use striple::striple_dser;
//use striple::copy_builder_id;
use striple::ref_builder_id_copy;
use std::ptr::copy_nonoverlapping;
use std::result::Result as StdResult;

pub trait StorageCypher : Debug {
  // encoding identifier (first byte of file/stream as xtendsize)
  fn get_id_val () -> usize;
  fn get_cypher_header () -> Vec<u8>;
  fn encrypt (&self, &[u8]) -> Vec<u8>;
  fn decrypt (&self, &[u8]) -> Vec<u8>;
}

#[derive(Debug)]
/// Not encrypted key, should be use with caution
pub struct NoCypher;

#[derive(Debug)]
/// Remove key, all owned striple lose their info
pub struct RemoveKey;

impl StorageCypher for RemoveKey {
  #[inline]
  fn get_id_val () -> usize { 0 }
  fn get_cypher_header () -> Vec<u8> {
    // one byte encode of id
    xtendsize(0,1)
  }
  fn encrypt (&self, pk : &[u8]) -> Vec<u8> {
    vec!()
  }
  fn decrypt (&self, pk : &[u8]) -> Vec<u8> {
    vec!()
  }
}



impl StorageCypher for NoCypher {
  #[inline]
  fn get_id_val () -> usize { 0 }
  fn get_cypher_header () -> Vec<u8> {
    // one byte encode of id
    xtendsize(Self::get_id_val(),1)
  }
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
pub fn write_striple_file
  <'a,
   SC : StorageCypher, 
   S  : 'a + StripleIf,
   IT : Iterator<Item=(&'a S, Option<&'a[u8]>)>,
   W  : Write + Seek,
    > (cypher : & SC, striples : &'a mut  IT, mut file : W) -> Result<()> 
    {
  try!(file.seek(SeekFrom::Start(0)));
  try!(file.write(&SC::get_cypher_header()));
  for mos in striples {
    match mos.1 {
      Some (pk) => 
    try!(write_striple(cypher,mos.0,Some(&pk[..]),&mut file)),
      None => 
    try!(write_striple(cypher,mos.0,None,&mut file)),
    }
  };
//  write_striple(cypher,striples.next().unwrap(),&mut file);
  

  Ok(())
}

/// technical for file reading only
pub enum AnyCyphers {
  NoCypher(NoCypher),
}

pub struct FileStripleIterator<SK : StripleKind, T : StripleIf, R : Read + Seek, B> (R, AnyCyphers, B, PhantomData<SK>)
  where B : Fn(&[u8], StripleRef<SK>) -> StdResult<T, StripleError>;
  //where B : Fn(&[u8], Striple<SK>) -> StdResult<T, StripleError>;

impl<SK : StripleKind, T : StripleIf, R : Read + Seek, B> FileStripleIterator<SK, T, R, B>
  where B : Fn(&[u8], StripleRef<SK>) -> StdResult<T, StripleError> {
//  where B : Fn(&[u8], Striple<SK>) -> StdResult<T, StripleError> {
  pub fn init (mut file :  R, cbuilder : B)  -> Result<FileStripleIterator<SK, T, R, B>> {
    try!(file.seek(SeekFrom::Start(0)));
    let idcypher = try!(xtendsizeread(&mut file, 1));
    let cyph = match idcypher {
      0 => Ok(AnyCyphers::NoCypher(NoCypher)),
      _ => Err(Error::new(ErrorKind::InvalidInput, "Non supported cypher type".to_string())),
    };
    cyph.map(|c|FileStripleIterator(file, c, cbuilder, PhantomData))
  }
}
impl<SK : StripleKind, T : StripleIf, R : Read + Seek, B> Iterator for FileStripleIterator<SK, T, R, B>
  where B : Fn(&[u8], StripleRef<SK>) -> StdResult<T, StripleError> {
  //where B : Fn(&[u8], Striple<SK>) -> StdResult<T, StripleError> {
  type Item = (T,Option<Vec<u8>>);

  fn next(&mut self) -> Option<Self::Item> {
    match &self.1 {
      &AnyCyphers::NoCypher(ref c) => {
        let res = read_striple::<_,SK,_,_,_>(c, &mut self.0, &self.2);
        println!("{:?}",res);
        
        res.ok()
      },
    }
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
  use storage::{NoCypher,write_striple,read_striple,write_striple_file,FileStripleIterator};
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
    
    let wr = write_striple_file(&NoCypher, &mut vecst.iter().map(|p|(p.0,p.1)), &mut buf);
    assert!(wr.is_ok());
 
    let mut rit : IOResult<FileStripleIterator<NoKind,Striple<NoKind>,_,_>> = FileStripleIterator::init(buf, ref_builder_id_copy); 
    assert!(rit.is_ok());
    let mut it = rit.unwrap();
    let st1 = it.next();
    assert!(st1.is_some());
    assert!(compare_striple(&st1.unwrap().0,&striple1));
    let st2 = it.next();
    assert!(st2.is_some());
    let (readstriple2, readpkey) = st2.unwrap();
    assert!(compare_striple(&striple2,&readstriple2));
    assert!(readpkey.unwrap() == pkey);
    let st3 = it.next();
    assert!(st3.is_none());
  }
 

}
