//! basic storage for Striple and OwnedStriple to file

use std::fmt::{Debug};
use std::iter::Iterator;
use std::marker::PhantomData;
use std::fs::File;
use std::io::{Write,Read,Seek,SeekFrom,Result,Error,ErrorKind};
use striple::{Striple,OwnedStripleIf,StripleIf,StripleKind,xtendsize,xtendsizeread,AsStriple,StripleRef};
use striple::Error as StripleError;
use std::ptr::copy_nonoverlapping;

#[derive(Debug)]
pub enum MaybeOwnedStriple<SK : StripleKind, OS : OwnedStripleIf<SK>, S : StripleIf<SK>> {
  Owned(OS,PhantomData<SK>),
  NoOwn(S,PhantomData<SK>),
}

impl<SK : StripleKind, OS : OwnedStripleIf<SK>, S : StripleIf<SK>>  MaybeOwnedStriple<SK, OS, S> {
  pub fn getOwned(self) -> Option<OS> {
    match self {
      MaybeOwnedStriple::Owned(s,_) => Some(s),
      _ => None,
    }
  }
  pub fn getNoOwn(self) -> Option<S> {
    match self {
      MaybeOwnedStriple::NoOwn(s,_) => Some(s),
      _ => None,
    }
  }
}

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
   SK : StripleKind,
   S  : StripleIf<SK>,
   OS : OwnedStripleIf<SK>,
   W  : Write,
    > (cypher : & SC, striple : &MaybeOwnedStriple<SK,OS,S>,  dest : &mut W) -> Result<()> {
      // Tag as normal writing
      dest.write(&[0]);
      let menc = match striple {
        &MaybeOwnedStriple::Owned(ref s,_) => {
          let encprikey = cypher.encrypt(&s.private_key());
          try!(dest.write(&xtendsize(encprikey.len(),2)));
          try!(dest.write(&encprikey));
          Ok(s.striple_ser())
        },
        &MaybeOwnedStriple::NoOwn(ref s,_) => {
          try!(dest.write(&xtendsize(0,2)));
          Ok(s.striple_ser())
        },
      };
      menc.and_then(|s| {
        try!(dest.write(&xtendsize(s.len(),4)));
        try!(dest.write(&s));
        Ok(())
      })
}

// TODO switch to striple error
pub fn read_striple 
  <SC : StorageCypher, 
   SK : StripleKind,
   T  : StripleKind,
   R  : Read,
    > (cypher : &SC, from : &mut R) -> Result<MaybeOwnedStriple<SK,(Striple<SK>,Vec<u8>),Striple<SK>>> {
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
  let typednone : Option<&Striple<T>> = None;
  match StripleRef::striple_dser(&st[..],typednone) {
    Ok(s) => {
      match mpkey {
        None => Ok(MaybeOwnedStriple::NoOwn(s.as_striple(),PhantomData)),
        Some(pk) => Ok(MaybeOwnedStriple::Owned((s.as_striple(),pk),PhantomData)),
      }
    },
    Err(e) => {
      Err(Error::new(ErrorKind::InvalidInput, e))
    }
  }
}


/// write some striple to a file overwriting it.
pub fn write_striple_file
  <'a,
   SC : StorageCypher, 
   SK : 'a + StripleKind,
   S  : 'a + StripleIf<SK>,
   OS : 'a + OwnedStripleIf<SK>,
   IT : Iterator<Item=&'a MaybeOwnedStriple<SK,OS,S>>,
   W  : Write + Seek,
    > (cypher : & SC, striples : &'a mut  IT, mut file : W) -> Result<()> 
    where SK::D : 'a, SK::S : 'a
    {
  try!(file.seek(SeekFrom::Start(0)));
  try!(file.write(&SC::get_cypher_header()));
  for mos in striples {
    try!(write_striple(cypher,&mos,&mut file));
  };
//  write_striple(cypher,striples.next().unwrap(),&mut file);
  

  Ok(())
}

/// technical for file reading only
pub enum AnyCyphers {
  NoCypher(NoCypher),
}

pub struct FileStripleIterator<SK : StripleKind, R : Read + Seek> (R, AnyCyphers, PhantomData<SK>);

impl<SK : StripleKind, R : Read + Seek> FileStripleIterator<SK, R> {
  pub fn init (mut file :  R)  -> Result<FileStripleIterator<SK, R>> {
    try!(file.seek(SeekFrom::Start(0)));
    let idcypher = try!(xtendsizeread(&mut file, 1));
    let cyph = match idcypher {
      0 => Ok(AnyCyphers::NoCypher(NoCypher)),
      _ => Err(Error::new(ErrorKind::InvalidInput, "Non supported cypher type".to_string())),
    };
    cyph.map(|c|FileStripleIterator(file, c, PhantomData))
  }
}
impl<SK : StripleKind, R : Read + Seek> Iterator for FileStripleIterator<SK, R> {
  type Item = MaybeOwnedStriple<SK,(Striple<SK>,Vec<u8>),Striple<SK>>;

  fn next(&mut self) -> Option<Self::Item> {
    match &self.1 {
      &AnyCyphers::NoCypher(ref c) => {
        let res = read_striple::<_,_,SK,_>(c, &mut self.0);
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
  use striple::StripleIf;
  use striple::AsStriple;
  use striple::StripleKind;
  use striple::NoKind;
  use striple::IDDerivation;
  use striple::SignatureScheme;
  use storage::{MaybeOwnedStriple,NoCypher,write_striple,read_striple,write_striple_file,FileStripleIterator};
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
    let mut wr = write_striple::<_,_,_,(Striple<NoKind>,Vec<u8>),_>(&NoCypher, &MaybeOwnedStriple::NoOwn(striple1.clone(),PhantomData), &mut buf);
    debug!("{:?}", buf);
    assert!(wr.is_ok());
    wr = write_striple::<_,_,Striple<NoKind>,_,_>(&NoCypher, &MaybeOwnedStriple::Owned((striple2.clone(),pkey.clone()),PhantomData), &mut buf);
    assert!(wr.is_ok());

    assert!(buf.seek(SeekFrom::Start(0)).is_ok());
    
    debug!("{:?}", buf);
    let readstriple1 = read_striple::<_,NoKind,NoKind,_>(&NoCypher, &mut buf);
    debug!("{:?}", readstriple1);
    assert!(readstriple1.is_ok());
    assert!(compare_striple(&readstriple1.unwrap().getNoOwn().unwrap(),&striple1));
    let readstriple2res = read_striple::<_,NoKind,NoKind,_>(&NoCypher, &mut buf);
    debug!("{:?}", readstriple2res);
    assert!(readstriple2res.is_ok());
    let (readstriple2, readpkey) = readstriple2res.unwrap().getOwned().unwrap();
    assert!(compare_striple(&striple2,&readstriple2));
    assert!(readpkey == pkey);
  }

  #[test]
  fn test_striple_enc_dec_file () {
    let mut tmpvec : Vec<u8> = Vec::new();
    let mut buf = Cursor::new(tmpvec);
    let striple1 = sampleStriple1();
    let striple2 = sampleStriple2();
    let pkey = random_bytes(18);
    let mut vecst : Vec<MaybeOwnedStriple<NoKind,(Striple<NoKind>,Vec<u8>),Striple<NoKind>>> = Vec::new();
    vecst.push(MaybeOwnedStriple::NoOwn(striple1.clone(),PhantomData));
    vecst.push(MaybeOwnedStriple::Owned((striple2.clone(),pkey.clone()),PhantomData));
    
    let wr = write_striple_file(&NoCypher, &mut vecst.iter(), &mut buf);
    assert!(wr.is_ok());
 
    let mut rit : IOResult<FileStripleIterator<NoKind,_>> = FileStripleIterator::init(buf); 
    assert!(rit.is_ok());
    let mut it = rit.unwrap();
    let st1 = it.next();
    assert!(st1.is_some());
    assert!(compare_striple(&st1.unwrap().getNoOwn().unwrap(),&striple1));
    let st2 = it.next();
    assert!(st2.is_some());
    let (readstriple2, readpkey) = st2.unwrap().getOwned().unwrap();
    assert!(compare_striple(&striple2,&readstriple2));
    let st3 = it.next();
    assert!(st3.is_none());
  }
 

}
