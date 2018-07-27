


#[cfg(feature="serialize")]
use base64::STANDARD as BASE64CONF;
use std::error::Error as ErrorTrait;
use std::io::Error as IOError;
#[cfg(feature="serialize")]
use serde::de::Error as SerdeError;
use std::env::VarError;
use std::fmt::{Display,Debug,Formatter};
use std::fmt::Result as FmtResult;
use std::marker::{
  PhantomData,
  Sync,
};
use std::mem;
use std::ptr::copy_nonoverlapping;
use std::io::{Read};
use std::io::Result as IOResult;
use std::result::Result as StdResult;
use std::io::Cursor;
use std::fs::File;
use std::path::PathBuf;
use std::fs::metadata;
use std::ops::Deref;
//use self::defaultStripleDefImpl::*;
 
pub const NOKEY : &'static [u8] = &[];
const ID_LENGTH : usize = 2;
const KEY_LENGTH : usize = 2;
const CONTENTIDS_LENGTH : usize = 1;
const CONTENT_LENGTH : usize = 4;
const SIG_LENGTH : usize = 4;
const CONTENT_LENGTH_COPYTRESHOLD : usize = 512;
/// size of content/id is define in striple which could be corrupted. Therefore we need to limit
/// the size (bigger allocation would be in memory file (bad practice) and full striple).
/// This is therefore the maximum xtended size allowed to be decoded (number of bytes). 
const MAX_ALLOC_SIZE : usize = 30000;

#[cfg(feature="serialize")]
use serde::{Serializer,Serialize,Deserialize,Deserializer};
#[cfg(feature="serialize")]
use base64;

macro_rules! fields_if_0{() => (
  #[inline]
  fn get_algo_key(&self) -> ByteSlice {
    self.0.get_algo_key()
  }
  #[inline]
  fn get_enc(&self) -> ByteSlice {
    self.0.get_enc()
  }
  #[inline]
  fn get_id(&self) -> &[u8] {
    self.0.get_id()
  }
  #[inline]
  fn get_from(&self) -> ByteSlice {
    self.0.get_from()
  }
  #[inline]
  fn get_about(&self) -> ByteSlice {
    self.0.get_about()
  }
  #[inline]
  fn get_content<'a>(&'a self) -> Option<&'a BCont<'a>> {
    self.0.get_content()
  }
  #[inline]
  fn get_content_ids(&self) -> Vec<&[u8]> {
    self.0.get_content_ids()
  }
  #[inline]
  fn get_key(&self) -> &[u8] {
    self.0.get_key()
  }
  #[inline]
  fn get_sig(&self) -> &[u8] {
    self.0.get_sig()
  }
  #[inline]
  fn ser_tosig<'a>(&'a self, res : &mut Vec<u8>) -> Result<Option<&'a BCont<'a>>> {
    self.0.ser_tosig(res)
  }

  #[inline]
  fn striple_ser_with_def<'a> (&'a self) -> Result<(Vec<u8>,Option<&'a BCont<'a>>)> {
    self.0.striple_ser_with_def()
  }
  #[inline]
  fn striple_ser<'a> (&'a self, v : Vec<u8>) -> Result<(Vec<u8>,Option<&'a BCont<'a>>)> {
    self.0.striple_ser(v)
  }
  #[inline]
  fn striple_def (&self) -> StripleDef {
    self.0.striple_def()
  }

    )
}

 
pub type Result<R> = StdResult<R,Error>;
/// Striple could be a standard struct, or references to contents from others struct
/// Trait should not be implemented for other struct (or conformance with test case needed).
/// Other struct should implement AsStriple (probably to stripleRef).
/// TODO word on enum to serialize and manage parametric types
pub trait StripleIf : StripleFieldsIf {

  fn check_content<R : Read>(&self, cont : &mut R, sig : &[u8]) -> Result<bool>;
  fn sign_content<R : Read>(&self, _ : &[u8], _ : &mut R) -> Result<Vec<u8>>;
  fn derive_id(&self, sig : &[u8]) -> Result<Vec<u8>>;
  fn check_id_derivation(&self, sig : &[u8], id : &[u8]) -> Result<bool>;
  /// check striple integrity (signature and key)
  fn check<S : StripleIf> (&self, from : &S) -> Result<bool> {
    //self.check_id(from).and_then(|a|self.check_sig(from).map(|b|a && b))
    Ok(self.check_id(from)? && self.check_sig(from)?)
  }


  /// check signature of striple
  fn check_sig<S : StripleIf>(&self, from : &S) -> Result<bool> {
    Ok(match self.get_tosig() {
      Ok((v, oc)) => {
        let mut cv = Cursor::new(v);
        *from.get_id() == *self.get_from() && match oc {
          Some (bc) => {
            match bc.get_readable() {
              Ok(mut r) => from.check_content(&mut cv.chain(r.trait_read()), self.get_sig())?,
              Err(_) => false,
            }
          },
          None => from.check_content(&mut cv, self.get_sig())?,
        }
      },
      Err(_) => false,
    })
  }

  /// check key of striple
  fn check_id<S : StripleIf>(&self, from : &S) -> Result<bool> {
    from.check_id_derivation(self.get_sig(), self.get_id())
  }

}

/// trait to use striple as fat pointer
pub trait GenStripleIf : StripleFieldsIf {
  fn check_content(&self, cont : &mut Read, sig : &[u8]) -> Result<bool>;
  fn sign_content(&self, _ : &[u8], _ : &mut Read) -> Result<Vec<u8>>;
  fn derive_id(&self, sig : &[u8]) -> Result<Vec<u8>>;
  fn check_id_derivation(&self, sig : &[u8], id : &[u8]) -> Result<bool>;
  fn check(&self, from : &GenStripleIf) -> Result<bool> {
    Ok(self.check_id(from)? && self.check_sig(from)?)
  }
  fn check_sig(&self, from : &GenStripleIf) -> Result<bool> {
    Ok(match self.get_tosig() {
      Ok((v, oc)) => {
        let mut cv = Cursor::new(v);
        *from.get_id() == *self.get_from() && match oc {
          Some (bc) => {
            match bc.get_readable() {
              Ok(mut r) => from.check_content(&mut cv.chain(r.trait_read()), self.get_sig())?,
              Err(_) => false,
            }
          },
          None => from.check_content(&mut cv, self.get_sig())?,
        }
      },
      Err(_) => false,
    })
  }

  fn check_id(&self, from : &GenStripleIf) -> Result<bool> {
    from.check_id_derivation(self.get_sig(), self.get_id())
  }
}
/*
impl<S : StripleIf> GenStripleIf for S {
  #[inline]
  fn check_content(&self, cont : &mut Read, sig : &[u8]) -> Result<bool> {
    <Self as StripleIf>::check_content(self,cont,sig)
  }
  #[inline]
  fn sign_content(&self, a : &[u8], b : &mut Read) -> Result<Vec<u8>> {
    <Self as StripleIf>::sign_content(self,a,b)
  }
  #[inline]
  fn derive_id(&self, sig : &[u8]) -> Result<Vec<u8>> {
    <Self as StripleIf>::derive_id(self,sig)
  }
  #[inline]
  fn check_id_derivation(&self, sig : &[u8], id : &[u8]) -> Result<bool> {
    <Self as StripleIf>::check_id_derivation(self,sig,id)
  }
  #[inline]
  fn check(&self, from : &GenStripleIf) -> Result<bool> {
    <Self as StripleIf>::check(self,from)
  }
  #[inline]
  fn check_sig(&self, from : &GenStripleIf) -> Result<bool> {
    <Self as StripleIf>::check_sig(self,from)
  }
  #[inline]
  fn check_id(&self, from : &GenStripleIf) -> Result<bool> {
    <Self as StripleIf>::check_id(self,from)
  }
}*/

/// use to mix static lifetime and non static lifetime, allows more flexibility for composing
/// striples
pub enum ByteSlice<'a> {
  Static(&'static [u8]),
  Owned(&'a[u8]),
}

impl<'a> Deref for ByteSlice<'a> {

  type Target = [u8];
  fn deref(&self) -> &[u8] {
    match *self {
      ByteSlice::Static(ref s) => &s[..],
      ByteSlice::Owned(ref s) => &s[..],
    }
  }
}

impl<'a> AsRef<[u8]> for ByteSlice<'a> {
  fn as_ref(&self) -> &[u8] {
    match *self {
      ByteSlice::Static(ref s) => &s[..],
      ByteSlice::Owned(ref s) => &s[..],
    }
  }
}
/*impl<'a> ByteSlice<'a> {
  pub fn bytes(&self) -> &[u8] {
    match *self {
      ByteSlice::Static(ref s) => &s[..],
      ByteSlice::Owned(ref s) => &s[..],
    }
  }
}*/
pub trait StripleFieldsIf : Debug {

  /// get key of striple defining algo scheme
  fn get_algo_key(&self) -> ByteSlice;

  /// get content enc value
  fn get_enc(&self) -> ByteSlice;

  /// get striple key value
  fn get_id(&self) -> &[u8];

  /// get striple key value
  fn get_from(&self) -> ByteSlice;

  /// get striple key value
  fn get_about(&self) -> ByteSlice;

  /// get content value
  fn get_content<'a>(&'a self) -> Option<&'a BCont<'a>>;

  /// get content ids value
  fn get_content_ids(&self) -> Vec<&[u8]>;

  /// get striple key value
  fn get_key(&self) -> &[u8];

  /// get striple signature value
  fn get_sig(&self) -> &[u8];

  fn ser_tosig<'a> (&'a self, res : &mut Vec<u8>) -> Result<Option<&'a BCont<'a>>> {
    if *self.get_id() != *self.get_from() {
      res.append(&mut self.get_from().to_vec());
    }
    // never encode the same value for about and id
    if *self.get_id() != *self.get_about() {
      res.append(&mut self.get_about().to_vec());
    }
    res.append(&mut self.get_key().to_vec());
    
    for cid in self.get_content_ids().iter(){
      res.append(&mut cid.to_vec());
    };
    // TODO very fishy
    let (con, ocon) = match self.get_content() {
      Some(ref c) => {
        let (ser, _) = c.copy_ser()?;
        if ser {
          let b = c.get_byte()?;
          (Some(b),None)
        } else {
          (None,self.get_content())
        }
      },
      None => {
        (None,None)
      },
    };
    con.map(|c|res.append(&mut c.to_vec()));
    Ok(ocon)
  }

  #[inline]
  /// get bytes which must be signed
  /// TODO return chain of read??(cursor over slices) -> todo self implement it to get two ix only
  /// (current slice and ix in current slice)
  fn get_tosig<'a>(&'a self) -> Result<(Vec<u8>,Option<&'a BCont<'a>>)> {
    let mut res = Vec::new();
    let ocont = self.ser_tosig(&mut res)?;
    Ok((res,ocont))
  }

  /// encode to bytes, but only striple content : Vec<u8> only include striple info.
  /// Might do others operation (like moving a file in a right container.
  /// If BCont is a Path, the path is written with a 2byte xtendsize before
  fn striple_ser_with_def<'a> (&'a self) -> Result<(Vec<u8>,Option<&'a BCont<'a>>)> {
    let mut res = Vec::new();
    push_id(&mut res, self.get_algo_key().deref());
    push_id(&mut res, &self.get_enc());
    ser_stripledesc(&self.striple_def(), &mut res)?;
    let r = self.striple_ser(res)?;

    Ok(r)
  }

  fn striple_ser<'a> (&'a self, mut res : Vec<u8>) -> Result<(Vec<u8>,Option<&'a BCont<'a>>)> {
    res.append(&mut self.get_id().to_vec());
    res.append(&mut self.get_sig().to_vec());

    let ocon = self.ser_tosig(&mut res)?;

    Ok((res,ocon))
  }

  fn striple_def (&self) -> StripleDef {
    StripleDef {
        idsize : self.get_id().len(),
        fromsize :  if *self.get_id() != *self.get_from() {
          self.get_from().len()
        } else {
          0
        },
        sigsize : self.get_sig().len(),
        aboutsize : if *self.get_id() != *self.get_about() {
          self.get_about().len()
        } else {
          0
        },
        keysize : self.get_key().len(),
        contentidssize : self.get_content_ids().iter().map(|i|i.len()).collect(),
        contentsize : self.get_content().as_ref().map(|bcont|bcont.len()).unwrap_or(0),
    }
  }
 
}

/// Use of striple kind for default implementation (StripleIf is implemented for StripleImpl
/// trait). In most cases to make an struct a striple, this is the best approach.
pub trait StripleImpl : StripleFieldsIf {
  type Kind : StripleKind;
}
pub trait GenStripleImpl : StripleFieldsIf {
  type Kind : StripleKind;
}


pub trait InstantiableSelfStripleImpl : OwnedStripleFieldsIf + InstantiableStripleImpl {
  fn self_init(&mut self) -> Result<()> {
/*  fn private_key_clone(&self) -> Vec<u8> {
    self.private_key_ref().to_vec()
  }

  fn private_key_ref(&self) -> &[u8];
}*/
    let (sig,id) = {
        let priv_k = self.private_key_ref();
        let (v, obc) = self.get_tosig()?;
        let mut cv = Cursor::new(v);
        let sig = match obc {
          Some (bc) => {
            let mut r = try!(bc.get_readable());
            let mut tos = cv.chain(r.trait_read());
            <<Self as StripleImpl>::Kind as StripleKind>::S::sign_content(priv_k, &mut tos)?
          },
          None => <<Self as StripleImpl>::Kind as StripleKind>::S::sign_content(priv_k, &mut cv)?,
        };
        let id = <<Self as StripleImpl>::Kind as StripleKind>::D::derive_id(&sig)?;
        (sig, id)
      };

      self.add_from(id.clone());
      self.init(sig,id);

      Ok(())
  }
}

pub trait InstantiableStripleImpl : StripleImpl + Sized {
  /// add from (should not be call directly, is called by default calc_init implementation)
  fn add_from(&mut self,
    from : Vec<u8>);
  /// init signing (should not be call directly, is called by default calc_init implementation)
  fn init(&mut self,
    sig : Vec<u8>,
    id : Vec<u8>);


  /// make initial striple sig and key (both struct should be initialized byte vec).
  fn calc_init<OST : OwnedStripleIf>(&mut self,
//    contentenc : Vec<u8>,
    from : &OST,
 //   about: Option<Vec<u8>>,
 //   contentids : Vec<Vec<u8>>,
 //   content : Option<BCont<'static>>,
  ) -> Result<()> {

    self.add_from(from.get_id().to_vec());
    let sig = from.sign(&(*self))?;
    let id = from.derive_id(&sig)?;

    self.init(sig,id);

    Ok(())
 
  }

}

impl<SI : GenStripleImpl> GenStripleIf for SI {
  #[inline]
  fn check_content(&self, cont : &mut Read, sig : &[u8]) -> Result<bool> {
    <SI::Kind as StripleKind>::S::check_content(&self.get_key(), cont, sig)
  }
  #[inline]
  fn sign_content(&self, pri : &[u8], con : &mut Read) -> Result<Vec<u8>> {
    <SI::Kind as StripleKind>::S::sign_content(pri, con)
  }
  #[inline]
  fn check_id_derivation(&self, sig : &[u8], id : &[u8]) -> Result<bool> {
    <SI::Kind as StripleKind>::D::check_id_derivation(sig,id)
  }
  #[inline]
  fn derive_id(&self, sig : &[u8]) -> Result<Vec<u8>> {
    <SI::Kind as StripleKind>::D::derive_id(sig)
  }
}
impl<SI : StripleImpl> StripleIf for SI {

  #[inline]
  fn check_content<R : Read>(&self, cont : &mut R, sig : &[u8]) -> Result<bool> {
    <SI::Kind as StripleKind>::S::check_content(&self.get_key(), cont, sig)
  }
  #[inline]
  fn sign_content<R : Read>(&self, pri : &[u8], con : &mut R) -> Result<Vec<u8>> {
    <SI::Kind as StripleKind>::S::sign_content(pri, con)
  }
  #[inline]
  fn check_id_derivation(&self, sig : &[u8], id : &[u8]) -> Result<bool> {
    <SI::Kind as StripleKind>::D::check_id_derivation(sig,id)
  }
  #[inline]
  fn derive_id(&self, sig : &[u8]) -> Result<Vec<u8>> {
    <SI::Kind as StripleKind>::D::derive_id(sig)
  }
}

/// Content wrapper over bytes with Read interface
#[derive(Clone,Debug)]
pub enum BCont<'a> {
  OwnedBytes(Vec<u8>),
  NotOwnedBytes(&'a[u8]),
  LocalPath(PathBuf,usize),
}
/*  ttimpl<'a> convert::AsRef<[u8]> for BCont<'a> {
  fn(&Self) -> &[u8] {
    match Self {
     OwnedBytes(ref v) => &v[..],
     NotOwnedBytes(ref a) => *a,
     LocalPath(ref pb) => ,

    }
  }
}*/
pub enum BContRead<'a> {
  Bytes(Cursor<&'a[u8]>),
  LocalPath(File),
}
impl<'a> BContRead<'a> {
  pub fn trait_read(&'a mut self) -> &'a mut Read {
    match self {
      & mut BContRead::Bytes(ref mut b) => b,
      & mut BContRead::LocalPath(ref mut p) => p,
    }
  }
}

impl<'a> BCont<'a> {
  /// borrow object to a Read with position initialized to start
  pub fn get_readable(&'a self) -> Result<BContRead<'a>> {
    match self {
      &BCont::OwnedBytes(ref b) => Ok(BContRead::Bytes(Cursor::new(&b[..]))),
      &BCont::NotOwnedBytes(ref b) => Ok(BContRead::Bytes(Cursor::new(b))),
      &BCont::LocalPath(ref p,_) => from_error(File::open(p).map(|f|BContRead::LocalPath(f))),
    }
  }
  /// check if for serialization (and also checking) we copy the content through `get_bytes` copy or include bcont
  /// Furtremore return length (included in both cases)
  #[inline]
  pub fn copy_ser(&'a self) -> Result<(bool, usize)> {
    match self {
      &BCont::OwnedBytes(ref b) => Ok((b.len() < CONTENT_LENGTH_COPYTRESHOLD, b.len())),
      &BCont::NotOwnedBytes(ref b) => Ok((b.len() < CONTENT_LENGTH_COPYTRESHOLD, b.len())),
      &BCont::LocalPath(ref p,_) => {
        let s = metadata(p)?.len() as usize;
        Ok((false, s))
      },
    }
  }
 
  /// borrow object to a Read with position initialized to start
  /// Warning this put all byte in memory this is very bad for File variant.
  /// TODO when Read use in deser see if delete this
  pub fn get_byte(&self) -> Result<Vec<u8>> {
    match self {
      &BCont::OwnedBytes(ref b) => Ok(b.clone()),
      &BCont::NotOwnedBytes(ref b) => Ok(b.to_vec()),
      &BCont::LocalPath(_,_) => {
        let mut bcr = try!(self.get_readable());
        let mut r = Vec::new();
        try!(bcr.trait_read().read_to_end(&mut r));
        Ok(r)
      },
    }
  }
  fn to_own(&self) -> BCont<'static> {
    match self {
      &BCont::NotOwnedBytes(ref b) => BCont::OwnedBytes(b.to_vec()),
      &BCont::OwnedBytes(ref b) => BCont::OwnedBytes(b.clone()),
      &BCont::LocalPath(ref p,s) => BCont::LocalPath(p.clone(),s),
    }
  }
  fn to_ref<'b>(&'b self) -> BCont<'b> {
    match self {
      &BCont::NotOwnedBytes(ref b) => BCont::NotOwnedBytes(b),
      &BCont::OwnedBytes(ref b) => BCont::NotOwnedBytes(&b[..]),
      &BCont::LocalPath(ref p,s) => BCont::LocalPath(p.clone(),s),
    }
  }
  fn len(&self) -> usize {
    match self {
      &BCont::NotOwnedBytes(ref b) => b.len(),
      &BCont::OwnedBytes(ref b) => b.len(),
      &BCont::LocalPath(ref _p,s) => s,
    }
  }
}



/*
impl Read for Content {
}*/

/// used to categorize a striple and its associated scheme
/// for exemple a struct can be convert to two striple :
///
/// fn<T : StripleKind> as_striple (user : &User) -> Striple<T>{...}
/// Sized to 0 (usage of phantomdata)
pub trait StripleKind : Debug + Clone + Send + Sync + 'static {
  type D : IDDerivation;
  type S : SignatureScheme;

  /// get key to the corresponding algo combination striple
  fn get_algo_key() -> &'static [u8];

}

/// specifies the scheme is public
pub trait PublicScheme : SignatureScheme{}


/// build key from bytes (signature)
pub trait IDDerivation {
  // possible expected size if constant key der size
  const EXPECTED_SIZE : Option<usize>;
  /// parameter is signature
  fn derive_id(sig : &[u8]) -> Result<Vec<u8>>;
  /// first parameter is signature, second is key
  fn check_id_derivation(sig : &[u8], id : &[u8]) -> Result<bool> {
    Ok(&Self::derive_id(sig)?[..] == id)
  }
}

/// when signature is not to long we derive with identity
pub struct IdentityKD;

/// key is same as signature (case where signature does not need to be serialize) 
/// warning this is prone to creating big key in heterogenous network (size of sig depends on
/// parent striple).
impl IDDerivation for IdentityKD {
  const EXPECTED_SIZE : Option<usize> = None;
  /// id
  #[inline]
  fn derive_id(sig : &[u8]) -> Result<Vec<u8>> {
    Ok(sig.to_vec())
  }
  /// simply equality
  #[inline]
  fn check_id_derivation(sig : &[u8], id : &[u8]) -> Result<bool> {
    Ok(sig == id)
  }
}



/// signing and checking scheme
/// when implementing this trait the following properties are required :
/// - two subsequent call to signing shoud create two different signature (otherwhise striple with
/// same content will have the same key), or the key derivation key use in combination should be
/// random (for example in public).
/// - key verification must be invalid if signature change
/// TODO in future I may switch to not using fat pointers on read
pub trait SignatureScheme {

  /// first parameter is private key, second parameter is content
  fn sign_content(pri : &[u8], cont : &mut Read) -> Result<Vec<u8>>;

// TODO result in check (right now an error is seen as not checked)?
  /// first parameter is public key, second is content and third is signature
  fn check_content(publ : &[u8],cont : &mut Read, sig : &[u8]) -> Result<bool>;

  /// create keypair (first is public, second is private)
  /// TODO allow returning none as private keypair for public scheme
  fn new_keypair() -> Result<(Vec<u8>, Vec<u8>)>;

}

pub trait OwnedStripleFieldsIf : StripleFieldsIf {

  /// owned striple has a private key, default implementation is inefficient
  fn private_key_clone(&self) -> Vec<u8> {
    self.private_key_ref().to_vec()
  }

  fn private_key_ref(&self) -> &[u8];
}

pub trait OwnedStripleIf : StripleIf + OwnedStripleFieldsIf {
  /// first parameter is private key, second parameter is content
  fn sign<TS : StripleIf> (&self, st : &TS) -> Result<Vec<u8>> {
    let (v, obc) = st.get_tosig()?;
    let mut cv = Cursor::new(v);
    match obc {
      Some (bc) => {
        let mut r = try!(bc.get_readable());
        self.sign_content(self.private_key_ref(), &mut cv.chain(r.trait_read()))
      },
      None => self.sign_content(self.private_key_ref(), &mut cv),
    }
  }

}


// TODO owned pair of striple

impl<'a, ST : GenStripleIf> AsStripleIf for (&'a ST, &'a [u8]) {
  #[inline]
  fn as_striple_if(&self) -> &GenStripleIf {
    self.0
  }
}

impl<'a, ST : GenStripleIf> AsStripleIf for (ST, Vec<u8>) {
  #[inline]
  fn as_striple_if(&self) -> &GenStripleIf {
    &self.0
  }
}

impl<ST : StripleIf> OwnedStripleFieldsIf for (ST, Vec<u8>) {

  #[inline]
  fn private_key_clone(&self) -> Vec<u8> {
    self.1.clone()
  }

  #[inline]
  fn private_key_ref (&self) -> &[u8] {
    &self.1[..]
  }
}
#[derive(Debug)]
pub struct SelfOwned<ST>(ST,Vec<u8>);
impl<ST : InstantiableStripleImpl> StripleImpl for SelfOwned<ST> {
  type Kind = <ST as StripleImpl>::Kind;
}
impl<ST : InstantiableStripleImpl> InstantiableSelfStripleImpl for SelfOwned<ST> {
}
impl<ST : InstantiableStripleImpl> InstantiableStripleImpl for SelfOwned<ST> {
  fn add_from(&mut self,
    from : Vec<u8>) {
    self.0.add_from(from)
  }

  fn init(&mut self,
    sig : Vec<u8>,
    id : Vec<u8>) {
    self.0.init(sig,id)
  }
}

impl<ST : InstantiableStripleImpl> StripleFieldsIf for SelfOwned<ST> {
  fields_if_0!();
}

impl<ST : InstantiableStripleImpl> OwnedStripleFieldsIf for SelfOwned<ST> {

  #[inline]
  fn private_key_clone(&self) -> Vec<u8> {
    self.1.clone()
  }

  #[inline]
  fn private_key_ref (&self) -> &[u8] {
    &self.1[..]
  }

}

macro_rules! if_0{() => (
  #[inline]
  fn check_content<R : Read>(&self, cont : &mut R, sig : &[u8]) -> Result<bool> {
    self.0.check_content(cont,sig)
  }
  #[inline]
  fn sign_content<R : Read>(&self, a : &[u8], b : &mut R) -> Result<Vec<u8>> {
    self.0.sign_content(a,b)
  }
  #[inline]
  fn derive_id(&self, sig : &[u8]) -> Result<Vec<u8>> {
    self.0.derive_id(sig)
  }
  #[inline]
  fn check_id_derivation(&self, sig : &[u8], id : &[u8]) -> Result<bool> {
    self.0.check_id_derivation(sig,id)
  }
  #[inline]
  fn check<S : StripleIf> (&self, from : &S) -> Result<bool> {
    self.0.check(from)
  }
  #[inline]
  fn check_sig<S : StripleIf>(&self, from : &S) -> Result<bool> {
    self.0.check_sig(from)
  }
  #[inline]
  fn check_id<S : StripleIf>(&self, from : &S) -> Result<bool> {
    self.0.check_id(from)
  }


    )}

impl<ST : StripleIf> StripleIf for (ST, Vec<u8>) {
  if_0!();
}


impl<ST : StripleIf> StripleFieldsIf for (ST, Vec<u8>) {
  fields_if_0!();
}

impl<'b, ST : StripleIf> StripleIf for (&'b ST, &'b [u8]) {
  if_0!();
}
impl<'b, ST : StripleIf> StripleFieldsIf for (&'b ST, &'b [u8]) {
  fields_if_0!();
}



impl<'b, ST : StripleIf> OwnedStripleFieldsIf for (&'b ST, &'b [u8]) {

  #[inline]
  fn private_key_clone (&self) -> Vec<u8> {
    self.1.to_vec()
  }

  #[inline]
  fn private_key_ref (&self) -> &[u8] {
    self.1
  }
}
impl<'b, ST : StripleIf> OwnedStripleIf for (&'b ST, &'b [u8]) {
}

impl<ST : StripleIf> OwnedStripleIf for (ST, Vec<u8>) { }

/// Type to use an striple as Public, allowing to sign/create striple from it without others info
/// (see Ownedstriple implementation). Usage with non public striple will result in error when
/// signing or worst when checking.
pub trait PubStriple : StripleIf{}
//impl<T : StripleKind, S : StripleImpl<T>> PubStriple for S where T::S : PublicScheme {}
impl<K : StripleKind> PubStriple for Striple<K> where K::S : PublicScheme {}
impl<'a, K : StripleKind> PubStriple for StripleRef<'a,K> where K::S : PublicScheme {}
/*
/// Mark as public based on some asumption, it is the same as using `(&S,&[][..])`
#[derive(Debug)]
pub struct UnsafePubStriple<'a, S : StripleIf + 'a> (&'a S);

impl<'a, S : StripleIf> PubStriple for UnsafePubStriple<'a, S> {}
*/
/// public scheme uses same value for public and private key
impl<S : PubStriple> OwnedStripleFieldsIf for S {

  fn private_key_clone (&self) -> Vec<u8> {
    self.get_key().to_vec()
  }

  fn private_key_ref (&self) -> &[u8] {
    self.get_key()
  }
}
impl<S : PubStriple> OwnedStripleIf for S {
}

/// Striple struct object to manipulate an striple
#[derive(Debug,Clone)]
pub struct Striple<T : StripleKind> {
  /// id of the striple defining the encoding of the content
  /// optional (null vec otherwhise)
  pub contentenc : Vec<u8>,
  /// id of the striple
  pub id : Vec<u8>,
  /// id of from striple
  from : Vec<u8>,
  /// signature of the striple (by its `from` striple)
  sig : Vec<u8>,
  /// id of about striple
  about : Vec<u8>,
  /// public key of the striple
  key : Vec<u8>,
  /// Possible ids in content
  contentids : Vec<Vec<u8>>,
  /// Possible content
  /// optional
  content : Option<BCont<'static>>,

  phtype : PhantomData<T>,
}

#[derive(Debug,Clone)]
pub struct StripleDef {
  pub idsize : usize,
  pub fromsize : usize,
  pub sigsize : usize,
  pub aboutsize : usize,
  pub keysize : usize,
  pub contentidssize : Vec<usize>,
  pub contentsize : usize,
}



/// Striple struct object to use striple functionality from other existing struct by using
/// reference only. For field definition please refer to `Striple`
#[derive(Debug,Clone)]
pub struct StripleRef<'a, T : StripleKind> {
  contentenc : &'a[u8],
  id         : &'a[u8],
  from       : &'a[u8],
  sig        : &'a[u8],
  about      : &'a[u8],
  key        : &'a[u8],
  contentids : Vec<&'a[u8]>,
  content : Option<BCont<'a>>,

  phtype : PhantomData<T>,
}

pub fn ser_stripledesc (d : &StripleDef, res : &mut Vec<u8>) -> Result<()> {

  res.append(&mut xtendsize(d.idsize,ID_LENGTH));
  res.append(&mut xtendsize(d.sigsize,SIG_LENGTH));

  // never encode the same value for about and id (about len must be initiated to 0 in this case
//  assert!(d.idsize != d.aboutsize || );
  res.append(&mut xtendsize(d.fromsize,ID_LENGTH));
  res.append(&mut xtendsize(d.aboutsize,ID_LENGTH));
  res.append(&mut xtendsize(d.keysize,KEY_LENGTH));
  res.append(&mut xtendsize(d.contentidssize.len(),CONTENTIDS_LENGTH));
  for cid in d.contentidssize.iter() {
    res.append(&mut xtendsize(*cid,ID_LENGTH));
  };
  res.append(&mut xtendsize(d.contentsize,CONTENT_LENGTH));
  Ok(())
}



impl<T : StripleKind> InstantiableStripleImpl for Striple<T> {
  fn add_from(&mut self,
    from : Vec<u8>) {
    self.from = from;
  }
 
  fn init(&mut self,
    sig : Vec<u8>,
    id : Vec<u8>) {
    self.sig = sig;
    self.id = id;
  }
}
impl<T : StripleKind> Striple<T> {

  /// first step is creation of the key pair for this striple.
  /// then signature by `from` and id generation.
  /// When `from` is not specified we consider that we sign ourself with the new striple :
  /// the striple is initialized from itself (for example a master key).
  /// None for `about` is the same as using `from` id.
  /// Return the initialized striple and its private key.
  /// TODO return result (add sign error and bcont error)
  pub fn new<OST : OwnedStripleIf> (
    contentenc : Vec<u8>,
    from : &OST,
    about: Option<Vec<u8>>,
    contentids : Vec<Vec<u8>>,
    content : Option<BCont<'static>>,
  ) -> Result<(Striple<T>,Vec<u8>)> {
    let (pubkey,prikey) = T::S::new_keypair()?;
    let mut res = Striple {
        contentenc : contentenc,
        id : vec!(),
        from : vec!(),
        sig : vec!(),
        about : about.unwrap_or(vec!()),
        key : pubkey,
        contentids : contentids,
        content : content,

        phtype : PhantomData,
    };
    res.calc_init(from)?;

    Ok((res,prikey))
  }
  pub fn new_self (
    contentenc : Vec<u8>,
    about: Option<Vec<u8>>,
    contentids : Vec<Vec<u8>>,
    content : Option<BCont<'static>>,
  ) -> Result<(Striple<T>,Vec<u8>)> {
    let (pubkey,prikey) = T::S::new_keypair()?;
    let res = Striple {
        contentenc : contentenc,
        id : vec!(),
        from : vec!(),
        sig : vec!(),
        about : about.unwrap_or(vec!()),
        key : pubkey,
        contentids : contentids,
        content : content,

        phtype : PhantomData,
    };
    let mut owned = SelfOwned(res,prikey);

    owned.self_init()?;

    Ok((owned.0,owned.1))
  }
 
}


impl<'a,T : StripleKind> StripleImpl for StripleRef<'a,T> {
  type Kind = T;
}
impl<T : StripleKind> StripleImpl for Striple<T> {
  type Kind = T;
}
/*
impl<T : StripleKind> StripleIf for Striple<T> {
  #[inline]
  fn check_content(&self, cont : &mut Read, sig : &[u8]) -> Result<bool> {
    T::S::check_content(&self.key, cont, sig)
  }
  #[inline]
  fn sign_content(&self, pri : &[u8], con : &mut Read) -> Result<Vec<u8>> {
    T::S::sign_content(pri, con)
  }
  #[inline]
  fn check_id_derivation(&self, sig : &[u8], id : &[u8]) -> Result<bool> {
    T::D::check_id_derivation(sig,id)
  }
  #[inline]
  fn derive_id(&self, sig : &[u8]) -> Result<Vec<u8>> {
    T::D::derive_id(sig)
  }
 
}*/

impl<T : StripleKind> StripleFieldsIf for Striple<T> {
  #[inline]
  fn get_algo_key(&self) -> ByteSlice {
    ByteSlice::Static(T::get_algo_key())
  }

 
  #[inline]
  fn get_key(&self) -> &[u8]{&self.key}
  #[inline]
  fn get_sig(&self) -> &[u8]{&self.sig}
  #[inline]
  fn get_id(&self) -> &[u8]{&self.id}
  #[inline]
  fn get_about(&self) -> ByteSlice {
    if self.about.len() > 0 {
      ByteSlice::Owned(&self.about)
    } else {
      ByteSlice::Owned(&self.id)
    }
  }
  #[inline]
  fn get_from(&self) -> ByteSlice {ByteSlice::Owned(&self.from)}
  #[inline]
  fn get_enc(&self) -> ByteSlice {ByteSlice::Owned(&self.contentenc)}
  #[inline]
  fn get_content<'a>(&'a self) -> Option<&'a BCont<'a>> {
    self.content.as_ref()
  }
  #[inline]
  fn get_content_ids(&self) -> Vec<&[u8]> {
    self.contentids.iter().map(|r|&r[..]).collect()
  }

}
/*
impl<'a,T : StripleKind> StripleIf for StripleRef<'a,T> {

  #[inline]
  fn check_content(&self, cont : &mut Read, sig : &[u8]) -> Result<bool> {
    T::S::check_content(self.key, cont, sig)
  }
  #[inline]
  fn sign_content(&self, pri : &[u8], con : &mut Read) -> Result<Vec<u8>> {
    T::S::sign_content(pri, con)
  }
  #[inline]
  fn check_id_derivation(&self, sig : &[u8], id : &[u8]) -> Result<bool> {
    T::D::check_id_derivation(sig,id)
  }
  #[inline]
  fn derive_id(&self, sig : &[u8]) -> Result<Vec<u8>> {
    T::D::derive_id(sig)
  }
}*/

impl<'a,T : StripleKind> StripleFieldsIf for StripleRef<'a,T> {
  #[inline]
  fn get_algo_key(&self) -> ByteSlice {
    ByteSlice::Static(T::get_algo_key())
  }


  #[inline]
  fn get_key(&self) -> &[u8]{self.key}
  #[inline]
  fn get_sig(&self) -> &[u8]{self.sig}
  #[inline]
  fn get_id(&self) -> &[u8]{self.id}
  #[inline]
  fn get_about(&self) -> ByteSlice {
    if self.about.len() > 0 {
      ByteSlice::Owned(self.about)
    } else {
      ByteSlice::Owned(self.id)
    }
  }
  #[inline]
  fn get_from(&self) -> ByteSlice {ByteSlice::Owned(self.from)}
  #[inline]
  fn get_enc(&self) -> ByteSlice {ByteSlice::Owned(self.contentenc)}
  #[inline]
  fn get_content<'b>(&'b self) -> Option<&'b BCont<'b>> {
    self.content.as_ref()
  }
  #[inline]
  fn get_content_ids(&self) -> Vec<&[u8]> {self.contentids.clone()}
}

/// deserialize to reference striple without and kind resolution (cast to kind of required kind)
pub fn ref_builder_id<'a,K : StripleKind>(algoid :&[u8], sr : StripleRef<'a,K>) -> Result<StripleRef<'a,K>> {
  if algoid != K::get_algo_key() && K::get_algo_key() != NOKEY {
    return Err(Error("Bad algo kind for this type of striple".to_string(), ErrorKind::UnexpectedStriple, None))
  };
  Ok(sr)
}
/// deserialize to striple without and kind resolution (cast to kind of required kind)
pub fn ref_builder_id_copy<'a,K : StripleKind>(algoid :&[u8], sr : StripleRef<'a,K>) -> Result<Striple<K>> {
  if algoid != K::get_algo_key() && K::get_algo_key() != NOKEY {
    return Err(Error("Bad algo kind for this type of striple".to_string(), ErrorKind::UnexpectedStriple, None))
  };
  Ok(sr.as_striple())
}
/// deserialize to striple without and kind resolution (cast to kind of required kind)
pub fn copy_builder_id<'a,K : StripleKind>(algoid :&[u8], sr : Striple<K>) -> Result<Striple<K>> {
  if algoid != K::get_algo_key() && K::get_algo_key() != NOKEY {
    return Err(Error("Bad algo kind for this type of striple".to_string(), ErrorKind::UnexpectedStriple, None))
  };
  Ok(sr)
}

#[inline]
/// dser without lifetime TODO redesign to interface on same as striple_dser_with_def : here useless as
/// cannot cast in any triple without a copy
pub fn striple_copy_dser<T : StripleIf, K : StripleKind, FS : StripleIf, B> (bytes : &[u8], obc : Option<BCont>, docheck : Option<&FS>, builder : B) -> Result<T>
  where B : Fn(&[u8], Striple<K>) -> Result<T>
{
  striple_dser_with_def(bytes, obc, docheck,
   |algoid, sref| {
    builder(algoid, sref.as_striple())
  }
  )
}

pub fn striple_read_def(bytes : &[u8], ix : &mut usize) -> StripleDef
{
  let idsize = xtendsizedec(bytes, ix, ID_LENGTH);

  let sigsize = xtendsizedec(bytes, ix, SIG_LENGTH);
  
  let fromsize = xtendsizedec(bytes, ix, ID_LENGTH);
  let aboutsize = xtendsizedec(bytes, ix, ID_LENGTH);

  let keysize = xtendsizedec(bytes, ix, KEY_LENGTH);

  let nbcids = xtendsizedec(bytes, ix, CONTENTIDS_LENGTH);
  let mut contentidssize = Vec::new();
  for _ in 0 .. nbcids {
    let is = xtendsizedec(bytes, ix, ID_LENGTH);
    contentidssize.push(is);
  };

  let contentsize = xtendsizedec(bytes, ix, CONTENT_LENGTH);

  StripleDef {
    idsize : idsize,
    fromsize : fromsize,
    sigsize : sigsize,
    aboutsize : aboutsize,
    keysize : keysize,
    contentidssize : contentidssize,
    contentsize : contentsize,
  }

}
 
pub fn striple_dser_with_def<'a, T : StripleIf, K : StripleKind, FS : StripleIf, B> (bytes : &'a[u8], obc : Option<BCont<'a>>, docheck : Option<&FS>, ref_builder : B) -> Result<T>
  where B : Fn(&[u8], StripleRef<'a,K>) -> Result<T>
{
  let mut ix = 0;
  let algoenc = read_id (bytes, &mut ix);

  let contentenc = read_id (bytes, &mut ix); 

  let sdef = striple_read_def(bytes, &mut ix);
  striple_dser(bytes,obc,docheck,ref_builder,&sdef, algoenc, contentenc, &mut ix)
}
 
/// decode from bytes, with possible signing validation
/// Deserialize does not result in StripleIf, because StripleIf is use to allow reference to
/// existing structure and adding content to a structure and still being an StripleIf, yet
/// deserialize as a library item is only here to enforce encoding of striple : 
/// to use on other structure deserialize must be use by a more general
/// deserialize primitive or if particular non striple encoding (in json for instance), the
/// resulting struct will use AsStriple (probably to stripleref) to use striple primitive.
///
/// If optional BCont is used, we assume it is valid, a size check is done as it is not to costy.
/// TODO optional BCon as param for deser + file size check??? !!!
pub fn striple_dser<'a, T : StripleIf, K : StripleKind, FS : StripleIf, B> (bytes : &'a[u8], obc : Option<BCont<'a>>, docheck : Option<&FS>, ref_builder : B, sdef : &StripleDef, algoenc : &'a[u8], contentenc : &'a[u8], ix : &mut usize) -> Result<T>
  where B : Fn(&[u8], StripleRef<'a,K>) -> Result<T>
{
  
  let id = read_len(bytes,ix,sdef.idsize);
  

  let mut sig = read_len(bytes,ix,sdef.sigsize);

  if sig.len() == 0 {
    sig = id;
  }
  
  let startcontent = *ix;

  let from = if sdef.fromsize == 0 {
    id
  } else {
    read_len(bytes,ix,sdef.fromsize)
  };

  let about = if sdef.aboutsize == 0 {
    id
  } else {
    read_len(bytes,ix,sdef.aboutsize)
  };

  let key = read_len(bytes,ix,sdef.keysize);

  let contentids = sdef.contentidssize.iter().map(|s|read_len(bytes,ix,*s)).collect();

  let s = sdef.contentsize;
  if let Some(fromst) = docheck {
    if fromst.get_id() != &from[..] {
      return Err(Error("Unexpected from id".to_string(), ErrorKind::UnexpectedStriple, None))
    };
    let tocheck = &bytes[startcontent .. bytes.len()];
 
    if !( fromst.check_id_derivation(sig,id)? &&
      match &obc {
        &Some (ref bc) => {
          let mut r = bc.get_readable()?;
          let mut tos = Cursor::new(tocheck).chain(r.trait_read());
          fromst.check_content(&mut tos, sig)?
        },
        &None => fromst.check_content(&mut Cursor::new(tocheck), sig)?,
      })
    {
      return Err(Error("Invalid signature or key derivation".to_string(), ErrorKind::UnexpectedStriple, None))
    };
  };

  let content = match obc {
    Some (bc) => {
    // check size if no sign check
    if docheck.is_none() && bc.copy_ser()?.1 != s {
      return Err(Error("Mismatch size of linked content".to_string(), ErrorKind::DecodingError, None))
    };
    Some(bc)
  },
  None => {
    if s == 0 {
      None
    } else {
      *ix = *ix + s;
      if *ix <= bytes.len() {
        Some(BCont::NotOwnedBytes(&bytes[*ix - s .. *ix]))
      } else {
        return Err(Error("Mismatch size of content".to_string(), ErrorKind::DecodingError, None))
      }
    }
  },};
  if *ix != bytes.len() {
    debug!("strip or {:?} - {:?}", ix, bytes.len());
    return Err(Error("Mismatch size of striple".to_string(), ErrorKind::DecodingError, None))
  }

  if id.len() == 0 
  || from.len() == 0 
  || (sdef.contentidssize.len() == 0 && content.is_none())
  {
    Err(Error("Invalid striple decoding".to_string(), ErrorKind::DecodingError, None))
  } else {
    let r = StripleRef {
      contentenc : contentenc,
      id : id,
      from : from,
      sig : sig,
      about : about,
      key : key,
      contentids : contentids,
      content : content,

      phtype : PhantomData,
    };
    ref_builder(algoenc,r)
  }
}

/// conversion to stripleif object trait
/// It is an adapter for cleaner polymorphism
/// (see AnyStriple impl).
pub trait AsStripleIf {
  fn as_striple_if(&self) -> &GenStripleIf;
}
/*
#[derive(Debug)]
pub struct AdaptAsStriple<'a,T : 'a + AsStripleIf>(&'a T);
// boilerplate adapter code
impl<'a,T : 'a + AsStripleIf + Debug> StripleIf for AdaptAsStriple<'a,T> {
  #[inline]
  fn check_content(&self, cont : &mut Read,sig : &[u8]) -> Result<bool> {
    self.as_striple_if().check_content(cont,sig)
  }
  #[inline]
  fn sign_content(&self, a : &[u8], b : &mut Read) -> Result<Vec<u8>> {
    self.as_striple_if().sign_content(a,b)
  }
  #[inline]
  fn derive_id(&self, sig : &[u8]) -> Result<Vec<u8>> {
    self.as_striple_if().derive_id(sig)
  }
  #[inline]
  fn check_id_derivation(&self, sig : &[u8], id : &[u8]) -> Result<bool> {
    self.as_striple_if().check_id_derivation(sig,id)
  }
}

impl<'a,T : 'a + AsStripleIf + Debug> StripleFieldsIf for AdaptAsStriple<'a,T> {
  #[inline]
  fn get_enc(&self) -> &[u8] {
    self.as_striple_if().get_enc()
  }
  #[inline]
  fn get_id(&self) -> &[u8] {
    self.as_striple_if().get_id()
  }
  #[inline]
  fn get_from(&self) -> &[u8] {
    self.as_striple_if().get_from()
  }
  #[inline]
  fn get_about(&self) -> &[u8] {
    self.as_striple_if().get_about()
  }
  #[inline]
  fn get_content<'b>(&'b self) -> &'b Option<BCont<'b>> {
    self.as_striple_if().get_content()
  }
  #[inline]
  fn get_content_ids(&self) -> Vec<&[u8]> {
    self.as_striple_if().get_content_ids()
  }
  #[inline]
  fn get_key(&self) -> &[u8] {
    self.as_striple_if().get_key()
  }
  #[inline]
  fn get_algo_key(&self) -> &'static [u8] {
    self.as_striple_if().get_algo_key()
  }
  #[inline]
  fn get_sig(&self) -> &[u8] {
    self.as_striple_if().get_sig()
  }
  #[inline]
  fn get_tosig<'b>(&'b self) -> Result<(Vec<u8>,Option<&'b BCont<'b>>)> {
    self.as_striple_if().get_tosig()
  }
  #[inline]
  fn striple_ser_with_def<'b> (&'b self) -> Result<(Vec<u8>,Option<&'b BCont<'b>>)> {
    self.as_striple_if().striple_ser_with_def()
  }
  #[inline]
  fn striple_ser<'b> (&'b self, res : Vec<u8>) -> Result<(Vec<u8>,Option<&'b BCont<'b>>)> {
    self.as_striple_if().striple_ser(res)
  }


}
*/
/// Trait for structure that could be use as an striple.
/// A structure can contain multiple striple, that is why the trait is parametric.
/// TODO user example
pub trait AsStriple<'a, T : StripleKind>  {
  type Target : StripleIf;
  fn as_striple(&'a self) -> Self::Target;
}

/// Getting an striple with it own memory from ref striple
impl<'a, T : StripleKind> AsStriple<'a, T> for StripleRef<'a,T> {
  type Target = Striple<T>;
  fn as_striple(&'a self) -> Striple<T> {

    let contentids = self.contentids.iter().map(|r|r.to_vec()).collect();
    let newcontent = self.content.as_ref().map(|c|c.to_own());
 
    Striple {
        contentenc : self.contentenc.to_vec(),
        id : self.id.to_vec(),
        from : self.from.to_vec(),
        sig : self.sig.to_vec(),
        about : self.about.to_vec(),
        key : self.key.to_vec(),
        contentids : contentids,
        content : newcontent,

        phtype : PhantomData,
    }
  }
}

/// Useless implementation, used in test and as sample of real world implementation of a
/// StripleRef instantiation from another struct.
impl<'a, T : StripleKind> AsStriple<'a, T> for Striple<T> {
  type Target = StripleRef<'a, T>;
  fn as_striple(&'a self) -> StripleRef<'a, T> {
   StripleRef {
        contentenc : &self.contentenc,
        id : &self.id,
        from : &self.from,
        sig : &self.sig,
        about : &self.about,
        key : &self.key,
        contentids : self.contentids.iter().map(|r|&r[..]).collect(),
        content : self.content.as_ref().map(|c|c.to_ref()),

        phtype : PhantomData,
    }
  }
}




#[cfg(feature="serialize")]
/// Most of the time serialize is use on another struct (implementing `AsStriple` trait), this only represent the serialization of
/// the byte form of an striple
impl<T : StripleKind> Serialize for Striple<T> {
  fn serialize<S:Serializer>(&self, s: S) -> StdResult<S::Ok, S::Error> {
    let (mut v, ocon) = match self.striple_ser_with_def() {
      Ok(a) => a,
      Err(_) => 
            panic!("cannot der striple"), // TODO see next panic
    };
    match ocon {
      Some(bcon) => {
        match bcon.get_byte() {
          Ok(mut vcon) => {
            v.append(&mut vcon);
            v.serialize(s)
          },
          Err(_) => {
            // TODO follow this https://github.com/rust-lang/rustc-serialize/issues/76 -> TODO
            // switch to SERD
            // for now panic
            panic!("cannot add BCont when serializing")
          }
        }
      },
      None => v.serialize(s),
    }
  }
}

// TODO test on this (not good)
#[cfg(feature="serialize")]
impl<'de,T : StripleKind> Deserialize<'de> for Striple<T> {
  fn deserialize<D:Deserializer<'de>>(d: D) -> StdResult<Striple<T>, D::Error> {
    let tmpres = Vec::deserialize(d);
    // Dummy type
    let typednone : Option<&Striple<T>> = None;
    tmpres.and_then(|vec| 
      striple_dser_with_def(&vec, None, typednone, ref_builder_id_copy).map_err(|err|
        <D::Error as SerdeError>::custom(&format!("{:?}",err))
      )
    )
  }
}

#[derive(Debug)]
pub struct Error(pub String, pub ErrorKind, pub Option<Box<ErrorTrait + Send>>);

#[inline]
pub fn from_error<T,E1 : Into<Error>>(r : StdResult<T, E1>) -> StdResult<T,Error>
{
  r.map_err(|e| e.into())
}

#[inline]
pub fn from_option<T>(r : Option<T>) -> Result<T> {
  match r {
    Some(t) => Ok(t),
    None => Err(Error("Unexpected None value".to_string(), ErrorKind::FromOption,None)),
  }
}



impl ErrorTrait for Error {
  
  fn description(&self) -> &str {
    &self.0
  }
  fn cause(&self) -> Option<&ErrorTrait> {
    match self.2 {
      Some(ref berr) => Some (&(**berr)),
      None => None,
    }
  }
}

impl From<IOError> for Error {

  #[inline]
  fn from(e : IOError) -> Error {
    Error(e.description().to_string(), ErrorKind::IOError, Some(Box::new(e)))
  }
}

impl From<VarError> for Error {

  #[inline]
  fn from(e : VarError) -> Error {
    Error(e.description().to_string(), ErrorKind::VarError, Some(Box::new(e)))
  }
}


impl Display for Error {

  fn fmt(&self, ftr : &mut Formatter) -> FmtResult {
    let kind = format!("{:?} : ",self.1);
    try!(ftr.write_str(&kind));
    try!(ftr.write_str(&self.0));
    match self.2 {
      Some(ref tr) => {
        let trace = format!(" - trace : {}", tr);
        try!(ftr.write_str(&trace[..]));
      },
      None => (),
    };
    Ok(())
  }
}

/// tool function to convert a length in striple xtendedlength encoding
/// firt parameter is the value and second is initial number of bytes
pub fn xtendsize(l : usize, nbbyte : usize) -> Vec<u8> {
  let mut res = Vec::new();
  let mut nbbytes = nbbyte;
  // TODO precalc iteration in table
  let p : usize = usize::pow(2 as usize, nbbyte as u32 * 8);
  let maxval : usize = (p - 1) / 2;
  // no need for recursive as nbbyte is limited by usize and just a few byte
  if l > maxval {
    nbbytes = calcnbbyte(l);
      debug!("DEBUG {:?} !!!",nbbytes);

    let wrnbbyte = ((nbbytes - nbbyte)) as u8 ^ 128;
    // push last byte of wrnbbyte
    res.push (wrnbbyte);
  }
  // TODO find a way to parameterized those 4 bytes (max_value can't be use in static init)
  unsafe {
      debug!("DEBUG {:?} !!!",l);
    let v : [u8;USIZE_LEN] = if cfg!(target_endian = "little") {
      mem::transmute(usize::from_be(l))
    }else{
      mem::transmute(l)
    };
 
      debug!("DEBUG {:?} !!!",v);
      for i in 8 - nbbytes .. 8 {
        res.push(v[i]);
      }

  };

  res
}
#[cfg(target_pointer_width = "64")]
const USIZE_LEN : usize = 8;
#[cfg(target_pointer_width = "32")]
const USIZE_LEN : usize = 4;
/// tool function to get a size as standard rust usize from xtensize in 
/// bytes at a certain position for a designed size.
/// The function update index value
pub fn xtendsizedec(bytes : &[u8], ix : &mut usize, nbbyte : usize) -> usize {
  if bytes.len() < *ix + 1 {
    return 0;
  };
 
  let mut nbbytes = nbbyte;
  let mut idx = *ix;
  let mut adj_ix = 0;
  // read value
  while bytes[idx] > 127 {
    // first byte minus its first bit
    adj_ix += (bytes[idx] ^ 128) as usize;
    debug!("adjix {:?} !!!",adj_ix);
    nbbytes += adj_ix;
    idx += 1;
  }
  let res = unsafe {
  let mut v : [u8;USIZE_LEN] = mem::transmute(0usize);
  debug!("DEBUG_bef {:?}, {:?} !!!",v, nbbytes);
  if idx + nbbytes <= bytes.len() {
    let b : &[u8] = &bytes[idx .. idx + nbbytes];
    copy_nonoverlapping(b.as_ptr(),v[USIZE_LEN-nbbytes..].as_mut_ptr(),nbbytes);
    debug!("DEBUG_aft {:?} !!!",v);
    if cfg!(target_endian = "little") {
      usize::from_be(mem::transmute(v))
    } else {
      mem::transmute(v)
    }
  } else {
    0
  }
  };

  *ix = idx + nbbytes;
  res
}

/// xtendsize reading
pub fn xtendsizeread<R : Read>(r : &mut R, nbbyte : usize) -> IOResult<usize> {
  if nbbyte == 0 {
    return Ok(0);
  };
  let mut nbbytes = nbbyte;
  let mut buf = vec![0; nbbytes];
  try!(r.read(&mut buf));
  let mut adj_ix = 0;
  // read value
  while buf[adj_ix] > 127 {
    // first byte minus its first bit
    let addbytes = (buf[0] ^ 128) as usize;
    adj_ix +=1;
    // TODO test with reserve_exact
    for _ in 0 .. 1 + addbytes {
      buf.push(0);
    }
    let nbread = try!(r.read(&mut buf[ nbbytes..]));
    if nbread != 1 + addbytes {
      // TODO switch to errror and rewrite test
      return Ok(0);
    };
    nbbytes =  nbbytes + addbytes;
  }
  Ok(unsafe {
  let mut v : [u8;USIZE_LEN] = mem::transmute(0usize);
  debug!("DEBUG_bef {:?}, {:?} !!!",v, nbbytes);
  if nbbytes <= USIZE_LEN {
    copy_nonoverlapping(buf[adj_ix..].as_ptr(),v[USIZE_LEN-nbbytes..].as_mut_ptr(),nbbytes);
    debug!("DEBUG_aft {:?} !!!",v);
    if cfg!(target_endian = "little") {
      usize::from_be(mem::transmute(v))
    } else {
      mem::transmute(v)
    }
  } else {
    // size to big for usize TODO maybe change xtendsize to bigint
    // TODO change to error at least + half size lost here
    0
  }
  })
}

/// xtendsize with length control
#[inline]
pub fn xtendsizeread_foralloc<R : Read>(r : &mut R, nbbyte : usize) -> StdResult<usize,Error> {
  let size = try!(xtendsizeread(r, nbbyte));
  if size < MAX_ALLOC_SIZE {
    Ok(size)
  } else {
    Err(Error(format!("Trying to load allocate a bigger buffer than allowed {:?}", size), ErrorKind::OversizedAllocate, None))
  }
}

// get nbbyte for a value
// TODO precalc iteration in table
// TODO test for i = uss
fn calcnbbyte(val : usize) -> usize {
  let mut res = 0;
  let uss = USIZE_LEN;
  for i in 0 .. uss {
    if val < (usize::pow(2,(i*8) as u32) - 1)/2 {
      res = i;
      break;
    }
  };
  res
}

#[test]
fn test_xtendsize () {
  let evec : Vec<u8> = Vec::new();
  assert_eq!(xtendsize(0,0),evec);
  //assert_eq!(xtendsize(127,1),vec![127]);
  assert_eq!(xtendsize(0,1),vec![0x0000]);
  assert_eq!(xtendsize(127,1),vec![0x7f]);
  assert_eq!(xtendsize(128,1),vec![129,0,128]);
  //assert_eq!(xtendsize(128,1),vec![0x81,0x80,0]);
  assert_eq!(xtendsize(357,2),vec![1,101]);
  //assert_eq!(xtendsize(357,2),vec![0x65,0x01]);
  assert_eq!(xtendsize(357,1),vec![129,1,101]);
  //assert_eq!(xtendsize(357,1),vec![0x81,0x65,0x01]);
  assert_eq!(xtendsize(357000,1),vec![130,5,114,136]);
  //assert_eq!(xtendsize(357000,1),vec![0x82,0x88,0x72,0x05]);
}

#[test]
fn test_xtendsizedec () {
  assert_eq!(xtendsizedec(&[1,2,3,4,4],&mut 3,0),0);
  assert_eq!(xtendsizedec(&[1,2,3,0,4],&mut 3,1),0);
  assert_eq!(xtendsizedec(&[1,2,127,0,4],&mut 2,1),127);
  assert_eq!(xtendsizedec(&[1,2,129,0,128],&mut 2,1),128);
  assert_eq!(xtendsizedec(&[1,2,1,101,4],&mut 2,2),357);
  assert_eq!(xtendsizedec(&[1,2,129,1,101],&mut 2,1),357);
  assert_eq!(xtendsizedec(&[1,2,130,5,114,136],&mut 2,1),357000);
  // overflow is same as 0 (bad)
  assert_eq!(xtendsizedec(&[1,2,130,136,114],&mut 2,1),0);
}

#[test]
fn test_xtendsizeread () {
  assert_eq!(xtendsizeread(&mut Cursor::new(&[4,4][..]),0).unwrap(),0);
  assert_eq!(xtendsizeread(&mut Cursor::new(&[0,4][..]),1).unwrap(),0);
  assert_eq!(xtendsizeread(&mut Cursor::new(&[127,0,4][..]),1).unwrap(),127);
  assert_eq!(xtendsizeread(&mut Cursor::new(&[129,0,128][..]),1).unwrap(),128);
  assert_eq!(xtendsizeread(&mut Cursor::new(&[1,101,4][..]),2).unwrap(),357);
  assert_eq!(xtendsizeread(&mut Cursor::new(&[129,1,101][..]),1).unwrap(),357);
  assert_eq!(xtendsizeread(&mut Cursor::new(&[130,5,114,136][..]),1).unwrap(),357000);
  // overflow is same as 0 (bad)
  assert_eq!(xtendsizeread(&mut Cursor::new(&[130,136,114][..]),1).unwrap(),0);
}



#[test]
fn test_readwriteid () {
  let id_1 : Vec<u8> = vec!(1,2,3,4,5);
  let id_2 : Vec<u8> = vec!(11,12,13);
  let mut encid = Vec::new();
  push_id(&mut encid, &id_1);
  push_id(&mut encid, &id_2);
  let mut ix = 0;
  let nid_1 = read_id(&encid,&mut ix);
  let nid_2 = read_id(&encid,&mut ix);
  assert_eq!(id_1,nid_1);
  assert_eq!(id_2,nid_2);
}

#[inline]
pub fn push_id(res : &mut Vec<u8>, content : &[u8]) {
    let tmplen = content.len();
    // TODO switch to 2 byte?? (see standard evo)
    res.append(&mut xtendsize(tmplen,ID_LENGTH));
    res.append(&mut content.to_vec());
}

#[inline]
/// The function update index value
pub fn read_id<'a> (bytes : &'a[u8], ix : &mut usize) -> &'a[u8] {
  let s = xtendsizedec(bytes, ix, ID_LENGTH);
  read_len(bytes,ix,s)
}
#[inline]
/// The function update index value
pub fn read_len<'a> (bytes : &'a[u8], ix : &mut usize, s : usize) -> &'a[u8] {
  let res = if *ix + s <= bytes.len() {
    &bytes[*ix .. *ix + s]
  } else {
    &bytes[0 .. 0]
  };
  *ix = *ix + s;
  res
}



#[derive(Debug)]
pub enum ErrorKind {
  OversizedAllocate,
  DecodingError,
  UnexpectedStriple,
  KindImplementationNotFound,
  MissingFile,
  MissingIx,
  IOError,
  VarError,
  FromOption,
}

// feature related implementation of serialize (using standard ser meth of striple) : to avoid
// redundant def (type alias...).


#[derive(Debug,Clone,PartialEq,Eq)]
/// Utility kind (mostly when deserializing), to get invalid striple (striple without a kind)
pub struct NoKind;
#[derive(Debug,Clone)]
pub struct NoIDDer;
#[derive(Debug,Clone)]
pub struct NoSigCh;

impl PublicScheme for NoSigCh {}
impl StripleKind for NoKind {
  type D = NoIDDer;
  type S = NoSigCh;
  #[inline]
  fn get_algo_key() -> &'static [u8] {
    NOKEY
  }
}
impl IDDerivation for NoIDDer {
  const EXPECTED_SIZE : Option<usize> = Some(0);
  fn derive_id(_ : &[u8]) -> Result<Vec<u8>> {
    Err(Error("NoDerivation".to_string(), ErrorKind::KindImplementationNotFound, None))
  }
  fn check_id_derivation(_ : &[u8], _ : &[u8]) -> Result<bool> {
    Err(Error("NoDerivation".to_string(), ErrorKind::KindImplementationNotFound, None))
  }
}
impl SignatureScheme for NoSigCh {
  fn sign_content(_ : &[u8], _ : &mut Read) -> Result<Vec<u8>> {
    Err(Error("NoSign".to_string(), ErrorKind::KindImplementationNotFound, None))
  }
  fn check_content(_ : &[u8],_ : &mut Read,_ : &[u8]) -> Result<bool> {
    Err(Error("NoSign".to_string(), ErrorKind::KindImplementationNotFound, None))
  }
  fn new_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
    Err(Error("NoSign".to_string(), ErrorKind::KindImplementationNotFound, None))
  }
}

#[inline]
/// NoKind striple could be set a kind (unsafe cast but kind is phantom data)
pub fn as_kind<'a, SK : StripleKind> (nk : &'a Striple<NoKind>) -> &'a Striple<SK> {
  unsafe {
    let ptr = nk as *const Striple<NoKind>;
    let sptr : *const Striple<SK> = mem::transmute(ptr);
    &(*sptr)
  }
}
#[inline]
/// NoKind striple could be set a kind (unsafe cast but kind is phantom data)
pub fn mut_as_kind<'a,  SK : StripleKind> (nk : &'a mut Striple<NoKind>) -> &'a mut Striple<SK> {
  unsafe {
    let ptr = nk as *mut Striple<NoKind>;
    let sptr : *mut Striple<SK> = mem::transmute(ptr);
    &mut(*sptr)
  }
}

#[inline]
/// NoKind striple could be set a kind (unsafe cast but kind is phantom data)
pub fn copy_as_kind< SK : StripleKind> (nk : &Striple<NoKind>) -> Striple<SK> {
  unsafe {
    mem::transmute_copy(nk)
  }

}
#[inline]
/// NoKind striple could be set a kind (unsafe cast but kind is phantom data)
pub fn ref_as_kind<'a, SK : StripleKind> (nk : &'a StripleRef<'a,NoKind>) -> &'a StripleRef<'a,SK> {
  unsafe {
    let ptr = nk as *const StripleRef<'a,NoKind>;
    let sptr : *const StripleRef<'a,SK> = mem::transmute(ptr);
    &(*sptr)
  }
}
#[inline]
/// NoKind striple could be set a kind (unsafe cast but kind is phantom data)
pub fn ref_mut_as_kind<'a,  SK : StripleKind> (nk : &'a mut StripleRef<'a, NoKind>) -> &'a mut StripleRef<'a,SK> {
  unsafe {
    let ptr = nk as *mut StripleRef<'a,NoKind>;
    let sptr : *mut StripleRef<'a,SK> = mem::transmute(ptr);
    &mut(*sptr)
  }
}

#[inline]
/// NoKind striple could be set a kind (unsafe cast but kind is phantom data)
pub fn ref_copy_as_kind<'a, SK : StripleKind> (nk : &StripleRef<'a,NoKind>) -> StripleRef<'a,SK> {
  unsafe {
    mem::transmute_copy(nk)
  }
}



#[cfg(test)]
pub mod test {
  extern crate rand;
  use std::fs;
  use std::path::PathBuf;
  use std::fs::File;
  use std::io::Write;
  use std::io::Read;
  use std::io::{Seek,SeekFrom};
  use std::io::Cursor;
  use self::rand::Rng;
  use std::marker::PhantomData;
  use crate::striple::Striple;
  use crate::striple::Result;
  use crate::striple::striple_dser_with_def;
  use crate::striple::striple_copy_dser;
  use crate::striple::StripleRef;
  use crate::striple::StripleIf;
  use crate::striple::StripleFieldsIf;
  use crate::striple::AsStriple;
  use crate::striple::StripleKind;
  use crate::striple::NoKind;
  use crate::striple::BCont;
  use crate::striple::Error;
  use crate::striple::as_kind;
  use crate::striple::mut_as_kind;
  use crate::striple::ref_builder_id_copy;
  use crate::striple::ref_builder_id;
  use crate::striple::copy_builder_id;
  use crate::striple::IDDerivation;
  use crate::striple::SignatureScheme;

  static TESTKIND1KEY : &'static [u8] = &[1,1,1];
  // static TESTKIND2KEY : &'static [u8] = &[];

  #[derive(Debug,Clone)]
  pub struct TestKind1;
  #[derive(Debug,Clone)]
  pub struct TestKeyDer1;
  #[derive(Debug,Clone)]
  pub struct TestSigSchem1;
  impl StripleKind for TestKind1 {
    //type D : IDDerivation;
    type D = TestKeyDer1;
    //type S : SignatureScheme;
    type S = TestSigSchem1;
    #[inline]
    fn get_algo_key() -> &'static [u8] {
      TESTKIND1KEY
    }
  }
  impl IDDerivation for TestKeyDer1 {
    const EXPECTED_SIZE : Option<usize> = None;
    fn derive_id(sig : &[u8]) -> Result<Vec<u8>> {
      // simply use signature as key
      Ok(sig.to_vec())
    }
    fn check_id_derivation(sig : &[u8], id : &[u8]) -> Result<bool> {
      Ok(sig == id) 
    }

  }
  impl SignatureScheme for TestSigSchem1 {
    fn sign_content(pri : &[u8], _ : &mut Read) -> Result<Vec<u8>> {
      // Dummy : just use pri
      Ok(pri.to_vec())
    }
    fn check_content(publ : &[u8], _ : &mut Read, sig : &[u8]) -> Result<bool> {
      // Dummy
      debug!("checkcontet :pub {:?}, sig {:?}", publ, sig);
      Ok(publ != sig)
    }
    fn new_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
      // Dummy pri is same as pub
      let mut tmp = [0u8; 4];
      rand::thread_rng().fill(&mut tmp[..]);
      let rand = tmp.to_vec();
      Ok((rand.clone(), rand))
    }
  }

  pub fn sample_striple1() -> Striple<NoKind> {
    let common_id = random_bytes(4);
    let common_id_2 = random_bytes(2);
    Striple {
        contentenc : vec!(),
        id : common_id.clone(),
        from : common_id_2.clone(),
        sig : common_id.clone(),
        about : vec!(),
        key : vec!(0),
        contentids : vec!(vec!(8,9)),
        content : None,

        phtype : PhantomData,
    }
  }
  pub fn sample_striple2() -> Striple<NoKind> {
    //let common_id = random_bytes(4);
    let common_id_2 = random_bytes(2);
    Striple {
        contentenc : vec!(),
        id : common_id_2.clone(),
        from : vec!(4,4,4,4),
        sig : common_id_2.clone(),
        about : vec!(),
        key : vec!(0),
        contentids : vec!(),
        content : Some(BCont::OwnedBytes(vec!(33,45,123))),

        phtype : PhantomData,

    }
  }
  // like sample 2 but with long content (>512)
  pub fn sample_striple3() -> Striple<NoKind> {
    //let common_id = random_bytes(4);
    let common_id_2 = random_bytes(2);
    let longcontent = random_bytes(600);
    Striple {
        contentenc : vec!(),
        id : common_id_2.clone(),
        from : vec!(4,4,4,4),
        sig : common_id_2.clone(),
        about : vec!(),
        key : vec!(0),
        contentids : vec!(),
        content : Some(BCont::OwnedBytes(longcontent)),

        phtype : PhantomData,

    }
  }
  // like sample 2 but with attached file
  // Warning this is pretty unsafe
  pub fn sample_striple4() -> Striple<NoKind> {
//    let common_id = random_bytes(40);
    let common_id_2 = random_bytes(20);
    let longcontent = random_bytes(600);
    let (path,size) = { 
      //let tmpdir = env::temp_dir();
      let tmpdir = PathBuf::new(); // TODO tmpdir when relative path ok??
      let mytmpdirpath = tmpdir.join("./test_rust_striple_sample");
      fs::create_dir_all(&mytmpdirpath).unwrap();
      let fpath = mytmpdirpath.join("striple4.file");
      debug!("Creating tmp file : {:?}",fpath);
      let mut f = File::create(&fpath).unwrap();
      f.write_all(&longcontent[..]).unwrap();
      let s = f.metadata().unwrap().len() as usize;
      assert!(s == longcontent.len());
      (fpath,s)
    };
    Striple {
        contentenc : vec!(),
        id : common_id_2.clone(),
        from : vec!(4,4,4,4),
        sig : common_id_2.clone(),
        about : vec!(),
        key : vec!(0),
        contentids : vec!(),
        content : Some(BCont::LocalPath(path,size)),

        phtype : PhantomData,

    }
  }




  #[test]
  fn test_striple_enc_dec () { // TODO !!! same test with file usage (due to long content and actual file)
    let ori_1tmp = sample_striple1();
    let mut ori_2tmp = sample_striple2();
    let ori_1 : &Striple<TestKind1> = as_kind(&ori_1tmp);
    let ori_2 : &mut Striple<TestKind1> = mut_as_kind(&mut ori_2tmp);
    ori_2.id = ori_1.from.clone();
    ori_2.sig = ori_1.from.clone();
    let ori_ref_1 = ori_1.as_striple();
    // No file
    let (encori_1, oc) = ori_1.striple_ser_with_def().unwrap();
    assert!(oc.is_none());
    debug!("Encoded : \n{:?}",encori_1);
    let typednone : Option<&Striple<TestKind1>> = Some(&ori_2);
    let dec1 : Striple<TestKind1> = striple_dser_with_def(&encori_1, None, typednone,ref_builder_id_copy).unwrap();
    assert_eq!(compare_striple(&ori_1,&dec1), true);
    let (encori_ref_1,oc2) = ori_ref_1.striple_ser_with_def().unwrap();
    assert!(oc2.is_none());
    assert_eq!(encori_1,encori_ref_1);
    let redec1 : Striple<TestKind1> = striple_copy_dser(&encori_1, None, typednone,copy_builder_id).unwrap();
    assert_eq!(compare_striple(&ori_1,&redec1), true);
    let redec1bis : StripleRef<TestKind1> = striple_dser_with_def(&encori_1, None, typednone,ref_builder_id).unwrap();
    let (encori_ref_1_bis,oc3) = redec1bis.striple_ser_with_def().unwrap();
    assert!(oc3.is_none());
    assert_eq!(encori_1,encori_ref_1_bis);
  }

  /// test set to run on any striple kind
  pub fn test_striple_kind<T : StripleKind> (sig_length : usize, public : bool) {
    unique_key_der::<T::D> (sig_length);
    if public {
      pub_sign::<T::S> ();
    } else {
      pri_sign::<T::S> ();
    };
  }
  
  fn unique_key_der<D : IDDerivation> (sig_length : usize) {
    // TODO rewrite as quick check !!! and key as random long enough for scheme + sig 1 same
    // length, 2 and 3 plus some bytes
    assert!(sig_length != 0);
    let sig_1 = &random_bytes(sig_length)[..];
    let sig_2 = &random_bytes(sig_length)[..];
    let sig_3 = &random_bytes(sig_length)[..];
    let sig_null = &vec!()[..];
    if sig_1 == sig_2 || sig_1 == sig_3 {
      return unique_key_der::<D>(sig_length)
    }

    let key_1 = D::derive_id (sig_1).unwrap();
    let key_2 = D::derive_id (sig_2).unwrap();
    let key_3 = D::derive_id (sig_3).unwrap();
    let key_null = D::derive_id (sig_null).unwrap();

    assert!((sig_1 == sig_2) || (key_1 != key_2));
    assert!((sig_2 == sig_2) || (key_2 != key_2));
    assert!((sig_3 == sig_2) || (key_3 != key_2));

    // generate signature of rendom right length and uncoment
    assert!(sig_1.len() >= key_1.len());
    // case with small sig
    assert!(sig_null.len() == key_null.len());

    assert!(D::check_id_derivation(sig_3, &key_3).unwrap());
    // TODO something with this case
    // assert!(!D::check_id_derivation(sig_null, &key_null));

  }

  fn pub_sign<S : SignatureScheme> () {
    let kp1 = S::new_keypair().unwrap();
    let kp2 = S::new_keypair().unwrap();
    let mut cont_1 = Cursor::new(vec!(1,2,3,4));
    let mut cont_2 = Cursor::new(vec!());
    let sig_1 = S::sign_content(&kp1.1, &mut cont_1).unwrap();
    cont_1.seek(SeekFrom::Start(0)).unwrap();
    let sig_2 = S::sign_content(&kp2.1, &mut cont_2).unwrap();
    cont_2.seek(SeekFrom::Start(0)).unwrap();

    // public of keypair unique (because include in content)
    assert!(kp1.0 != kp2.0);
    // public is same as private
    assert!(kp1.0 == kp1.1);
    assert!(kp2.0 == kp2.1);
 
    // check content does depend on from keypair (from must be added to content if hashing scheme)
    assert!(S::check_content(&kp1.0, &mut cont_1, &sig_1).unwrap());
    cont_1.seek(SeekFrom::Start(0)).unwrap();
    assert!(!S::check_content(&vec!(1,2,3,4), &mut cont_1, &sig_1).unwrap());
    cont_1.seek(SeekFrom::Start(0)).unwrap();
    // and sig validate content
    assert!(!S::check_content(&kp2.0, &mut cont_2, &vec!()).unwrap());
    cont_2.seek(SeekFrom::Start(0)).unwrap();

    // signing do not have salt (uniqueness by keypair pub in content).
    assert!(S::sign_content(&kp1.1, &mut cont_1).unwrap() == sig_1);
    cont_1.seek(SeekFrom::Start(0)).unwrap();
    assert!(S::sign_content(&kp2.1, &mut cont_2).unwrap() == sig_2);
    cont_1.seek(SeekFrom::Start(0)).unwrap();

  }

  fn pri_sign<S : SignatureScheme> () {
    let kp1 = S::new_keypair().unwrap();
    let kp2 = S::new_keypair().unwrap();
    let mut cont_1 = Cursor::new(vec!(1,2,3,4));
    let mut cont_2 = Cursor::new(vec!(1,2,3,4,5));
    let sig_1 = S::sign_content(&kp1.1, &mut cont_1).unwrap();
    cont_1.seek(SeekFrom::Start(0)).unwrap();
    let sig_2 = S::sign_content(&kp2.1, &mut cont_2).unwrap();
    cont_2.seek(SeekFrom::Start(0)).unwrap();

    // keypair unique
    assert!(kp1.0 != kp2.0);
    assert!(kp1.1 != kp2.1);
    // and asym
    assert!(kp1.0 != kp1.1);

    let evec : Vec<u8> = Vec::new();
    // signature never empty
    assert!(S::sign_content(&kp1.1[..], &mut cont_1).unwrap() != &evec[..]);
    cont_1.seek(SeekFrom::Start(0)).unwrap();
    assert!(S::sign_content(&kp2.1[..], &mut cont_1).unwrap() != &evec[..]);
    cont_1.seek(SeekFrom::Start(0)).unwrap();

    // signing must have salt : no since different public key in content
    // assert!(S::sign_content(&kp1.1[..], cont_1) != sig_1);
    // assert!(S::sign_content(&kp2.1[..], cont_2) != sig_2);

    // check content only when finely signed
    assert!(!S::check_content(&kp1.0[..], &mut cont_1, &vec!(4)[..]).unwrap());
    cont_1.seek(SeekFrom::Start(0)).unwrap();
    assert!(S::check_content(&kp1.0[..], &mut cont_1, &sig_1[..]).unwrap());
    cont_1.seek(SeekFrom::Start(0)).unwrap();
    assert!(S::check_content(&kp2.0[..], &mut cont_2, &sig_2[..]).unwrap());
    cont_2.seek(SeekFrom::Start(0)).unwrap();
  }

  // test for chaning integrity, construct a K1 root then K1 and K2 son then for K2 K1 and K2 son.
  // With test for altering integrity (mut striple).
  pub fn chaining_test<K1 : StripleKind, K2 : StripleKind> () {
    let contentenc = random_bytes(99);
    let ownedroot : (Striple<K1>, Vec<u8>) = Striple::new_self(
      contentenc.clone(),
      None,
      Vec::new(),
      Some(BCont::OwnedBytes(random_bytes(333))),
    ).unwrap();
    let root = ownedroot.0;
    // check algo is same as K1 get_algo
    assert_eq!(*root.get_algo_key(), *K1::get_algo_key());
    // check about and from are same as id
    assert_eq!(root.get_id(),&root.from[..]);
    assert!(*root.get_id() == *root.get_about());

    // check signed by itself
    assert!(root.check(&root).unwrap());
    
     let ownedson1 : (Striple<K1>, Vec<u8>) = Striple::new(
      contentenc.clone(),
      &(&root,&ownedroot.1[..]),
      // random about : no logic here because about is not validated
      Some(random_bytes(9)),
      // random contentids
      vec!(vec!(1),vec!(3,4,4)),
      None,
    ).unwrap();
    let son1 = ownedson1.0;

    assert!(son1.check(&root).unwrap());
    assert!(!son1.check(&son1).unwrap());

    let ownedson2 : (Striple<K2>, Vec<u8>) = Striple::new(
      contentenc.clone(),
      &(&root,&ownedroot.1[..]),
      // random about : no logic here because about is not validated
      Some(random_bytes(7)),
      // random contentids
      vec!(vec!(5,1),vec!(3,4,4)),
      Some(BCont::OwnedBytes(vec!(5,2))),
      
    ).unwrap();
    let son2 = ownedson2.0;
 
    assert!(son2.check(&root).unwrap());
    assert!(!son2.check(&son1).unwrap());
    assert!(!son2.check(&son2).unwrap());



    let ownedson21 : (Striple<K1>, Vec<u8>) = Striple::new(
      contentenc.clone(),
      &(&son2,&ownedson2.1[..]),
      // random about : no logic here because about is not validated
      Some(vec!(4,4,3,4)),
      // random contentids
      vec!(vec!(5,1),vec!(3,4,4)),
      Some(BCont::OwnedBytes(vec!(5,2))),
    ).unwrap();
    let son21 = ownedson21.0;
 
    assert!(son21.check(&son2).unwrap());
    assert!(!son21.check(&root).unwrap());

    let ownedson22 : (Striple<K2>, Vec<u8>) = Striple::new(
      contentenc.clone(),
      &(&son2,&ownedson2.1[..]),
      // random about : no logic here because about is not validated
      Some(vec!(4,4,3,4)),
      // random contentids
      vec!(vec!(5,1),vec!(3,4,4)),
      Some(BCont::OwnedBytes(vec!(5,2))),
    ).unwrap();
    let son22 = ownedson22.0;

    assert!(son22.check(&son2).unwrap());
    assert!(!son22.check(&root).unwrap());

    let ownedson22bis : (Striple<K2>, Vec<u8>) = Striple::new(
      contentenc.clone(),
      &(&son2,&ownedson2.1[..]),
      // random about : no logic here because about is not validated
      Some(vec!(4,4,3,4)),
      // random contentids
      vec!(vec!(5,1),vec!(3,4,4)),
      Some(BCont::OwnedBytes(vec!(5,2))),
    ).unwrap();
    let son22bis = ownedson22bis.0;

    // unicity of striple
    assert!(!compare_striple(&son22,&son22bis));
    let unknown_vec = random_bytes(6);
    // check changing `from` break previous checking (even if same from in check)
    let mut tmp2 = son22.clone();
    assert!(tmp2.check(&son2).unwrap());
    let mut tmp1 = son1.clone();
    assert!(tmp1.check(&root).unwrap());
    tmp2.from = unknown_vec.clone();
    assert!(!tmp2.check(&son2).unwrap());
    tmp1.from = unknown_vec.clone();
    assert!(!tmp1.check(&root).unwrap());
    
    // check changing `about` break previous checking...
    tmp2 = son22.clone();
    tmp1 = son1.clone();
    tmp2.about = unknown_vec.clone();
    assert!(!tmp2.check(&son2).unwrap());
    tmp1.about = unknown_vec.clone();
    assert!(!tmp1.check(&root).unwrap());
    // check changing `content` break previous checking...
    tmp2 = son22.clone();
    tmp1 = son1.clone();
    tmp2.content = Some(BCont::OwnedBytes(unknown_vec.clone()));
    assert!(!tmp2.check(&son2).unwrap());
    tmp1.content = Some(BCont::OwnedBytes(unknown_vec.clone()));
    assert!(!tmp1.check(&root).unwrap());
    // check changing `contentid` break previous checking...
    tmp2 = son22.clone();
    tmp1 = son1.clone();
    tmp2.contentids = vec!(unknown_vec.clone());
    assert!(!tmp2.check(&son2).unwrap());
    tmp1.contentids = vec!(unknown_vec.clone());
    assert!(!tmp1.check(&root).unwrap());
    // check changing `key` break previous checking...
    tmp2 = son22.clone();
    tmp1 = son1.clone();
    tmp2.key = unknown_vec.clone();
    assert!(!tmp2.check(&son2).unwrap());
    tmp1.key = unknown_vec.clone();
    assert!(!tmp1.check(&root).unwrap());
    // check changing `sig` break previous checking...
    tmp2 = son22.clone();
    tmp1 = son1.clone();
    tmp2.sig = unknown_vec.clone();
    assert!(!tmp2.check(&son2).unwrap());
    tmp1.sig = unknown_vec.clone();
    assert!(!tmp1.check(&root).unwrap());
    // check changing `id` break previous checking...
    tmp2 = son22.clone();
    tmp1 = son1.clone();
    tmp2.id = unknown_vec.clone();
    assert!(!tmp2.check(&son2).unwrap());
    tmp1.id = unknown_vec.clone();
    assert!(!tmp1.check(&root).unwrap());
    // check changing `encodingid` is impactless previous checking... (content encoding is not in
    // scheme and purely meta)
    tmp2 = son22.clone();
    tmp1 = son1.clone();
    tmp2.contentenc = unknown_vec.clone();
    assert!(tmp2.check(&son2).unwrap());
    tmp1.contentenc = unknown_vec.clone();
    assert!(tmp1.check(&root).unwrap());

  }

  // utility
  pub fn random_bytes(size : usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut bytes = vec![0; size];
    rng.fill(&mut bytes[..]);
    bytes
  }

  /// comparison of well formed striple should only use key
  /// this is more of an utility for debugging and testing
  pub fn compare_striple<K1 : StripleKind, K2 : StripleKind> (st1 : &Striple<K1>, st2 : &Striple<K2>) -> bool {
    let cmpcont = if st1.content.is_some() && st2.content.is_some() {
      compare_bcont(st1.content.as_ref().unwrap(),st2.content.as_ref().unwrap()).unwrap_or(false)
    } else {
    println!("st1 : {:?}, st2 : {:?}", st1.content, st2.content);
      st1.content.is_none() && st2.content.is_none()
    };
    println!("CMPCONT {:?}",cmpcont);
    cmpcont
    && <K1 as StripleKind>::get_algo_key() == <K2 as StripleKind>::get_algo_key()
    && st1.contentenc == st2.contentenc
    && st1.id == st2.id
    && st1.from == st2.from
    && (
      st1.sig == st2.sig ||
      (st1.sig.len()==0 && st1.id == st2.sig) ||
      (st2.sig.len()==0 && st2.id == st1.sig) 
      )
    && (
      st1.about == st2.about ||
      (st1.about.len() == 0 && st1.id == st2.about) ||
      (st2.about.len() == 0 && st2.id == st1.about)
      )
    && st1.key == st2.key
    && st1.contentids == st2.contentids
  }


  pub fn compare_bcont (b1 : &BCont, b2 : &BCont) -> Result<bool> {
    let mut r1 = try!(b1.get_readable());
    let mut r2 = try!(b2.get_readable());
    let mut buff1 = [0;256];
    let mut buff2 = [0;256];
    let mut result = true;
    let tr1 = r1.trait_read();
    let tr2 = r2.trait_read();
    loop {
      let i1 = try!(tr1.read(&mut buff1));
      let i2 = try!(tr2.read(&mut buff2));
      if i1 != i2 || &buff1[0..i1] != &buff2[0..i2] {
        result  = false;
        break
      };
      if i1 == 0 && i2 == 0 {
        break
      };
    };
    return Ok(result);
  }

}

pub struct StripleDisp<'a, S : 'a + StripleIf>(pub &'a S);
pub struct OwnedStripleDisp<'a, S : 'a + OwnedStripleIf>(pub &'a S);
// TODO mark as rust unsafe?? (more lib unsafe)
pub struct UnsafeOwnedStripleDisp<'a, S : 'a + OwnedStripleIf>(pub &'a S);




#[cfg(feature="serialize")]
impl<'a,  S : StripleIf> Display for StripleDisp<'a, S> {
  fn fmt(&self, ftr : &mut Formatter) -> FmtResult {
    ftr.debug_struct("")
    .field("id", &base64::encode_config(self.0.get_id(),BASE64CONF))
    .field("from", &base64::encode_config(&self.0.get_from(),BASE64CONF))
    .field("about", &base64::encode_config(&self.0.get_about(),BASE64CONF))
    .field("content_ids", &{
      let mut catids = "[".to_string();
      for id in self.0.get_content_ids().iter() {
        catids = catids + &base64::encode_config(id,BASE64CONF)[..] + ",";
      }
      catids + "]"
      }
    )
    .field("content", &base64::encode_config(&truncated_content(self.0.get_content())[..],BASE64CONF))
    .field("content_string", &String::from_utf8(truncated_content(self.0.get_content()).to_vec()))
    .field("key", &base64::encode_config(self.0.get_key(),BASE64CONF))
    .field("sig", &base64::encode_config(self.0.get_sig(),BASE64CONF))
    .field("kind ", &base64::encode_config(&self.0.get_algo_key(),BASE64CONF))
    .finish()

  }
}

#[inline]
fn truncated_content<'a> ( ocont : Option<&BCont<'a>>)-> Vec<u8> {
  ocont.map_or(vec!(),|cont|{
    match cont.get_readable() {
      Ok(BContRead::Bytes(mut b)) => {
        let r = &mut [0; 300];
        b.read(r).map(|i| r[0..i].to_vec())
          .unwrap_or("error read content".as_bytes().to_vec())
      },
      Ok(BContRead::LocalPath(mut p)) => {
        let r = &mut [0; 300];
        p.read(r).map(|i| r[0..i].to_vec())
          .unwrap_or("error read content".as_bytes().to_vec())
      },
      Err(_) => {
        "error read content".as_bytes().to_vec()
      },
    }
  })
}

#[cfg(feature="serialize")]
impl<'a, S : OwnedStripleIf> Display  for OwnedStripleDisp<'a,S> {
  fn fmt(&self, ftr : &mut Formatter) -> FmtResult {
    ftr.debug_struct("")
    .field("striple", &format!("{}",StripleDisp(self.0)))
    .field("PrivateKey", &"********")
    .finish()
 
  }
}
#[cfg(feature="serialize")]
impl<'a, S : OwnedStripleIf> Display  for UnsafeOwnedStripleDisp<'a,S> {
  fn fmt(&self, ftr : &mut Formatter) -> FmtResult {
    ftr.debug_struct("")
    .field("striple", &format!("{}",StripleDisp(self.0)))
    .field("PrivateKey", &base64::encode_config(self.0.private_key_ref(),BASE64CONF))
    .finish()
  }
}

/*#[cfg(feature="serialize")]
pub static BASE64CONF : base64::Config = base64::Config {
    char_set : base64::CharacterSet::Standard,
    strip_whitespace : false,
    pad : true,
    line_wrap : base64::LineWrap::NoWrap,
};*/

