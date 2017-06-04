

use std::error::Error as ErrorTrait;
use std::io::Error as IOError;
use std::env::VarError;
use std::fmt::{Display,Debug,Formatter};
use std::fmt::Result as FmtResult;
use std::marker::PhantomData;
use num;
use std::mem;
use std::ptr::copy_nonoverlapping;
use std::io::{Read};
use std::io::Result as IOResult;
use std::result::Result as StdResult;
use std::io::Cursor;
use std::fs::File;
use std::path::PathBuf;
use std::fs::metadata;
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
use rustc_serialize::{Encoder,Encodable,Decoder,Decodable};
#[cfg(feature="serialize")]
use rustc_serialize::base64::ToBase64;
#[cfg(feature="serialize")]
use rustc_serialize::base64;

 
pub type Result<R> = StdResult<R,Error>;
/// Striple could be a standard struct, or references to contents from others struct
/// Trait should not be implemented for other struct (or conformance with test case needed).
/// Other struct should implement AsStriple (probably to stripleRef).
/// TODO word on enum to serialize and manage parametric types
pub trait StripleIf : Debug {

  fn check_content(&self, cont : &mut Read, sig : &[u8]) -> bool;
  fn sign_content(&self, _ : &[u8], _ : &mut Read) -> Result<Vec<u8>>;
  fn derive_id(&self, sig : &[u8]) -> Vec<u8>;
  fn check_id_derivation(&self, sig : &[u8], id : &[u8]) -> bool;
  /// check striple integrity (signature and key)
  fn check (&self, from : &StripleIf) -> bool {
    self.check_id(from) && self.check_sig(from)
  }


  /// check signature of striple
  fn check_sig (&self, from : &StripleIf) -> bool {
    match self.get_tosig() {
      Ok((v, oc)) => {
        let mut cv = Cursor::new(v);
        from.get_id() == self.get_from() && match oc {
          Some (bc) => {
            match bc.get_readable() {
              Ok(mut r) => from.check_content(&mut cv.chain(r.trait_read()), self.get_sig()),
              Err(_) => false,
            }
          },
          None => from.check_content(&mut cv, self.get_sig()),
        }
      },
      Err(_) => false,
    }
  }

  /// check key of striple
  fn check_id (&self, from : &StripleIf) -> bool {
    from.check_id_derivation(self.get_sig(), self.get_id())
  }

  /// get content enc value
  fn get_enc(&self) -> &[u8];

  /// get striple key value
  fn get_id(&self) -> &[u8];

  /// get striple key value
  fn get_from(&self) -> &[u8];

  /// get striple key value
  fn get_about(&self) -> &[u8];

  /// get content value
  fn get_content<'a>(&'a self) -> &'a Option<BCont<'a>>;

  /// get content ids value
  fn get_content_ids(&self) -> Vec<&[u8]>;

  /// get striple key value
  fn get_key(&self) -> &[u8];

  /// get key of striple defining algo scheme
  fn get_algo_key(&self) -> &'static [u8];

  /// get striple signature value
  fn get_sig(&self) -> &[u8];

  // TODO test where decode from ser to striple, then check getbytes is allways the same
  // (sig to) 
  /// get bytes which must be signed
  /// TODO plus optional File or return Chain<Read> : that is better as we already copy mem -> use
  /// array of bcontread
  fn get_tosig<'a>(&'a self) -> Result<(Vec<u8>,Option<&'a BCont<'a>>)>;

  /// encode to bytes, but only striple content : Vec<u8> only include striple info.
  /// Might do others operation (like moving a file in a right container.
  /// If BCont is a Path, the path is written with a 2byte xtendsize before
  /// TODO ser with filename
  fn striple_ser<'a> (&'a self) -> Result<(Vec<u8>,Option<&'a BCont<'a>>)>;

}

/// Content wrapper over bytes with Read interface
#[derive(Clone,Debug)]
pub enum BCont<'a> {
  OwnedBytes(Vec<u8>),
  NotOwnedBytes(&'a[u8]),
  LocalPath(PathBuf),
}
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
      &BCont::LocalPath(ref p) => from_error(File::open(p).map(|f|BContRead::LocalPath(f))),
    }
  }
  /// check if for serialization (and also checking) we copy the content through `get_bytes` copy or include bcont
  /// Furtremore return length (included in both cases)
  #[inline]
  pub fn copy_ser(&'a self) -> Result<(bool, usize)> {
    match self {
      &BCont::OwnedBytes(ref b) => Ok((b.len() < CONTENT_LENGTH_COPYTRESHOLD, b.len())),
      &BCont::NotOwnedBytes(ref b) => Ok((b.len() < CONTENT_LENGTH_COPYTRESHOLD, b.len())),
      &BCont::LocalPath(ref p) => {
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
      &BCont::LocalPath(_) => {
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
      &BCont::LocalPath(ref p) => BCont::LocalPath(p.clone()),
    }
  }
  fn to_ref<'b>(&'b self) -> BCont<'b> {
    match self {
      &BCont::NotOwnedBytes(ref b) => BCont::NotOwnedBytes(b),
      &BCont::OwnedBytes(ref b) => BCont::NotOwnedBytes(&b[..]),
      &BCont::LocalPath(ref p) => BCont::LocalPath(p.clone()),
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
pub trait StripleKind : Debug + Clone {
  type D : IDDerivation;
  type S : SignatureScheme;

  /// get key to the corresponding algo combination striple
  fn get_algo_key() -> &'static [u8];

}

/// specifies the scheme is public
pub trait PublicScheme : SignatureScheme{}

/// build key from bytes (signature)
pub trait IDDerivation {
  /// parameter is signature
  fn derive_id(sig : &[u8]) -> Vec<u8>;
  /// first parameter is signature, second is key
  fn check_id_derivation(sig : &[u8], id : &[u8]) -> bool {
    &Self::derive_id(sig)[..] == id
  }
}

/// when signature is not to long we derive with identity
pub struct IdentityKD;

/// key is same as signature (case where signature does not need to be serialize) 
/// warning this is prone to creating big key in heterogenous network (size of sig depends on
/// parent striple).
impl IDDerivation for IdentityKD {
  /// id
  #[inline]
  fn derive_id(sig : &[u8]) -> Vec<u8> {
    sig.to_vec()
  }
  /// simply equality
  #[inline]
  fn check_id_derivation(sig : &[u8], id : &[u8]) -> bool {
    sig == id 
  }
}



/// signing and checking scheme
/// when implementing this trait the following properties are required :
/// - two subsequent call to signing shoud create two different signature (otherwhise striple with
/// same content will have the same key), or the key derivation key use in combination should be
/// random (for example in public).
/// - key verification must be invalid if signature change
pub trait SignatureScheme {

  /// first parameter is private key, second parameter is content
  fn sign_content(pri : &[u8], cont : &mut Read) -> Result<Vec<u8>>;

// TODO result in check (right now an error is seen as not checked)?
  /// first parameter is public key, second is content and third is signature
  fn check_content(publ : &[u8],cont : &mut Read, sig : &[u8]) -> bool;

  /// create keypair (first is public, second is private)
  fn new_keypair() -> (Vec<u8>, Vec<u8>);

}

pub trait OwnedStripleIf : StripleIf {

  /// owned striple has a private key, default implementation is inefficient
  fn private_key(&self) -> Vec<u8> {
    self.private_key_ref().to_vec()
  }

  fn private_key_ref(&self) -> &[u8];

  /// first parameter is private key, second parameter is content
  fn sign(&self, st : &StripleIf) -> Result<Vec<u8>> {
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

impl<'a, ST : StripleIf> AsStripleIf for (&'a ST, &'a [u8]) {
  #[inline]
  fn as_striple_if(&self) -> &StripleIf {
    self.0
  }
}

impl<'a, ST : StripleIf> AsStripleIf for (ST, Vec<u8>) {
  #[inline]
  fn as_striple_if(&self) -> &StripleIf {
    &self.0
  }
}

impl<ST : StripleIf> OwnedStripleIf for (ST, Vec<u8>) {

  #[inline]
  fn private_key (&self) -> Vec<u8> {
    self.1.clone()
  }

  #[inline]
  fn private_key_ref (&self) -> &[u8] {
    &self.1[..]
  }

}

impl<'b, ST : StripleIf> OwnedStripleIf for (&'b ST, &'b [u8]) {

  #[inline]
  fn private_key (&self) -> Vec<u8> {
    self.1.to_vec()
  }

  #[inline]
  fn private_key_ref (&self) -> &[u8] {
    self.1
  }

}


/// Type to use an striple as Public, allowing to sign/create striple from it without others info
/// (see Ownedstriple implementation). Usage with non public striple will result in error when
/// signing or worst when checking.
pub trait PubStriple : StripleIf{}

impl<K : StripleKind> PubStriple for Striple<K> where K::S : PublicScheme {}
impl<'a, K : StripleKind> PubStriple for StripleRef<'a,K> where K::S : PublicScheme {}
/*
/// Mark as public based on some asumption, it is the same as using `(&S,&[][..])`
#[derive(Debug)]
pub struct UnsafePubStriple<'a, S : StripleIf + 'a> (&'a S);

impl<'a, S : StripleIf> PubStriple for UnsafePubStriple<'a, S> {}
*/
/// public scheme uses same value for public and private key
impl<S : PubStriple> OwnedStripleIf for S {

  fn private_key (&self) -> Vec<u8> {
    self.get_key().to_vec()
  }

  fn private_key_ref (&self) -> &[u8] {
    self.get_key()
  }
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

// identic code for stripleref and striple   
macro_rules! ser_content(() => (
  #[inline]
  fn ser_tosig<'b> (&'b self, res : &mut Vec<u8>) -> Result<Option<&'b BCont<'b>>> {
    let mut tmplen;

    // never encode the same value for about and id
    if self.id != self.about {
      push_id(res, &self.about);
    } else {
      push_id(res, &[]);
    }

    tmplen = self.key.len();
    res.append(&mut xtendsize(tmplen,KEY_LENGTH));
    res.append(&mut self.key.to_vec());
    
    tmplen = self.contentids.len();
    res.append(&mut xtendsize(tmplen,CONTENTIDS_LENGTH));
    for cid in self.contentids.iter(){
      push_id(res, &cid)
    };
    let (con, ocon) = match self.content {
      Some(ref c) => {
        let (ser, l) = c.copy_ser()?;
        tmplen = l;
        if ser {
          let b = c.get_byte()?;
          (Some(b),None)
        } else {
          (None,self.content.as_ref())
        }
      },
      None => {
        tmplen = 0;
        (None,None)
      },
    };
    res.append(&mut xtendsize(tmplen,CONTENT_LENGTH));
    con.map(|c|res.append(&mut c.to_vec()));
    Ok(ocon)
  }
)
);


impl<T : StripleKind> Striple<T> {

  /// first step is creation of the key pair for this striple.
  /// then signature by `from` and id generation.
  /// When `from` is not specified we consider that we sign ourself with the new striple :
  /// the striple is initialized from itself (for example a master key).
  /// None for `about` is the same as using `from` id.
  /// Return the initialized striple and its private key.
  /// TODO return result (add sign error and bcont error)
  pub fn new (
    contentenc : Vec<u8>,
    from : Option<&OwnedStripleIf>,
    about: Option<Vec<u8>>,
    contentids : Vec<Vec<u8>>,
    content : Option<BCont<'static>>,
  ) -> Result<(Striple<T>,Vec<u8>)> {
    let keypair = T::S::new_keypair();
    let mut res = Striple {
        contentenc : contentenc,
        id : vec!(),
        from : vec!(),
        sig : vec!(),
        about : about.unwrap_or(vec!()),
        key : keypair.0,
        contentids : contentids,
        content : content,

        phtype : PhantomData,
    };

    let (sig,id) = match from {
      Some (st) => {
        let sig = try!(st.sign(&res));
        let id = st.derive_id(&sig);
        (sig, id)
      },
      None => {
        let (v, obc) = res.get_tosig()?;
        let mut cv = Cursor::new(v);
        let sig = match obc {
          Some (bc) => {
            let mut r = try!(bc.get_readable());
            let mut tos = cv.chain(r.trait_read());
            try!(T::S::sign_content(&keypair.1, &mut tos))
          },
          None => try!(T::S::sign_content(&keypair.1, &mut cv)),
        };
        let id = T::D::derive_id(&sig);
        (sig, id)
      },
    };
    res.sig = sig;
    res.id = id;

    match from {
      Some (st) => {
        res.from = st.get_id().to_vec();
      },
      None => {
        res.from = res.id.clone();
      },
    };

    Ok((res, keypair.1))
  }
  // utility to fact code
  ser_content!();
}

impl<'a, T : StripleKind> StripleRef<'a, T> {

  // utility to fact code
  ser_content!();
}


impl<T : StripleKind> StripleIf for Striple<T> {


  #[inline]
  fn get_algo_key(&self) -> &'static [u8]{
    T::get_algo_key()
  }
  #[inline]
  fn check_content(&self, cont : &mut Read, sig : &[u8]) -> bool {
    T::S::check_content(&self.key, cont, sig)
  }
  #[inline]
  fn sign_content(&self, pri : &[u8], con : &mut Read) -> Result<Vec<u8>> {
    T::S::sign_content(pri, con)
  }
  #[inline]
  fn check_id_derivation(&self, sig : &[u8], id : &[u8]) -> bool {
    T::D::check_id_derivation(sig,id)
  }
  #[inline]
  fn derive_id(&self, sig : &[u8]) -> Vec<u8> {
    T::D::derive_id(sig)
  }
 

  fn striple_ser<'a> (&'a self) -> Result<(Vec<u8>,Option<&'a BCont<'a>>)> {
    let mut res = Vec::new();
    let tmplen;
    push_id(&mut res, <T as StripleKind>::get_algo_key());
    push_id(&mut res, &self.contentenc);
    push_id(&mut res, &self.id);
    push_id(&mut res, &self.from);

    tmplen = self.sig.len();
    res.append(&mut xtendsize(tmplen,SIG_LENGTH));
    res.append(&mut self.sig.to_vec());

    let ocon = self.ser_tosig(&mut res)?;

    Ok((res,ocon))
  }
 
  #[inline]
  fn get_key(&self) -> &[u8]{&self.key}
  #[inline]
  fn get_sig(&self) -> &[u8]{&self.sig}
  #[inline]
  fn get_id(&self) -> &[u8]{&self.id}
  #[inline]
  fn get_about(&self) -> &[u8] {
    if self.about.len() > 0 {
      &self.about
    } else {
      &self.id
    }
  }
  #[inline]
  fn get_from(&self) -> &[u8] {&self.from}
  #[inline]
  fn get_enc(&self) -> &[u8] {&self.contentenc}
  #[inline]
  fn get_content<'a>(&'a self) -> &'a Option<BCont<'a>> {
    &self.content
  }
  #[inline]
  fn get_content_ids(&self) -> Vec<&[u8]> {
    self.contentids.iter().map(|r|&r[..]).collect()
  }
  fn get_tosig<'a>(&'a self) -> Result<(Vec<u8>,Option<&'a BCont<'a>>)> {
    let mut res = Vec::new();
    let oc =  self.ser_tosig(&mut res)?;
    Ok((res, oc))
  }
}

impl<'a,T : StripleKind> StripleIf for StripleRef<'a,T> {

  #[inline]
  fn get_algo_key(&self) -> &'static [u8]{
    T::get_algo_key()
  }
  #[inline]
  fn check_content(&self, cont : &mut Read, sig : &[u8]) -> bool {
    T::S::check_content(self.key, cont, sig)
  }
  #[inline]
  fn sign_content(&self, pri : &[u8], con : &mut Read) -> Result<Vec<u8>> {
    T::S::sign_content(pri, con)
  }
  #[inline]
  fn check_id_derivation(&self, sig : &[u8], id : &[u8]) -> bool {
    T::D::check_id_derivation(sig,id)
  }
  #[inline]
  fn derive_id(&self, sig : &[u8]) -> Vec<u8> {
    T::D::derive_id(sig)
  }
 
 



  fn striple_ser<'b> (&'b self) -> Result<(Vec<u8>,Option<&'b BCont<'b>>)> {
    let mut res = Vec::new();
    let tmplen;
    push_id(&mut res, <T as StripleKind>::get_algo_key());
    push_id(&mut res, self.contentenc);
    push_id(&mut res, self.id);
    push_id(&mut res, self.from);

    tmplen = self.sig.len();
    res.append(&mut xtendsize(tmplen,SIG_LENGTH));
    res.append(&mut self.sig.to_vec());

    let ocon = self.ser_tosig(&mut res)?;

    Ok((res,ocon))
  }

  #[inline]
  fn get_key(&self) -> &[u8]{self.key}
  #[inline]
  fn get_sig(&self) -> &[u8]{self.sig}
  #[inline]
  fn get_id(&self) -> &[u8]{self.id}
  #[inline]
  fn get_about(&self) -> &[u8] {
    if self.about.len() > 0 {
      self.about
    } else {
      self.id
    }
  }
  #[inline]
  fn get_from(&self) -> &[u8] {self.from}
  #[inline]
  fn get_enc(&self) -> &[u8] {self.contentenc}
  #[inline]
  fn get_content<'b>(&'b self) -> &'b Option<BCont<'b>> {
    &self.content
  }
  #[inline]
  fn get_content_ids(&self) -> Vec<&[u8]> {self.contentids.clone()}
  #[inline]
  fn get_tosig<'b>(&'b self) -> Result<(Vec<u8>,Option<&'b BCont<'b>>)> {
    let mut res = Vec::new();
    let oc = self.ser_tosig(&mut res)?;
    Ok((res, oc))
  }
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
/// dser without lifetime TODO redesign to interface on same as striple_dser : here useless as
/// cannot cast in any triple without a copy
pub fn striple_copy_dser<T : StripleIf, K : StripleKind, FS : StripleIf, B> (bytes : &[u8], obc : Option<BCont>, docheck : Option<&FS>, builder : B) -> Result<T>
  where B : Fn(&[u8], Striple<K>) -> Result<T>
{
  striple_dser(bytes, obc, docheck,
   |algoid, sref| {
    builder(algoid, sref.as_striple())
  }
  )
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
pub fn striple_dser<'a, T : StripleIf, K : StripleKind, FS : StripleIf, B> (bytes : &'a[u8], obc : Option<BCont<'a>>, docheck : Option<&FS>, ref_builder : B) -> Result<T>
  where B : Fn(&[u8], StripleRef<'a,K>) -> Result<T>
{
  let mut ix = 0;
  let algoenc = read_id (bytes, &mut ix);
  let contentenc = read_id (bytes, &mut ix); 
  let id = read_id (bytes, &mut ix);
  let from = read_id (bytes, &mut ix);

  let s = xtendsizedec(bytes, &mut ix, SIG_LENGTH);
  let mut sig = if ix + s <= bytes.len() {
    &bytes[ix .. ix + s]
  } else {
    &bytes[0 .. 0]
  };
  ix = ix + s;

  if sig.len() == 0 {
    sig = id;
  }
  
  let startcontent = ix;

  let mut about = read_id (bytes, &mut ix);
  if about.len() == 0 {
    about = id;
  };

  let s = xtendsizedec(bytes, &mut ix, KEY_LENGTH);
  let key = if ix + s <= bytes.len() {
    &bytes[ix .. ix + s]
  } else {
    &bytes[0 .. 0]
  };
  ix = ix + s;

  let nbcids = xtendsizedec(bytes, &mut ix, CONTENTIDS_LENGTH);
  let mut contentids = Vec::new();
  for _ in 0 .. nbcids {
    contentids.push(read_id (bytes, &mut ix));
  };

  let s = xtendsizedec(bytes, &mut ix, CONTENT_LENGTH);
  let checkerror : Option<Error> = docheck.and_then(|fromst|{
    if fromst.get_id() != &from[..] {
      return Some(Error("Unexpected from id".to_string(), ErrorKind::UnexpectedStriple, None))
    };
    let tocheck = &bytes[startcontent .. bytes.len()];
 
    if !( fromst.check_id_derivation(sig,id) &&
      match &obc {
        &Some (ref bc) => {
          match bc.get_readable() {
            Ok(mut r) => {
              let mut tos = Cursor::new(tocheck).chain(r.trait_read());
              fromst.check_content(&mut tos, sig)
            },
            Err(r) => return Some(r),
          }
        },
        &None => fromst.check_content(&mut Cursor::new(tocheck), sig),
      })
    {
      return Some(Error("Invalid signature or key derivation".to_string(), ErrorKind::UnexpectedStriple, None))
    };
    None
  });
  match checkerror {
    Some(err) => {return Err(err);}
    None => ()
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
      ix = ix + s;
      if ix <= bytes.len() {
        Some(BCont::NotOwnedBytes(&bytes[ix - s .. ix]))
      } else {
        return Err(Error("Mismatch size of content".to_string(), ErrorKind::DecodingError, None))
      }
    }
  },};
  if ix != bytes.len() {
    debug!("strip or {:?} - {:?}", ix, bytes.len());
    return Err(Error("Mismatch size of striple".to_string(), ErrorKind::DecodingError, None))
  }




  if id.len() == 0 
  || from.len() == 0 
  || (contentids.len() == 0 && content.is_none())
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
  fn as_striple_if(&self) -> &StripleIf;
}
// boilerplate adapter code
impl<T : AsStripleIf + Debug> StripleIf for T {
  #[inline]
  fn check_content(&self, cont : &mut Read,sig : &[u8]) -> bool {
    self.as_striple_if().check_content(cont,sig)
  }
  #[inline]
  fn sign_content(&self, a : &[u8], b : &mut Read) -> Result<Vec<u8>> {
    self.as_striple_if().sign_content(a,b)
  }
  #[inline]
  fn derive_id(&self, sig : &[u8]) -> Vec<u8> {
    self.as_striple_if().derive_id(sig)
  }
  #[inline]
  fn check_id_derivation(&self, sig : &[u8], id : &[u8]) -> bool {
    self.as_striple_if().check_id_derivation(sig,id)
  }
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
  fn get_content<'a>(&'a self) -> &'a Option<BCont<'a>> {
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
  fn striple_ser<'b> (&'b self) -> Result<(Vec<u8>,Option<&'b BCont<'b>>)> {
    self.as_striple_if().striple_ser()
  }

}

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
impl<T : StripleKind> Encodable for Striple<T> {
  fn encode<S:Encoder> (&self, s: &mut S) -> StdResult<(), S::Error> {
    let (mut v, ocon) = match self.striple_ser() {
      Ok(a) => a,
      Err(_) => 
            panic!("cannot der striple"), // TODO see next panic
    };
    match ocon {
      Some(bcon) => {
        match bcon.get_byte() {
          Ok(mut vcon) => {
            v.append(&mut vcon);
            v.encode(s)
          },
          Err(_) => {
            // TODO follow this https://github.com/rust-lang/rustc-serialize/issues/76 -> TODO
            // switch to SERD
            // for now panic
            panic!("cannot add BCont when serializing")
          }
        }
      },
      None => v.encode(s),
    }
  }
}

// TODO test on this (not good)
#[cfg(feature="serialize")]
impl<T : StripleKind> Decodable for Striple<T> {
  fn decode<D:Decoder> (d : &mut D) -> StdResult<Striple<T>, D::Error> {
    let tmpres = Vec::decode(d);
    // Dummy type
    let typednone : Option<&Striple<T>> = None;
    tmpres.and_then(|vec| 
      striple_dser(&vec, None, typednone, ref_builder_id_copy).map_err(|err|
        d.error(&format!("{:?}",err))
      )
    )
  }
}

#[derive(Debug)]
pub struct Error(pub String, pub ErrorKind, pub Option<Box<ErrorTrait>>);

#[inline]
pub fn from_error<T,E1 : Into<Error>>(r : StdResult<T, E1>) -> StdResult<T,Error>
{
  r.map_err(|e| e.into())
}

#[inline]
pub fn from_option<T>(r : Option<T>) -> Result<T> {
  match r {
    Some(T) => Ok(T),
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
  let maxval = (num::pow(2, nbbyte * 8) - 1) / 2;
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
    let v : [u8;8] = if cfg!(target_endian = "little") {
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
  let mut v : [u8;8] = mem::transmute(0usize);
  debug!("DEBUG_bef {:?}, {:?} !!!",v, nbbytes);
  if idx + nbbytes <= bytes.len() {
    let b : &[u8] = &bytes[idx .. idx + nbbytes];
    copy_nonoverlapping(b.as_ptr(),v[8-nbbytes..].as_mut_ptr(),nbbytes);
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
  let mut v : [u8;8] = mem::transmute(0usize);
  debug!("DEBUG_bef {:?}, {:?} !!!",v, nbbytes);
  if nbbytes <= 8 {
    copy_nonoverlapping(buf[adj_ix..].as_ptr(),v[8-nbbytes..].as_mut_ptr(),nbbytes);
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
fn calcnbbyte(val : usize) -> usize {
  let mut res = 0;
  for i in 0 .. 8 {
    if val < (num::pow(2,i*8) - 1)/2 {
      res = i;
      break;
    }
  };
  res
}

#[test]
fn test_xtendsize () {
  assert_eq!(xtendsize(0,0),vec![]);
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
  IOError,
  VarError,
  FromOption,
}

// feature related implementation of serialize (using standard ser meth of striple) : to avoid
// redundant def (type alias...).


#[derive(Debug,Clone)]
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
  fn derive_id(_ : &[u8]) -> Vec<u8> {
    vec!()
  }
  fn check_id_derivation(_ : &[u8], _ : &[u8]) -> bool {
    false
  }

}
impl SignatureScheme for NoSigCh {
  fn sign_content(_ : &[u8], _ : &mut Read) -> StdResult<Vec<u8>,Error> {
    Ok(vec!())
  }
  fn check_content(_ : &[u8],_ : &mut Read,_ : &[u8]) -> bool {
    false
  }
  fn new_keypair() -> (Vec<u8>, Vec<u8>) {
    (vec!(), vec!())
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
  use striple::Striple;
  use striple::Result;
  use striple::striple_dser;
  use striple::striple_copy_dser;
  use striple::StripleRef;
  use striple::StripleIf;
  use striple::AsStriple;
  use striple::StripleKind;
  use striple::NoKind;
  use striple::BCont;
  use striple::Error;
  use striple::as_kind;
  use striple::mut_as_kind;
  use striple::ref_builder_id_copy;
  use striple::ref_builder_id;
  use striple::copy_builder_id;
  use striple::IDDerivation;
  use striple::SignatureScheme;

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
    fn derive_id(sig : &[u8]) -> Vec<u8> {
      // simply use signature as key
      sig.to_vec()
    }
    fn check_id_derivation(sig : &[u8], id : &[u8]) -> bool {
      sig == id 
    }

  }
  impl SignatureScheme for TestSigSchem1 {
    fn sign_content(pri : &[u8], _ : &mut Read) -> Result<Vec<u8>> {
      // Dummy : just use pri
      Ok(pri.to_vec())
    }
    fn check_content(publ : &[u8], _ : &mut Read, sig : &[u8]) -> bool {
      // Dummy
      debug!("checkcontet :pub {:?}, sig {:?}", publ, sig);
      publ != sig
    }
    fn new_keypair() -> (Vec<u8>, Vec<u8>) {
      // Dummy pri is same as pub
      let mut tmp = [0u8; 4];
      rand::thread_rng().fill_bytes(&mut tmp);
      let rand = tmp.to_vec();
      (rand.clone(), rand)
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
    let path = { 
      //let tmpdir = env::temp_dir();
      let tmpdir = PathBuf::new(); // TODO tmpdir when relative path ok??
      let mytmpdirpath = tmpdir.join("./test_rust_striple_sample");
      fs::create_dir_all(&mytmpdirpath).unwrap();
      let fpath = mytmpdirpath.join("striple4.file");
      debug!("Creating tmp file : {:?}",fpath);
      let mut f = File::create(&fpath).unwrap();
      f.write_all(&longcontent[..]).unwrap();
      fpath
    };
    Striple {
        contentenc : vec!(),
        id : common_id_2.clone(),
        from : vec!(4,4,4,4),
        sig : common_id_2.clone(),
        about : vec!(),
        key : vec!(0),
        contentids : vec!(),
        content : Some(BCont::LocalPath(path)),

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
    let (encori_1, oc) = ori_1.striple_ser().unwrap();
    assert!(oc.is_none());
    debug!("Encoded : \n{:?}",encori_1);
    let typednone : Option<&Striple<TestKind1>> = Some(&ori_2);
    let dec1 : Striple<TestKind1> = striple_dser(&encori_1, None, typednone,ref_builder_id_copy).unwrap();
    assert_eq!(compare_striple(&ori_1,&dec1), true);
    let (encori_ref_1,oc2) = ori_ref_1.striple_ser().unwrap();
    assert!(oc2.is_none());
    assert_eq!(encori_1,encori_ref_1);
    let redec1 : Striple<TestKind1> = striple_copy_dser(&encori_1, None, typednone,copy_builder_id).unwrap();
    assert_eq!(compare_striple(&ori_1,&redec1), true);
    let redec1bis : StripleRef<TestKind1> = striple_dser(&encori_1, None, typednone,ref_builder_id).unwrap();
    let (encori_ref_1_bis,oc3) = redec1bis.striple_ser().unwrap();
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

    let key_1 = D::derive_id (sig_1);
    let key_2 = D::derive_id (sig_2);
    let key_3 = D::derive_id (sig_3);
    let key_null = D::derive_id (sig_null);

    assert!((sig_1 == sig_2) || (key_1 != key_2));
    assert!((sig_2 == sig_2) || (key_2 != key_2));
    assert!((sig_3 == sig_2) || (key_3 != key_2));

    // generate signature of rendom right length and uncoment
    assert!(sig_1.len() >= key_1.len());
    // case with small sig
    assert!(sig_null.len() == key_null.len());

    assert!(D::check_id_derivation(sig_3, &key_3));
    // TODO something with this case
    // assert!(!D::check_id_derivation(sig_null, &key_null));

  }

  fn pub_sign<S : SignatureScheme> () {
    let kp1 = S::new_keypair();
    let kp2 = S::new_keypair();
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
    assert!(S::check_content(&kp1.0, &mut cont_1, &sig_1));
    cont_1.seek(SeekFrom::Start(0)).unwrap();
    assert!(!S::check_content(&vec!(1,2,3,4), &mut cont_1, &sig_1));
    cont_1.seek(SeekFrom::Start(0)).unwrap();
    // and sig validate content
    assert!(!S::check_content(&kp2.0, &mut cont_2, &vec!()));
    cont_2.seek(SeekFrom::Start(0)).unwrap();

    // signing do not have salt (uniqueness by keypair pub in content).
    assert!(S::sign_content(&kp1.1, &mut cont_1).unwrap() == sig_1);
    cont_1.seek(SeekFrom::Start(0)).unwrap();
    assert!(S::sign_content(&kp2.1, &mut cont_2).unwrap() == sig_2);
    cont_1.seek(SeekFrom::Start(0)).unwrap();

  }

  fn pri_sign<S : SignatureScheme> () {
    let kp1 = S::new_keypair();
    let kp2 = S::new_keypair();
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

    // signature never empty
    assert!(S::sign_content(&kp1.1[..], &mut cont_1).unwrap() != &vec!()[..]);
    cont_1.seek(SeekFrom::Start(0)).unwrap();
    assert!(S::sign_content(&kp2.1[..], &mut cont_1).unwrap() != &vec!()[..]);
    cont_1.seek(SeekFrom::Start(0)).unwrap();

    // signing must have salt : no since different public key in content
    // assert!(S::sign_content(&kp1.1[..], cont_1) != sig_1);
    // assert!(S::sign_content(&kp2.1[..], cont_2) != sig_2);

    // check content only when finely signed
    assert!(!S::check_content(&kp1.0[..], &mut cont_1, &vec!(4)[..]));
    cont_1.seek(SeekFrom::Start(0)).unwrap();
    assert!(S::check_content(&kp1.0[..], &mut cont_1, &sig_1[..]));
    cont_1.seek(SeekFrom::Start(0)).unwrap();
    assert!(S::check_content(&kp2.0[..], &mut cont_2, &sig_2[..]));
    cont_2.seek(SeekFrom::Start(0)).unwrap();
  }

  // test for chaning integrity, construct a K1 root then K1 and K2 son then for K2 K1 and K2 son.
  // With test for altering integrity (mut striple).
  pub fn chaining_test<K1 : StripleKind, K2 : StripleKind> () {
    let contentenc = random_bytes(99);
    let ownedroot : (Striple<K1>, Vec<u8>) = Striple::new(
      contentenc.clone(),
      None,
      None,
      Vec::new(),
      Some(BCont::OwnedBytes(random_bytes(333))),
    ).unwrap();
    let root = ownedroot.0;
    // check algo is same as K1 get_algo
    assert_eq!(root.get_algo_key(), K1::get_algo_key());
    // check about and from are same as id
    assert_eq!(root.get_id(),&root.from[..]);
    assert!(root.get_id() == root.get_about());

    // check signed by itself
    assert!(root.check(&root));
    
     let ownedson1 : (Striple<K1>, Vec<u8>) = Striple::new(
      contentenc.clone(),
      Some(&(&root,&ownedroot.1[..])),
      // random about : no logic here because about is not validated
      Some(random_bytes(9)),
      // random contentids
      vec!(vec!(1),vec!(3,4,4)),
      None,
    ).unwrap();
    let son1 = ownedson1.0;

    assert!(son1.check(&root));
    assert!(!son1.check(&son1));

    let ownedson2 : (Striple<K2>, Vec<u8>) = Striple::new(
      contentenc.clone(),
      Some(&(&root,&ownedroot.1[..])),
      // random about : no logic here because about is not validated
      Some(random_bytes(7)),
      // random contentids
      vec!(vec!(5,1),vec!(3,4,4)),
      Some(BCont::OwnedBytes(vec!(5,2))),
      
    ).unwrap();
    let son2 = ownedson2.0;
 
    assert!(son2.check(&root));
    assert!(!son2.check(&son1));
    assert!(!son2.check(&son2));



    let ownedson21 : (Striple<K1>, Vec<u8>) = Striple::new(
      contentenc.clone(),
      Some(&(&son2,&ownedson2.1[..])),
      // random about : no logic here because about is not validated
      Some(vec!(4,4,3,4)),
      // random contentids
      vec!(vec!(5,1),vec!(3,4,4)),
      Some(BCont::OwnedBytes(vec!(5,2))),
    ).unwrap();
    let son21 = ownedson21.0;
 
    assert!(son21.check(&son2));
    assert!(!son21.check(&root));

    let ownedson22 : (Striple<K2>, Vec<u8>) = Striple::new(
      contentenc.clone(),
      Some(&(&son2,&ownedson2.1[..])),
      // random about : no logic here because about is not validated
      Some(vec!(4,4,3,4)),
      // random contentids
      vec!(vec!(5,1),vec!(3,4,4)),
      Some(BCont::OwnedBytes(vec!(5,2))),
    ).unwrap();
    let son22 = ownedson22.0;

    assert!(son22.check(&son2));
    assert!(!son22.check(&root));

    let ownedson22bis : (Striple<K2>, Vec<u8>) = Striple::new(
      contentenc.clone(),
      Some(&(&son2,&ownedson2.1[..])),
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
    assert!(tmp2.check(&son2));
    let mut tmp1 = son1.clone();
    assert!(tmp1.check(&root));
    tmp2.from = unknown_vec.clone();
    assert!(!tmp2.check(&son2));
    tmp1.from = unknown_vec.clone();
    assert!(!tmp1.check(&root));
    
    // check changing `about` break previous checking...
    tmp2 = son22.clone();
    tmp1 = son1.clone();
    tmp2.about = unknown_vec.clone();
    assert!(!tmp2.check(&son2));
    tmp1.about = unknown_vec.clone();
    assert!(!tmp1.check(&root));
    // check changing `content` break previous checking...
    tmp2 = son22.clone();
    tmp1 = son1.clone();
    tmp2.content = Some(BCont::OwnedBytes(unknown_vec.clone()));
    assert!(!tmp2.check(&son2));
    tmp1.content = Some(BCont::OwnedBytes(unknown_vec.clone()));
    assert!(!tmp1.check(&root));
    // check changing `contentid` break previous checking...
    tmp2 = son22.clone();
    tmp1 = son1.clone();
    tmp2.contentids = vec!(unknown_vec.clone());
    assert!(!tmp2.check(&son2));
    tmp1.contentids = vec!(unknown_vec.clone());
    assert!(!tmp1.check(&root));
    // check changing `key` break previous checking...
    tmp2 = son22.clone();
    tmp1 = son1.clone();
    tmp2.key = unknown_vec.clone();
    assert!(!tmp2.check(&son2));
    tmp1.key = unknown_vec.clone();
    assert!(!tmp1.check(&root));
    // check changing `sig` break previous checking...
    tmp2 = son22.clone();
    tmp1 = son1.clone();
    tmp2.sig = unknown_vec.clone();
    assert!(!tmp2.check(&son2));
    tmp1.sig = unknown_vec.clone();
    assert!(!tmp1.check(&root));
    // check changing `id` break previous checking...
    tmp2 = son22.clone();
    tmp1 = son1.clone();
    tmp2.id = unknown_vec.clone();
    assert!(!tmp2.check(&son2));
    tmp1.id = unknown_vec.clone();
    assert!(!tmp1.check(&root));
    // check changing `encodingid` is impactless previous checking... (content encoding is not in
    // scheme and purely meta)
    tmp2 = son22.clone();
    tmp1 = son1.clone();
    tmp2.contentenc = unknown_vec.clone();
    assert!(tmp2.check(&son2));
    tmp1.contentenc = unknown_vec.clone();
    assert!(tmp1.check(&root));

  }

  // utility
  pub fn random_bytes(size : usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut bytes = vec![0; size];
    rng.fill_bytes(&mut bytes);
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
    .field("id", &self.0.get_id().to_base64(BASE64CONF))
    .field("from", &self.0.get_from().to_base64(BASE64CONF))
    .field("about", &self.0.get_about().to_base64(BASE64CONF))
    .field("content_ids", &{
      let mut catids = "[".to_string();
      for id in self.0.get_content_ids().iter() {
        catids = catids + &id.to_base64(BASE64CONF)[..] + ",";
      }
      catids + "]"
      }
    )
    .field("content", &truncated_content(self.0.get_content()).to_base64(BASE64CONF))
    .field("content_string", &String::from_utf8(truncated_content(self.0.get_content()).to_vec()))
    .field("key", &self.0.get_key().to_base64(BASE64CONF))
    .field("sig", &self.0.get_sig().to_base64(BASE64CONF))
    .field("kind ", &self.0.get_algo_key().to_base64(BASE64CONF))
    .finish()

  }
}

#[inline]
fn truncated_content<'a> ( ocont : &Option<BCont<'a>>)-> Vec<u8> {
  ocont.as_ref().map_or(vec!(),|cont|{
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
    .field("PrivateKey", &self.0.private_key_ref().to_base64(BASE64CONF))
    .finish()
  }
}

#[cfg(feature="serialize")]
pub static BASE64CONF : base64::Config = base64::Config {
    char_set : base64::CharacterSet::Standard,
    newline : base64::Newline::LF,
    pad : true,
    line_length : None,
};

