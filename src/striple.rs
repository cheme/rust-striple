
use std::fmt::{Debug};
use std::marker::PhantomData;
use num;
use std::mem;
use std::ptr::copy_nonoverlapping;
use num::traits::{ToPrimitive};


#[cfg(feature="serialize")]
use rustc_serialize::{Encoder,Encodable,Decoder,Decodable};

// TODO replace vec new push all [u8] by something better for convert &[u8] to Vec<u8> -> simply
// to_vec() ????

/// Striple could be a standard struct, or references to contents from others struct
/// Trait should not be implemented for other struct (or conformance with test case needed).
/// Other struct should implement AsStriple (probably to stripleRef).
/// TODO word on enum to serialize and manage parametric types
pub trait StripleIf<T : StripleKind> : Clone + Debug {

  /// check striple integrity (signature and key)
  fn check<FK : StripleKind, FS : StripleIf<FK>> (&self, from : &FS) -> bool {
    self.check_id(from) && self.check_sig(from)
  }

  /// check signature of striple
  fn check_sig<FK : StripleKind, FS : StripleIf<FK>> (&self, from : &FS) -> bool {
    from.get_id() == self.get_from() && <FK::S as SignatureScheme>::check_content(from.get_key(), &self.get_tosig(), self.get_sig())
  }

  /// check key of striple
  fn check_id<FK : StripleKind, FS : StripleIf<FK>> (&self, from : &FS) -> bool {
    <FK::D as IDDerivation>::check_id_derivation(self.get_sig(), self.get_id())
  }

  /// get striple key value
  fn get_id(&self) -> &[u8];

  /// get striple key value
  fn get_from(&self) -> &[u8];

  /// get striple key value
  fn get_about(&self) -> &[u8];

  /// get conte value
  fn get_content(&self) -> &[u8];
  /// get content ids value
  fn get_content_ids(&self) -> Vec<&[u8]>;


// TODO get content utils


  /// get striple key value
  fn get_key(&self) -> &[u8];

  /// get key of striple defining algo scheme
  fn get_algo_key(&self) -> &'static [u8] {
    <T as StripleKind>::get_algo_key()
  }

  /// get striple signature value
  fn get_sig(&self) -> &[u8];

  // TODO test where decode from ser to striple, then check getbytes is allways the same
  // (sig to) 
  /// get bytes which must be signed
  fn get_tosig(&self) -> Vec<u8>;


  /// encode to bytes, but only striple content : Vec<u8> only include striple info.
  fn striple_ser (&self) -> Vec<u8>;

  /// decode from bytes, with possible signing validation
  /// Deserialize does not result in StripleIf, because StripleIf is use to allow reference to
  /// existing structure and adding content to a structure and still being an StripleIf, yet
  /// deserialize as a library item is only here to enforce encoding of striple : 
  /// to use on other structure deserialize must be use by a more general
  /// deserialize primitive or if particular non striple encoding (in json for instance), the
  /// resulting struct will use AsStriple (probably to stripleref) to use striple primitive.
  fn striple_dser<'a, FK : StripleKind, FS : StripleIf<FK>>  (bytes : &'a[u8], docheck : Option<&FS>) -> Result<StripleRef<'a,T>, Error> {
    StripleRef::striple_dser(bytes, docheck)
  }


}

/// used to categorize a striple and its associated scheme
/// for exemple a struct can be convert to two striple :
///
/// fn<T : StripleKind> as_striple (user : &User) -> Striple<T>{...}
///
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
  fn sign_content(pri : &[u8], cont : &[u8]) -> Vec<u8>;

  /// first parameter is public key, second is content and third is signature
  fn check_content(publ : &[u8],cont : &[u8],sig : &[u8]) -> bool;

  /// create keypair (first is public, second is private)
  fn new_keypair() -> (Vec<u8>, Vec<u8>);

}

pub trait OwnedStripleIf<T : StripleKind> : StripleIf<T> {

  /// owned striple has a private key, default implementation is inefficient
  fn private_key (&self) -> Vec<u8> {
    self.private_key_ref().to_vec()
  }

  fn private_key_ref<'a> (&'a self) -> &'a[u8];

  /// first parameter is private key, second parameter is content
  fn sign<K : StripleKind, ST : StripleIf<K>>(&self, st : &ST) -> Vec<u8> {
    T::S::sign_content(self.private_key_ref(), &st.get_tosig())
  }

 
  // TODO debug with *** private + serialize for file

}


// TODO owned pair of striple


impl<'a, T : StripleKind, ST : StripleIf<T>> StripleIf<T> for (&'a ST, &'a [u8]) {
  #[inline]
  fn striple_ser (&self) -> Vec<u8> {
    // TODO complete with scheme for file as this is false and incomplete
    self.0.striple_ser()
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
  fn get_id(&self) -> &[u8] {
    self.0.get_id()
  }
  #[inline]
  fn get_about(&self) -> &[u8] {
    self.0.get_about()
  }
  #[inline]
  fn get_from(&self) -> &[u8] {
    self.0.get_from()
  }
  #[inline]
  fn get_content(&self) -> &[u8] {
    self.0.get_content()
  }
   #[inline]
  fn get_content_ids(&self) -> Vec<&[u8]> {
    self.0.get_content_ids()
  }
  #[inline]
  fn get_tosig(&self) -> Vec<u8> {
    self.0.get_tosig()
  }
}

impl<'b, T : StripleKind, ST : StripleIf<T>> OwnedStripleIf<T> for (&'b ST, &'b [u8]) {

  #[inline]
  fn private_key (&self) -> Vec<u8> {
    self.1.to_vec()
  }

  #[inline]
  fn private_key_ref<'a> (&'a self) -> &'a[u8] {
    self.1
  }

}

/// Type to use an striple as Public, allowing to sign/create striple from it without others info
/// (see Ownedstriple implementation). Usage with non public striple will result in error when
/// signing or worst when checking.
#[derive(Debug,Clone)]
pub struct PubStriple<'a, T : StripleKind, ST : StripleIf<T> + 'a> (&'a ST, PhantomData<T>) where T::S : PublicScheme;

/// use as PubStriple
#[inline]
pub fn striple_as_public<'a, T : StripleKind, ST : StripleIf<T>> (st : &'a ST) -> PubStriple<'a, T, ST>  where T::S : PublicScheme {
  PubStriple(st, PhantomData)
}

impl<'b, T : StripleKind, ST : StripleIf<T> + 'b> StripleIf<T> for PubStriple<'b, T, ST>  where T::S : PublicScheme {
  #[inline]
  fn striple_ser (&self) -> Vec<u8> {
    self.0.striple_ser()
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
  fn get_id(&self) -> &[u8] {
    self.0.get_id()
  }
  #[inline]
  fn get_about(&self) -> &[u8] {
    self.0.get_about()
  }
   #[inline]
  fn get_from(&self) -> &[u8] {
    self.0.get_from()
  }
  #[inline]
  fn get_content(&self) -> &[u8] {
    self.0.get_content()
  }
   #[inline]
  fn get_content_ids(&self) -> Vec<&[u8]> {
    self.0.get_content_ids()
  }
 
  #[inline]
  fn get_tosig(&self) -> Vec<u8> {
    self.0.get_tosig()
  }
}

/// public scheme uses same value for public and private key
impl<'b, T : StripleKind, ST : StripleIf<T> + 'b> OwnedStripleIf<T> for PubStriple<'b, T,ST>  where T::S : PublicScheme {

  fn private_key (&self) -> Vec<u8> {
    self.0.get_key().to_vec()
  }

  fn private_key_ref<'a> (&'a self) -> &'a[u8] {
    self.0.get_key()
  }

}

/// Striple struct object to manipulate an striple
/// TODO currently not memory efficient (if id = sig or if from = about two identical vec are stored)
#[derive(Debug,Clone)]
pub struct Striple<T : StripleKind> {
  /// id of the striple defining the encoding of the content
  /// optional (null vec otherwhise)
  contentenc : Vec<u8>,
  /// id of the striple
  id : Vec<u8>,
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
  /// optional (null vec otherwhise)
  content : Vec<u8>,

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
  content    : &'a[u8],

  phtype : PhantomData<T>,
} 

// identic code for stripleref and striple   
macro_rules! ser_content(() => (
  #[inline]
  fn ser_tosig (&self, res : &mut Vec<u8>) {
    let mut tmplen;

    // never encode the same value for about and id
    if self.id != self.about {
      push_id(res, &self.about);
    } else {
      push_id(res, &[]);
    }

    tmplen = self.key.len();
    res.push_all(&xtendsize(tmplen,2));
    res.push_all(&self.key);
    
    tmplen = self.contentids.len();
    res.push_all(&xtendsize(tmplen,1));
    for cid in self.contentids.iter(){
      push_id(res, &cid)
    };

    tmplen = self.content.len();
    res.push_all(&xtendsize(tmplen,4));
    res.push_all(&self.content);
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
  pub fn new<TF : StripleKind, SF : OwnedStripleIf<TF>> (
    contentenc : Vec<u8>,
    from : Option<&SF>,
    about: Option<Vec<u8>>,
    contentids : Vec<Vec<u8>>,
    content :    Vec<u8>,
  ) -> (Striple<T>,Vec<u8>) {
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
        let sig = st.sign(&res);
        let id = TF::D::derive_id(&sig);
        (sig, id)
      },
      None => {
        let sig = T::S::sign_content(&keypair.1, &res.get_tosig());
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

    (res, keypair.1)
  }
  // utility to fact code
  ser_content!();
}

impl<'a, T : StripleKind> StripleRef<'a, T> {

  // utility to fact code
  ser_content!();
}


impl<T : StripleKind> StripleIf<T> for Striple<T> {

  fn striple_ser (&self) -> Vec<u8> {
    let mut res = Vec::new();
    let mut tmplen;
    push_id(&mut res, <T as StripleKind>::get_algo_key());
    push_id(&mut res, &self.contentenc);
    push_id(&mut res, &self.id);
    push_id(&mut res, &self.from);

    tmplen = self.sig.len();
    res.push_all(&xtendsize(tmplen,4));
    res.push_all(&self.sig);

    self.ser_tosig(&mut res);

    res
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
      &self.from
    }
  }
  #[inline]
  fn get_from(&self) -> &[u8] {&self.from}
  #[inline]
  fn get_content(&self) -> &[u8] {&self.content  }
  #[inline]
  fn get_content_ids(&self) -> Vec<&[u8]> {
    self.contentids.iter().map(|r|&r[..]).collect()
  }
 
  fn get_tosig(&self) -> Vec<u8>{
    let mut res = Vec::new();
    self.ser_tosig(&mut res);
    res
  }

}

impl<'a,T : StripleKind> StripleIf<T> for StripleRef<'a,T> {

  fn striple_ser (&self) -> Vec<u8> {
    let mut res = Vec::new();
    let mut tmplen;
    push_id(&mut res, <T as StripleKind>::get_algo_key());
    push_id(&mut res, self.contentenc);
    push_id(&mut res, self.id);
    push_id(&mut res, self.from);

    tmplen = self.sig.len();
    res.push_all(&xtendsize(tmplen,4));
    res.push_all(self.sig);

    self.ser_tosig(&mut res);

    res
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
      self.from
    }
  }
  #[inline]
  fn get_from(&self) -> &[u8] {self.from}
  #[inline]
  fn get_content(&self) -> &[u8] {self.content}
  #[inline]
  fn get_content_ids(&self) -> Vec<&[u8]> {self.contentids.clone()}
  #[inline]
  fn get_tosig(&self) -> Vec<u8>{
    let mut res = Vec::new();
    self.ser_tosig(&mut res);
    res
  }

  /// decode from bytes
  /// TODO better error management
  fn striple_dser<'b, FK : StripleKind, FS : StripleIf<FK>>  (bytes : &'b[u8], docheck : Option<&FS>) -> Result<StripleRef<'b,T>, Error> {
    let mut ix = 0;
    let algoenc = read_id (bytes, &mut ix);
    if algoenc != <T as StripleKind>::get_algo_key() {
      return Err(("Bad algo kind for this type of striple".to_string(), ErrorKind::UnexpectedStriple))
    };
    let contentenc = read_id (bytes, &mut ix); 
    let id = read_id (bytes, &mut ix);
    let from = read_id (bytes, &mut ix);

    let s = xtendsizedec(bytes, &mut ix, 4);
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
      about = from;
    };

    let s = xtendsizedec(bytes, &mut ix, 2);
    let key = if ix + s <= bytes.len() {
      &bytes[ix .. ix + s]
    } else {
      &bytes[0 .. 0]
    };
    ix = ix + s;

    let nbcids = xtendsizedec(bytes, &mut ix, 1);
    let mut contentids = Vec::new();
    for _ in (0 .. nbcids) {
      contentids.push(read_id (bytes, &mut ix));
    };

    let s = xtendsizedec(bytes, &mut ix, 4);
    let content = if ix + s <= bytes.len() {
      &bytes[ix .. ix + s]
    } else {
      &bytes[0 .. 0]
    };
    ix = ix + s;

    if ix != bytes.len() {
      debug!("strip or {:?} - {:?}", ix, bytes.len());
      return Err(("Mismatch size of striple".to_string(), ErrorKind::DecodingError))
    }

    let checkerror : Option<Error>= docheck.and_then(|fromst|{
      if fromst.get_id() != &from[..] {
        return Some(("Unexpected from id".to_string(), ErrorKind::UnexpectedStriple))
      };
      let content = &bytes[startcontent .. bytes.len()];
      if !(
         <FK::D as IDDerivation>::check_id_derivation(sig,id) &&
         <FK::S as SignatureScheme>::check_content(fromst.get_key(), content, sig)) {
        return Some(("Invalid signature or key derivation".to_string(), ErrorKind::UnexpectedStriple))
      };
      None
    });
    match checkerror {
      Some(err) => {return Err(err);}
      None => ()
    };
 

    if id.len() == 0 
    || from.len() == 0 
    || (contentids.len() == 0 && content.len() == 0)
    {
      Err(("Invalid striple decoding".to_string(), ErrorKind::DecodingError))
    } else {
      Ok(StripleRef{
        contentenc : contentenc,
        id : id,
        from : from,
        sig : sig,
        about : about,
        key : key,
        contentids : contentids,
        content : content,

        phtype : PhantomData,
      })
    }
  }
 

}


/// Trait for structure that could be use as an striple.
/// A structure can contain multiple striple, that is why the trait is parametric.
/// TODO user example
trait AsStriple<'a, T : StripleKind>  {
  type Target : StripleIf<T>;
  fn as_striple(&'a self) -> Self::Target;
}

/// Getting an striple with it own memory from ref striple
impl<'a, T : StripleKind> AsStriple<'a, T> for StripleRef<'a,T> {
  type Target = Striple<T>;
  fn as_striple(&'a self) -> Striple<T> {
    let contentids = self.contentids.iter().map(|r|r.to_vec()).collect();

 
    Striple {
        contentenc : self.contentenc.to_vec(),
        id : self.id.to_vec(),
        from : self.from.to_vec(),
        sig : self.sig.to_vec(),
        about : self.about.to_vec(),
        key : self.key.to_vec(),
        contentids : contentids,
        content : self.content.to_vec(),

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
        content : &self.content,

        phtype : PhantomData,
    }


  }
}




#[cfg(feature="serialize")]
/// Most of the time serialize is use on another struct (implementing `AsStriple` trait), this only represent the serialization of
/// the byte form of an striple
impl<T : StripleKind> Encodable for Striple<T> {
  fn encode<S:Encoder> (&self, s: &mut S) -> Result<(), S::Error> {
    self.striple_ser().encode(s)
  }
}

// TODO test on this (not good)
#[cfg(feature="serialize")]
impl<T : StripleKind> Decodable for Striple<T> {
  fn decode<D:Decoder> (d : &mut D) -> Result<Striple<T>, D::Error> {
    let tmpres = Vec::decode(d);
    // Dummy type
    let typednone : Option<&Striple<T>> = None;
    tmpres.and_then(|vec| 
      Self::striple_dser(&vec, typednone).map(|r|r.as_striple()).map_err(|err|
        d.error(&format!("{:?}",err))
      )
    )
  }
}

/// striple Error type TODO impl Display trait
pub type Error = (String, ErrorKind);


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

    let wrnbbyte = ((nbbytes - nbbyte)).to_u8().unwrap() ^ 128;
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

      res.push_all(&v[8 - nbbytes .. 8]);
  };

  res
}

/// tool function to get a size as standard rust usize from xtensize in 
/// bytes at a certain position for a designed size.
/// The function update index value
pub fn xtendsizedec(bytes : &[u8], ix : &mut usize, nbbyte : usize) -> usize {
  let mut res : usize = 0;
  let mut nbbytes = nbbyte;
  let mut idx = *ix;
  let mut adj_ix = 0;
  // read value
  while bytes[idx] > 127 {
    // first byte minus its first bit
    adj_ix += (bytes[idx] ^ 128).to_usize().unwrap();
    println!("adjix {:?} !!!",adj_ix);
    nbbytes += adj_ix;
    idx += 1;
  }
  res = unsafe {
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

// get nbbyte for a value
// TODO precalc iteration in table
fn calcnbbyte(val : usize) -> usize {
  let mut res = 0;
  for i in (0 .. 8) {
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
    res.push_all(&xtendsize(tmplen,1));
    res.push_all(content);
}

#[inline]
/// The function update index value
pub fn read_id<'a> (bytes : &'a[u8], ix : &mut usize) -> &'a[u8] {
  let s = xtendsizedec(bytes, ix, 1);
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
  DecodingError,
  UnexpectedStriple,
}

// feature related implementation of serialize (using standard ser meth of striple) : to avoid
// redundant def (type alias...).

#[cfg(test)]
pub mod test {
  extern crate rand;
  use self::rand::Rng;
  use std::marker::PhantomData;
  use striple::Striple;
  use striple::StripleIf;
  use striple::AsStriple;
  use striple::StripleKind;
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
    fn sign_content(pri : &[u8], _ : &[u8]) -> Vec<u8> {
      // Dummy : just use pri
      pri.to_vec()
    }
    fn check_content(publ : &[u8],_ : &[u8],sig : &[u8]) -> bool {
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



  #[test]
  fn test_striple_enc_dec () {
    let common_id = random_bytes(4);
    let common_id_2 = random_bytes(2);
    let ori_1 : Striple<TestKind1> = 
    Striple {
        contentenc : vec!(),
        id : common_id.clone(),
        from : common_id_2.clone(),
        sig : common_id.clone(),
        about : vec!(),
        key : vec!(0),
        contentids : vec!(vec!(8,9)),
        content : vec!(),

        phtype : PhantomData,
    };
    let ori_2 : Striple<TestKind1> = 
    Striple {
        contentenc : vec!(),
        id : common_id_2.clone(),
        from : vec!(),
        sig : common_id_2.clone(),
        about : vec!(),
        key : vec!(0),
        contentids : vec!(),
        content : vec!(),

        phtype : PhantomData,
    };
    let ori_ref_1 = ori_1.as_striple();
    let encori_1 = ori_1.striple_ser();
    debug!("Encoded : \n{:?}",encori_1);
    let typednone : Option<&Striple<TestKind1>> = Some(&ori_2);
    let dec1_ref = Striple::striple_dser(&encori_1, typednone).unwrap();
    let dec1 : Striple<TestKind1> = dec1_ref.as_striple();
    assert_eq!(compare_striple(&ori_1,&dec1), true);
    let encori_ref_1 = ori_ref_1.striple_ser();
    assert_eq!(encori_1,encori_ref_1);

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
    let cont_1 = &vec!(1,2,3,4);
    let cont_2 = &vec!();
    let sig_1 = S::sign_content(&kp1.1, cont_1);
    let sig_2 = S::sign_content(&kp2.1, cont_2);

    // public of keypair unique (because include in content)
    assert!(kp1.0 != kp2.0);
    // public is same as private
    assert!(kp1.0 == kp1.1);
    assert!(kp2.0 == kp2.1);
 
    // check content does depend on from keypair (from must be added to content if hashing scheme)
    assert!(S::check_content(&kp1.0, cont_1, &sig_1));
    assert!(!S::check_content(cont_1, cont_1, &sig_1));
    // and sig validate content
    assert!(!S::check_content(&kp2.0, cont_2, cont_2));

    // signing do not have salt (uniqueness by keypair pub in content).
    assert!(S::sign_content(&kp1.1, cont_1) == sig_1);
    assert!(S::sign_content(&kp2.1, cont_2) == sig_2);

  }

  fn pri_sign<S : SignatureScheme> () {
    let kp1 = S::new_keypair();
    let kp2 = S::new_keypair();
    let cont_1 = &vec!(1,2,3,4);
    let cont_2 = &vec!(1,2,3,4,5);
    let sig_1 = S::sign_content(&kp1.1, cont_1);
    let sig_2 = S::sign_content(&kp2.1, cont_2);

    // keypair unique
    assert!(kp1.0 != kp2.0);
    assert!(kp1.1 != kp2.1);
    // and asym
    assert!(kp1.0 != kp1.1);

    // signature never empty
    assert!(S::sign_content(&kp1.1[..], cont_1) != &vec!()[..]);
    assert!(S::sign_content(&kp2.1[..], cont_1) != &vec!()[..]);

    // signing must have salt : no since different public key in content
    // assert!(S::sign_content(&kp1.1[..], cont_1) != sig_1);
    // assert!(S::sign_content(&kp2.1[..], cont_2) != sig_2);

    // check content only when finely signed
    assert!(!S::check_content(&kp1.0[..], cont_1, &vec!(4)[..]));
    assert!(S::check_content(&kp1.0[..], cont_1, &sig_1[..]));
    assert!(S::check_content(&kp2.0[..], cont_2, &sig_2[..]));
  }

  // test for chaning integrity, construct a K1 root then K1 and K2 son then for K2 K1 and K2 son.
  // With test for altering integrity (mut striple).
  pub fn chaining_test<K1 : StripleKind, K2 : StripleKind> () {
    let contentenc = random_bytes(99);
    let recrootsign : Option<&(&Striple<K1>, &[u8])> = None;
    let ownedroot : (Striple<K1>, Vec<u8>) = Striple::new(
      contentenc.clone(),
      recrootsign,
      None,
      Vec::new(),
      random_bytes(333)
    );
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
      vec!(),
    );
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
      vec!(5,2),
    );
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
      vec!(5,2),
    );
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
      vec!(5,2),
    );
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
      vec!(5,2),
    );
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
    tmp2.content = unknown_vec.clone();
    assert!(!tmp2.check(&son2));
    tmp1.content = unknown_vec.clone();
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
  fn random_bytes(size : usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut bytes = vec![0; size];
    rng.fill_bytes(&mut bytes);
    bytes
  }

  /// comparison of well formed striple should only use key
  /// this is more of an utility for debugging and testing
  pub fn compare_striple<K1 : StripleKind, K2 : StripleKind> (st1 : &Striple<K1>, st2 : &Striple<K2>) -> bool {
    <K1 as StripleKind>::get_algo_key() == <K2 as StripleKind>::get_algo_key()
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
      (st1.about.len() == 0 && st1.from == st2.about) ||
      (st2.about.len() == 0 && st2.from == st1.about)
      )
    && st1.key == st2.key
    && st1.contentids == st2.contentids
    && st1.content == st2.content
  }

}



