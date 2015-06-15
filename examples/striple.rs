//!
//! TODO doc normalize command
//! Command line utils.
//!
//! This is define as an example but should be moved to its own crate for building.
//!
//! It is not define as an executable of the library because it should be rewrite to include more
//! striplekinds, and specific environnement capabilities.
//!
//! index in command start at 1
//!
//!  TODO replace all "_" and "__" files with true temporary files
//!  


#![feature(collections)] // only use for a push_all : TODO remove when better extend
#![feature(plugin)]
#![plugin(docopt_macros)]
extern crate docopt;

extern crate striple;
extern crate num;
#[cfg(feature="serialize")]
extern crate rustc_serialize;
extern crate env_logger;

#[cfg(feature="serialize")]
use rustc_serialize::base64::ToBase64;
#[cfg(feature="serialize")]
use rustc_serialize::base64::FromBase64;
use std::fs::{File,OpenOptions};
use std::fs;
use std::path;
use std::io::{Read,Write,Seek,SeekFrom};
use striple::anystriple::{AnyStriple, copy_builder_any};
use striple::striple::{BCont,NoKind,StripleDisp, StripleIf,Striple, StripleRef};
#[cfg(feature="serialize")]
use striple::striple::BASE64CONF;
use striple::striple::Error as StripleError;
use striple::storage::{FileMode,FileStripleIterator,StorageCypher,write_striple,Pbkdf2,AnyCyphers};
use std::io::Result as IOResult;
use std::result::Result as StdResult;
use std::io::{stdin,BufRead};
use num::traits::ToPrimitive;
use striple::storage::{write_striple_file,write_striple_file_ref,NoCypher,RemoveKey,init_any_cipher_stdin,init_any_cypher_with_pass,init_noread_key};


#[cfg(feature="serialize")]
docopt!(Args derive Debug, "
Usage: 
striple disp (-i <file> | - ) [--inpass <inpass>]  [-x <ix>]...
striple id64 [from | about | content | kind | enc] (-i <file> | - ) [--inpass <inpass>] [-x <ix>]...
striple cp (-i <file> | - ) [--inpass <inpass>] [-x <ix>]... (-o <file>) [--outpass <outpass>] [--ox <outix>] [--relative | --absolute | --nofile] [--conttreshold <conttreshold>]
striple rm -i <file> [--inpass <inpass>] [-x <ix>]...
striple rewrite  (-i <file> | - ) [--inpass <inpass>] [-o <file>] [-c <cipher>] [--outpass <outpass>] [--relative | --absolute | --nofile] [--conttreshold <conttreshold>]
striple check (-i <file> | - ) (-x <ix>) [--inpass <inpass>] [--fromfile <fromfile>] [-x <ix>]...
striple create [--encfile <encfile> -x <ix> | --encid <encid>] (--kindfile <kindfile> -x <ix> | --kindid <kindid>) [--fromfile <fromfile> -x <ix> [--frompass <frompass>]] [--aboutfile <aboutfile> -x <ix> | --aboutid <aboutid>] (--contentfile <contentfile> | --content <content> | (--contentid <contentid>)... | - ) [-o <file>] [-c <cipher>] [--outpass <outpass>] [--ox <outix>] [--relative | --absolute | --nofile] [--conttreshold <conttreshold>]

striple -h
striple -V

Options: 
-h --help   Show this screen
-i --in <file>
-x --ix <ix>  Indexes to use. Depending on usecase it is for first file or for matching index files. Index in command start at 1.
--inpass <inpass>  Input passphrase. For multiple pass they match multiple input file indexes stdin being last index
-o --out <file>
--ox <outix>  Indexes to use for output when output in an existing file.[default: 0]
--relative  File and big content could be written in a relative way
--absolute  File and big content could be written in an absolute way
--conttreshold <conttreshold>   In big content may be written to file if bigger than this treshold and file mode allows it [default: 0]
--nofile  Attached file are forced into the storage
--outpass <outpass>  Output passphrase.
-c --cipher <cipher>   Cipher to use for output (PBKDF2, NoCipher, RemoveKey...) [default: PBKDF2]
--content <content>  Content as simple string, for byte content use stdin
--contentid <contentid>  Base64 encoded contentid
-V --version
", flag_ix : Vec<usize>, flag_ox : usize, flag_conttreshold : usize);

fn main() {

  // activate env_logger
  env_logger::init().unwrap();
  
  run()
}

#[cfg(not(feature="serialize"))]
fn run() {
//  println!("{:?}", args);
  println!("missing required features");
}
#[cfg(feature="serialize")]
fn run() {
  let args: Args = Args::docopt().decode().unwrap_or_else(|e| e.exit());
//  println!("{:?}", args);
  if !args.cmd_create {
  let readseek = if args.flag_in.len() > 0 {
    File::open(&args.flag_in).unwrap()
  } else {
    println!("Reading form piped input not implemented yet");
    return()
  };
  let mut rit :  IOResult<FileStripleIterator<NoKind,AnyStriple,_,_,_>>  = if args.flag_inpass.len() > 0 {
    FileStripleIterator::init(readseek, copy_builder_any, &init_any_cypher_with_pass, args.flag_inpass.clone())
  } else {
    FileStripleIterator::init(readseek, copy_builder_any, &init_any_cipher_stdin, ())
  };
  let mut it = rit.unwrap();
  // default single ix to first striple (usecase is file with one striple only)
  let ix = if args.flag_ix.len() > 0 {
    args.flag_ix[0]
  } else {
    1
  };
 
  match (args.cmd_disp, args.cmd_id64, args.cmd_cp,args.cmd_rm,args.cmd_rewrite,args.cmd_check) {
   (true,_,_,_,_,_) => {
     //disp
    if args.flag_ix.len() > 0 {
      for i in args.flag_ix.iter() {
      let s : IOResult<(AnyStriple,Option<Vec<u8>>)> = it.get(i - 1);
        show_it(s.unwrap(), *i);
      }
    } else {
      // disp all
      for s in it {
        show_it(s, 0);
      }
    };
   },
   (_,true,_,_,_,_) => {
     //id64
    let s : IOResult<(AnyStriple,Option<Vec<u8>>)> = it.get(ix - 1);
     match (args.cmd_from, args.cmd_about, args.cmd_content,args.cmd_kind,args.cmd_enc) {
       (true,_,_,_,_) => print!("{}", s.unwrap().0.get_from().to_vec().to_base64(BASE64CONF)),
       (_,true,_,_,_) => print!("{}", s.unwrap().0.get_about().to_vec().to_base64(BASE64CONF)),
       (_,_,true,_,_) => {
         let ids : Vec<&[u8]> = s.as_ref().unwrap().0.get_content_ids();
         if args.flag_ix.len() > 1 {
           if ids.len() > args.flag_ix[1] {
             print!("{}", ids[args.flag_ix[1]].to_vec().to_base64(BASE64CONF))
           }
         } else {
           if ids.len() > 0 {
             print!("{}", ids[0].to_vec().to_base64(BASE64CONF))
           }
         }
       },
       (_,_,_,true,_) => print!("{}", s.unwrap().0.get_algo_key().to_vec().to_base64(BASE64CONF)),
       (_,_,_,_,true) => print!("{}", s.unwrap().0.get_enc().to_vec().to_base64(BASE64CONF)),
       _ => print!("{}", s.unwrap().0.get_id().to_vec().to_base64(BASE64CONF)),
     }
  },

   (_,_,true,_,_,_) => {
     //cp
     if args.flag_ix.len() == 0 {
       copy_iter(&args, it);
     } else {
       let mut v = Vec::new();
       for ix in args.flag_ix.iter() {
         v.push(it.get(*ix -1).unwrap());
       };
       copy_vec_oriter(&args, v, Some(it.1));
     };
  },
  (_,_,_,true,_,_) => {
    //rm
    let tmppath = args.flag_in.clone() + "_";
    let mut out = File::create(&tmppath).unwrap();
    let endpos = it.0.metadata().unwrap().len();
    let mut sortflag = args.flag_ix.clone();
    println!("dtad{:?}", sortflag);
    sortflag.sort();
    let mut pos : u64 = 0;
    sortflag.iter().map(|ix|*ix-1).fold((),|_,ix|{
    println!("dtd");
      it.0.seek(SeekFrom::Start(pos));
      let r = it.get_entryposlength(ix).unwrap();
      buff_copy(&mut it.0, &mut out, (r.0 - pos).to_usize().unwrap());
      pos = r.0 + r.1.to_u64().unwrap();
    });
    it.0.seek(SeekFrom::Start(pos));
    buff_copy(&mut it.0, &mut out, (endpos - pos).to_usize().unwrap());

    // unsafe
    fs::rename(&tmppath,&args.flag_in).unwrap();
  },
   (_,_,_,_,true,_) => {
     //rewrite
    let mut out = File::create(&args.flag_out).unwrap();
    let fm = parse_cmd_filemode(&args);
    match &args.flag_cipher {
      i if (i == "PBKDF2") => {
        let pbk = initpkbdf2(args.flag_outpass.clone());
        write_striple_file(&pbk, &mut it, &fm, &mut out).unwrap()
      },
      i if (i == "NoCipher") => write_striple_file(&NoCypher, &mut it, &fm,  &mut out).unwrap(),
      i if (i == "RemoveKey") => write_striple_file(&RemoveKey, &mut it, &fm, &mut out).unwrap(),
      _ => {println!("Unknown cipher");},
    }
  },
   (_,_,_,_,_,true) => {
     //check
     let to_check = it.get(ix - 1).unwrap().0;
     let fromid = to_check.get_from();
     let mut fromfile = File::open(&args.arg_fromfile).unwrap();
     let mut rfromit = FileStripleIterator::init(fromfile, copy_builder_any, &init_noread_key, ());
     let mut fromit = rfromit.unwrap();
     let ofrom = if args.flag_ix.len() > 1 {
       fromit.get(args.flag_ix[1] - 1).ok()
     } else {
       fromit.find (|f|f.0.get_id() == fromid)
     };
     match ofrom {
       Some(ref from) => {
         if(to_check.check(&from.0)) {
           println!("check ok");
         } else {
           println!("striple does not check");
         };
       },
       None => {
         println!("No matching origin/from found for check");
       },
     }
   },
   _ => {
     println!("missing command");
   },
  }}
  else {

   let mut ixnb = 0;
   let encid = if args.flag_encid {
    args.arg_encid.from_base64().unwrap()
   } else {
     if args.flag_encfile {
     let mut encfile = File::open(&args.arg_encfile).unwrap();
     let mut encit = FileStripleIterator::init(encfile, copy_builder_any, &init_noread_key, ()).unwrap();
     let enc = encit.get(args.flag_ix[ixnb] - 1).unwrap();
     ixnb += 1;
     enc.0.get_id().to_vec()
     } else {
       vec!()
     }
   };
   let kindid = if args.flag_kindid {
    args.arg_kindid.from_base64().unwrap()
   } else {
     let mut kindfile = File::open(&args.arg_kindfile).unwrap();
     let mut kindit = FileStripleIterator::init(kindfile, copy_builder_any, &init_noread_key, ()).unwrap();
     let kind = kindit.get(args.flag_ix[ixnb] - 1).unwrap();
     ixnb += 1;
     kind.0.get_id().to_vec()
   };
   let fromix = if args.flag_fromfile {
   ixnb += 1;
   args.flag_ix[ixnb - 1] - 1
   }else{0};

   let aboutid = if args.flag_aboutid {
    Some(args.arg_aboutid.from_base64().unwrap())
   } else {
     if args.flag_aboutfile {
     let mut aboutfile = File::open(&args.arg_aboutfile).unwrap();
     let mut aboutit = FileStripleIterator::init(aboutfile, copy_builder_any, &init_noread_key, ()).unwrap();
     let about = aboutit.get(args.flag_ix[ixnb] - 1).unwrap();
     ixnb += 1;
     Some(about.0.get_id().to_vec())
     } else {
       None
     }
   };

   let contentids = args.flag_contentid.iter().map(|c|c.from_base64().unwrap()).collect();

   let content = if args.flag_contentfile {
     // TODO add option to get BCont file instead of load
     if args.flag_relative || args.flag_absolute {
       let fileexists = fs::metadata(&args.arg_contentfile).map(|f|f.is_file()).unwrap_or(false);
       if fileexists {
         Some(BCont::LocalPath(path::PathBuf::from(&args.arg_contentfile)))
       } else {
         panic!("Invalid content file for striple creation")
       }
     } else {

       let mut contentfile = File::open(&args.arg_contentfile).unwrap();
       let mut res = Vec::new();
       contentfile.read_to_end(&mut res);
       Some(BCont::OwnedBytes(res))
     }
   } else {
     if args.flag_content.len() > 0 {
       Some(BCont::OwnedBytes(args.flag_content.from_base64().unwrap()))
     } else {
       None
     }
   };
   let ofrom = if args.flag_fromfile {
     let mut fromfile = File::open(&args.arg_fromfile).unwrap();
     let mut rfromit = if args.flag_frompass {
       FileStripleIterator::init(fromfile, copy_builder_any, &init_any_cypher_with_pass, args.arg_frompass.clone())
     } else {
       FileStripleIterator::init(fromfile, copy_builder_any, &init_any_cipher_stdin, ())
     };
     let mut fromit = rfromit.unwrap();
     let from = fromit.get(fromix).unwrap();
     if from.0.is_public() {
       let pk = from.0.get_key().to_vec();
        Some((from.0, pk))
     } else {
       match from.1 {
         Some(pass) => {
       if pass.len() == 0 {
         panic!("Origin cannot initiate a new striple (not owned)")
       } else {
         Some((from.0, pass))
       }
         },
         None => panic!("Origin cannot initiate a new striple (not owned)"),
      }
    }
   } else {
     None
   };
   let ownedStriple : (AnyStriple, Vec<u8>) = AnyStriple::new(
      &kindid[..],
      encid,
      ofrom.as_ref(),
      aboutid,
      contentids,
      content,
   ).unwrap();
   if args.flag_out.len() > 0 {
     let mut contents = Vec::new();
     contents.push((ownedStriple.0,Some(ownedStriple.1)));
     copy_vec_oriter(&args, contents, None);
   } else {
     // out on stdout as base64 : key then striple
     println!("{}", ownedStriple.1.to_base64(BASE64CONF));
     let mut sser = ownedStriple.0.striple_ser();
     match &sser.1 {
       &Some(ref bcon)=> {
         // TODO buff the out (just complete to be multiple of (see base64 padding)
         sser.0.push_all(&bcon.get_byte().unwrap()[..]);
       },
       &None => (),
     };
     print!("{}", sser.0.to_base64(BASE64CONF));
     
   }
  }



}


#[cfg(feature="serialize")]
fn show_it(toshow : (AnyStriple,Option<Vec<u8>>), ix : usize) {
  if ix == 0 {
    println!("- : {}", StripleDisp(&toshow.0));

  }else {
    println!("-{}: {}", ix, StripleDisp(&toshow.0));
//    println!("{:?}", toshow.0.get_id());
  }
  toshow.1.map(|pass| println!("Private key present"));

}

// find a lib to replace (see evo of io)...
fn buff_copy<R : Read, W : Write> (from : &mut R, to : &mut W, size : usize) -> IOResult<()> {
  let mut buff = &mut [0;4096];
  let nbit = size / 4096;
  let rembit = size - nbit * 4096;
  for _ in 0 .. nbit {
    try!(from.read(buff));
    try!(to.write(buff));
  };
  let mut lastbuff = &mut buff[0..rembit];
  try!(from.read(lastbuff));
  try!(to.write(lastbuff));
  Ok(())

}

#[cfg(feature="opensslpbkdf2")]
fn initpkbdf2 (outpass : String) -> Pbkdf2 {
        let pass = if outpass.len() > 0 {
          outpass
        } else {
        println!("writing as protected, please input passphrase ?");
        let mut tstdin = stdin();
        let mut stdin = tstdin.lock();
        let mut pass = String::new();
        stdin.read_line(&mut pass);
        // remove terminal \n
        pass.pop();
        pass
        };
        Pbkdf2::new(pass,2000,None)

}

#[cfg(not(feature="opensslpbkdf2"))]
fn initpkbdf2 (_ : String) -> RemoveKey {
  println!("No implementation for pbkdf2, removing keys");
  RemoveKey
}

fn parse_cmd_filemode(arg : &Args) -> FileMode {
  let ct = if arg.flag_conttreshold == 0 {
    Some(arg.flag_conttreshold)
  } else {
    None
  };
  if arg.flag_relative {
    return FileMode::Relative(None);
  };
  if arg.flag_absolute {
    return FileMode::Absolute(None);
  };
  if arg.flag_nofile {
    return FileMode::NoFile;
  };
  FileMode::Idem
}
#[cfg(feature="serialize")]
fn copy_iter<B> (args : &Args, it :FileStripleIterator<NoKind, AnyStriple, File, AnyCyphers, B>)
where B :  Fn(&[u8], StripleRef<NoKind>) -> StdResult<AnyStriple, StripleError>
{ 
  let fm = parse_cmd_filemode(args);
  let mut out = OpenOptions::new().read(true).write(true).append(true).truncate(false).create(true).open(&args.flag_out).unwrap();
  fs::copy(&args.flag_out, args.flag_out.clone() + "_");
  let initiallen = out.metadata().unwrap().len();
  if initiallen > 0 {
    let mut rot : IOResult<FileStripleIterator<NoKind,AnyStriple,_,_,_>>  = if args.flag_outpass.len() > 0 {
      FileStripleIterator::init(out, copy_builder_any, &init_any_cypher_with_pass, args.flag_outpass.clone())
    } else {
      FileStripleIterator::init(out, copy_builder_any, &init_any_cipher_stdin, ())
    };
    let mut ot = rot.unwrap();
    let splitpos = if args.flag_ox > 0 {
      ot.get_entryposlength(args.flag_ox - 1).unwrap().0
    }else{0};

    for mos in it {
      write_striple(&ot.1,&mos.0,mos.1.as_ref().map(|pk|&pk[..]), &fm, &mut ot.0).unwrap();
    };
    if args.flag_ox > 0 {
      let mut out = &mut File::create(args.flag_out.clone() + "__").unwrap();
      let from = &mut ot.0;
      let usplit = splitpos.to_usize().unwrap();
      let finallen = from.metadata().unwrap().len();
      from.seek(SeekFrom::Start(0));
      buff_copy(from, out, usplit);
      from.seek(SeekFrom::Start(initiallen));
      buff_copy(from, out, (finallen - initiallen).to_usize().unwrap());
      from.seek(SeekFrom::Start(splitpos));
      buff_copy(from, out, (initiallen - splitpos).to_usize().unwrap());
      fs::rename(args.flag_out.clone() + "__",args.flag_out.clone()).unwrap();
    }; 
  } else {
    fs::copy(&args.flag_in, &args.flag_out);
  };
}

#[cfg(feature="serialize")]
fn copy_vec_oriter (args : &Args, contents : Vec<(AnyStriple,Option<Vec<u8>>)>, it : Option<AnyCyphers>)
  {
    let fm = parse_cmd_filemode(args);
    let mut out = OpenOptions::new().read(true).write(true).append(true).truncate(false).create(true).open(&args.flag_out).unwrap();
    fs::copy(&args.flag_out, args.flag_out.clone() + "_");
    let initiallen = out.metadata().unwrap().len();
    if initiallen > 0 {
      let mut rot : IOResult<FileStripleIterator<NoKind,AnyStriple,_,_,_>>  = if args.flag_outpass.len() > 0 {
         FileStripleIterator::init(out, copy_builder_any, &init_any_cypher_with_pass, args.flag_outpass.clone())
      } else {
         FileStripleIterator::init(out, copy_builder_any, &init_any_cipher_stdin, ())
      };
      let mut ot = rot.unwrap();
      let splitpos = if args.flag_ox > 0 {
         ot.get_entryposlength(args.flag_ox - 1).unwrap().0
      }else{0};

      for mos in contents {
        write_striple(&ot.1,&mos.0,mos.1.as_ref().map(|pk|&pk[..]),&fm,&mut ot.0).unwrap();
      };
      if args.flag_ox > 0 {
        let mut out = &mut File::create(args.flag_out.clone() + "__").unwrap();
        let from = &mut ot.0;
        let usplit = splitpos.to_usize().unwrap();
        let finallen = from.metadata().unwrap().len();
        from.seek(SeekFrom::Start(0));
        buff_copy(from, out, usplit);
        from.seek(SeekFrom::Start(initiallen));
        buff_copy(from, out, (finallen - initiallen).to_usize().unwrap());
        from.seek(SeekFrom::Start(splitpos));
        buff_copy(from, out, (initiallen - splitpos).to_usize().unwrap());
        fs::rename(args.flag_out.clone() + "__",args.flag_out.clone()).unwrap();
      }; 
    } else {
      let ciph = match it {
        Some(i) => i,
        None => {
          match &args.flag_cipher {
            i if (i == "PBKDF2") => {
              AnyCyphers::Pbkdf2( initpkbdf2(args.flag_outpass.clone()))
            },
            i if (i == "NoCipher") => AnyCyphers::NoCypher(NoCypher),
            _ => {panic!("Unknown cipher (required for new file output)")},
          }
        },
      };
      write_striple_file(&ciph, &mut contents.into_iter(), &fm, &mut out).unwrap()
      //out.write(&ciph.get_cypher_header()).unwrap();
     /* for mos in contents.iter() {
        write_striple(&ciph,&mos.0,mos.1.as_ref().map(|pk|&pk[..]),&mut out).unwrap();
          // copy (byte directly for unknow kind)
 //         let mos = it.get_asbyte(*ix).unwrap();
 //         out.write(&mos[..]);
      }*/
    };
}
