//!
//! TODO doc normalize command
//! Command line utils.
//! disp : show striple TODO multi input plus id resolution ...
//! -in an input file
//! -ix ix of striple to display from file
//! -out cat result to file
//! -ciph cipher for writing in out (default to NoCypher for now) 
//! 
//! recode : read and write with other ciph
//! -in an input file
//! -out an output file
//! -ciph cipher
//!
//! cp : copy striple to another file
//! -in from file
//! -out to file
//! -ix from index
//! -toix to index (default end of file)
//! -ciph  (optional, default to NoCypher, could change all cypher of outfile)
//!
//! rm : remove striple from a file
//! -out from file
//! -ix rm index
//! -ciph  (optional, default to NoCypher, could change all cypher of outfile)
//!
//! create : create new striple TODO add base64 id param + encid + typeid
//! -in from file
//! - fromix
//! - aboutix
//! - contentix (multiple possible)
//! - content : String utf8
//! - contentfile : get file as bin from file (conflict with content)
//! - fromfile : another input file for from (optional)
//! - aboutfile : another input file for from
//! - fromin : optional if from from another file
//! - recursive : about is ourselve (conflict with...)
//! - fullrecursive : about and from are ourselve (conflict with...)
//! -out out to file instead of stdout
//! -outix if out in xisting file
//! -ix rm index
//! -ciph  (optional, default to NoCypher, could change all cypher of outfile)
//!
//! 
//!  

fn main() {
}
