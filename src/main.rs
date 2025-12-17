use camino::Utf8PathBuf;
use clap::{Parser, ValueEnum};
use sha2::Digest;
use std::io::{self};

/// An enumeration of possible hash algorithms supported by this program.
#[derive(Debug, ValueEnum, Clone)]
enum DigestType {
    /// Calculate the SHA256 hash for each file
    SHA256,
    /// Calculate the SHA512 hash for each file
    SHA512,
}

/// Relevant data about files passed to this program on the command line.
#[derive(Debug)]
struct CheckedFile {
    /// This [`camino::Utf8PathBuf`] contains a file path as passed on the command line.
    file_path: Utf8PathBuf,
    /// Ok(()) indicates the path points to a file ([`camino::Utf8PathBuf.is_file()`] returned true).
    /// Err(msg) indicates the path is a directory or some other non-file.
    hashable: Result<(), String>,
}

impl CheckedFile {
    /// Checks the file pointed to by `path` to determine whether it's a regular file.
    ///
    /// See [`camino::Utf8PathBuf`] for more details.
    ///
    /// # Errors
    ///
    /// This function will return an error if `path` is a directory or some other non-file.
    fn new(path: &Utf8PathBuf) -> Self {
        if path.is_file() {
            CheckedFile {
                file_path: path.clone(),
                hashable: Ok(()),
            }
        } else if path.is_dir() {
            CheckedFile {
                file_path: path.clone(),
                hashable: Err(format!("{}: is a directory, not a file", path)),
            }
        } else {
            CheckedFile {
                file_path: path.clone(),
                hashable: Err(format!("{}: is not a directory or a file", path)),
            }
        }
    }
}

#[derive(Parser)]
#[command(version, about="Calculate a cryptographic hash for one or more files.", long_about = None)]
struct Cli {
    /// The cryptographic hash to be calculated
    #[arg(value_enum, short, long)]
    digest: DigestType,
    /// The file(s) for which the hash should be calculated
    #[arg(value_name="FILE", value_hint=clap::ValueHint::FilePath)]
    filename: Vec<Utf8PathBuf>,
}

fn main() {
    let args = Cli::parse();

    let checked_files = args
        .filename
        .iter()
        .map(CheckedFile::new)
        .collect::<Vec<CheckedFile>>();

    hash_files(&checked_files, &args.digest);
}

fn hash_files(files: &Vec<CheckedFile>, digest: &DigestType) {
    for file in files {
        let CheckedFile {
            file_path: path_buf,
            hashable: result,
        } = file;
        match result {
            Ok(()) => hash_file(path_buf, digest),
            Err(err) => eprintln!("{}: unable to hash this file", err),
        }
    }
}

fn hash_file(path_buf: &Utf8PathBuf, digest: &DigestType) {
    match perform_hash(path_buf, digest) {
        Ok(hash_value) => println!("{}: {}", hash_value, path_buf),
        Err(e) => println!("{}: error during hashing: {}", path_buf, e),
    }
}

fn perform_hash(path_buf: &Utf8PathBuf, digest: &DigestType) -> std::io::Result<String> {
    match digest {
        DigestType::SHA256 => calculate_hash::<sha2::Sha256>(path_buf),
        DigestType::SHA512 => calculate_hash::<sha2::Sha512>(path_buf),
    }
}

fn calculate_hash<D: Digest + std::io::Write>(path_buf: &Utf8PathBuf) -> std::io::Result<String> {
    let mut file = std::fs::File::open(path_buf)?;
    let mut hasher = D::new();
    let _n = io::copy(&mut file, &mut hasher)?;
    let finalized_hash = hasher.finalize().to_vec();
    Ok(to_hex_lowercase(&finalized_hash))
}

/// Converts a Vec<u8> into a lowercase hexadecimal string.
///
/// # Example
///
/// ```rust
/// let vec_hash: Vec<u8> = vec![68, 201, 46];
/// assert_eq!(to_hex_lowercase(&vec_hash, String::from("44c92e"));
/// ```
fn to_hex_lowercase(vec_hash: &[u8]) -> String {
    vec_hash.iter().map(|b| format!("{:02x}", b)).collect()
}
