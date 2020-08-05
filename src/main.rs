use std::fs::File;
use std::io::{Read, BufReader, BufRead};
use std::{env, io};
use std::fmt::Error;
use std::array::TryFromSliceError;

const SHA_BUF_LEN: usize = 1;

fn check(checksum_filename: &String) -> io::Result<()> {
    let checksum_file = File::open(checksum_filename).expect("Failed to read checksum file");
    let reader = BufReader::new(checksum_file);
    for reader_line in reader.lines() {
        let line = reader_line.unwrap();
        let vec: Vec<&str> = line.split_whitespace().collect();
        println!("{:?}", vec);

        let file_checksum = match hex::decode(vec[0]) {
            Ok(x) => {
                x
            }
            Err(e) => {
                panic!("Failed to decode sha256 checksum");
            }
        }
        let file_name = vec[1];
        print!("{}\t", file_name);

        let mut hmac = hmac_sha256::Hash::new();

        let mut file = File::open(file_name).expect(&*format!("Failed to find {}", file_name));
        let mut buf = vec![0; SHA_BUF_LEN];
        while file.read(&mut buf)? != 0 {
            hmac.update(&buf);
            buf = vec![0; SHA_BUF_LEN];
        }

        let computed_checksum = hmac.finalize();
        if file_checksum == computed_checksum {
            println!("PASS");
        } else {
            println!("FAIL");
            println!("Read SHA256:     {}", hex::encode(file_checksum));
            println!("Computed SHA256: {}", hex::encode(computed_checksum));
        }
    }

    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        if check(&args[1]).is_err() {
            println!("Failed to check checksums");
        }
    }
}
