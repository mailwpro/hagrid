use std::io::Write;
use std::{fs::File, io, io::BufRead, path::Path};

use anyhow::Result;
use rand::seq::SliceRandom;
use rand::{thread_rng, Rng};

use crate::util;

pub fn do_genreqs(host: &str, fprs_path: &Path) -> Result<()> {
    let file = File::open(fprs_path)?;
    let fingerprints: Vec<String> = io::BufReader::new(file).lines().flatten().collect();

    /* possible requests:
     * /vks/v1/by-fingerprint/
     * /vks/v1/by-keyid/
     * /vks/v1/by-email/
     */

    let mut rng = thread_rng();
    let mut stdout = io::LineWriter::new(io::stdout());
    loop {
        let result = match rng.gen_range(0, 3) {
            0 => {
                let email = util::gen_email(rng.gen_range(0, fingerprints.len() as u64));
                stdout.write_fmt(format_args!(
                    "GET {}/vks/v1/by-email/{}\n",
                    host, email
                ))
            }
            1 => {
                let random_fpr = fingerprints.choose(&mut rng).unwrap();
                stdout.write_fmt(format_args!(
                    "GET {}/vks/v1/by-keyid/{}\n",
                    host,
                    &random_fpr[24..40]
                ))
            }
            _ => {
                let random_fpr = fingerprints.choose(&mut rng).unwrap();
                stdout.write_fmt(format_args!(
                    "GET {}/vks/v1/by-fingerprint/{}\n",
                    host, random_fpr
                ))
            }
        };

        if result.is_err() {
            return Ok(());
        }
    }
}
