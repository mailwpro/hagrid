extern crate anyhow;
extern crate clap;
extern crate indicatif;
extern crate sequoia_openpgp as openpgp;
extern crate serde_derive;

use std::path::PathBuf;

use anyhow::Result;

use clap::{App, Arg, SubCommand};

mod generate;

fn main() -> Result<()> {
    let matches = App::new("Hagrid Tester")
        .version("0.1")
        .about("Control hagrid database externally")
        .arg(
            Arg::with_name("config")
                .short("c")
                .long("config")
                .value_name("FILE")
                .help("Sets a custom config file")
                .takes_value(true),
        )
        .subcommand(
            SubCommand::with_name("generate")
                .about("Generate a test set of certificates")
                .arg(
                    Arg::with_name("cert count")
                        .long("cert-count")
                        .default_value("100000")
                        .help("number of certifictes to generate"),
                )
                .arg(
                    Arg::with_name("certs output file")
                        .long("output-file")
                        .default_value("keyring.pub.pgp")
                        .help("path to file to store the certificates in"),
                )
                .arg(
                    Arg::with_name("fingerprints output file")
                        .long("fingerprints-file")
                        .default_value("fingerprints.txt")
                        .help("path to file to store fingerprints in"),
                ),
        )
        .get_matches();

    if let Some(matches) = matches.subcommand_matches("generate") {
        let count: u64 = matches.value_of("cert count").unwrap().parse().unwrap();
        let output_certs: PathBuf = matches
            .value_of("certs output file")
            .unwrap()
            .parse()
            .unwrap();
        let output_fprs: Option<PathBuf> = matches
            .value_of("fingerprints output file")
            .map(|s| s.parse().unwrap());
        generate::do_generate(count, output_certs.as_path(), output_fprs.as_ref().map(|f| f.as_path()))?;
    } else {
        println!("{}", matches.usage());
    }

    Ok(())
}
