#![feature(proc_macro_hygiene, plugin, decl_macro)]
#![recursion_limit = "1024"]

extern crate anyhow;
extern crate clap;
extern crate tempfile;
extern crate sequoia_openpgp as openpgp;
extern crate hagrid_database as database;
#[macro_use]
extern crate serde_derive;
extern crate toml;
extern crate indicatif;
extern crate walkdir;

use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::Result;

use clap::{Arg, App, SubCommand};

mod import;
mod regenerate;
mod updates;

#[derive(Deserialize)]
pub struct HagridConfigs {
    development: HagridConfig,
    staging: HagridConfig,
    production: HagridConfig,
}

// this is not an exact match - Rocket config has more complicated semantics
// than a plain toml file.
// see also https://github.com/SergioBenitez/Rocket/issues/228
#[derive(Deserialize,Clone)]
pub struct HagridConfig {
    _template_dir: Option<PathBuf>,
    keys_internal_dir: Option<PathBuf>,
    keys_external_dir: Option<PathBuf>,
    _assets_dir: Option<PathBuf>,
    _token_dir: Option<PathBuf>,
    tmp_dir: Option<PathBuf>,
    _maintenance_file: Option<PathBuf>,
}

fn main() -> Result<()> {
    let matches = App::new("Hagrid Control")
                          .version("0.1")
                          .about("Control hagrid database externally")
                          .arg(Arg::with_name("config")
                               .short("c")
                               .long("config")
                               .value_name("FILE")
                               .help("Sets a custom config file")
                               .takes_value(true))
                          .arg(Arg::with_name("env")
                               .short("e")
                               .long("env")
                               .value_name("ENVIRONMENT")
                               .takes_value(true)
                               .default_value("prod")
                               .possible_values(&["dev","stage","prod"]))
                          .subcommand(SubCommand::with_name("regenerate")
                                      .about("Regenerate symlink directory"))
                          .subcommand(SubCommand::with_name("import")
                                      .about("Import keys into Hagrid")
                                      .arg(Arg::with_name("dry run")
                                          .short("n")
                                          .long("dry-run")
                                          .help("don't actually keep imported keys")
                                      )
                                      .arg(Arg::with_name("keyring files")
                                           .required(true)
                                           .multiple(true)))
        .subcommand(SubCommand::with_name("updates")
                    .about("Manages Update Manifests")
                    .subcommand(SubCommand::with_name("from-log")
                                .about("Syncs key update log to \
                                        Update Manifests")
                                .arg(Arg::with_name("current-day")
                                     .long("current-day")
                                     .value_name("YYYY-mm-dd")
                                     .default_value("today")
                                     .help("Start syncing from this day \
                                            working backwards"))
                                .arg(Arg::with_name("current-epoch")
                                     .long("current-epoch")
                                     .value_name("EPOCH")
                                     .default_value("current")
                                     .help("Start from this epoch \
                                            working backwards"))
                                .arg(Arg::with_name("keep-going")
                                     .long("keep-going")
                                     .help("Keep going once we reached known \
                                            history")))
                    .subcommand(SubCommand::with_name("check")
                                .about("Checks for consistency")
                                .arg(Arg::with_name("current-epoch")
                                     .long("current-epoch")
                                     .value_name("EPOCH")
                                     .default_value("current")
                                     .help("Start from this epoch \
                                            working backwards")))
                    .subcommand(SubCommand::with_name("recover")
                                .about("Recovers from inconsistencies, \
                                        potentially truncating history")
                                .arg(Arg::with_name("current-epoch")
                                     .long("current-epoch")
                                     .value_name("EPOCH")
                                     .default_value("current")
                                     .help("Start from this epoch \
                                            working backwards")))
                    .subcommand(SubCommand::with_name("compact")
                                .about("Compacts Update Manifests by \
                                        merging buckets")
                                .arg(Arg::with_name("current-epoch")
                                     .long("current-epoch")
                                     .value_name("EPOCH")
                                     .default_value("current")
                                     .help("Start from this epoch \
                                            working backwards")))
                    .subcommand(SubCommand::with_name("gc")
                                .about("Deletes all but the given number of \
                                        Update Manifests")
                                .arg(Arg::with_name("keep")
                                     .long("keep")
                                     .value_name("N")
                                     .default_value("2048")
                                     .help("Keep this many manifests, \
                                            the default being roughly 2 years"))
                                .arg(Arg::with_name("current-epoch")
                                     .long("current-epoch")
                                     .value_name("EPOCH")
                                     .default_value("current")
                                     .help("Start from this epoch \
                                            working backwards"))))
        .get_matches();

    let config_file = matches.value_of("config").unwrap_or("Rocket.toml");
    let config_data = fs::read_to_string(config_file).unwrap();
    let configs: HagridConfigs = toml::from_str(&config_data).unwrap();
    let config = match matches.value_of("env").unwrap() {
        "dev" => configs.development,
        "stage" => configs.staging,
        "prod" => configs.production,
        _ => configs.development,
    };

    if let Some(matches) = matches.subcommand_matches("import") {
        let dry_run = matches.occurrences_of("dry run") > 0;
        let keyrings: Vec<PathBuf> = matches
            .values_of_lossy("keyring files")
            .unwrap()
            .iter()
            .map(|arg| PathBuf::from_str(arg).unwrap())
            .collect();
        import::do_import(&config, dry_run, keyrings)?;
    } else if let Some(_matches) = matches.subcommand_matches("regenerate") {
        regenerate::do_regenerate(&config)?;
    } else if let Some(matches) = matches.subcommand_matches("updates") {
        let db = database::KeyDatabase::new_internal(
            config.keys_internal_dir.as_ref().unwrap(),
            config.keys_external_dir.as_ref().unwrap(),
            config.tmp_dir.as_ref().unwrap(),
            false,
        )?;

        match matches.subcommand() {
            ("from-log",  Some(m)) => updates::from_log(
                &db,
                m.value_of("current-day").expect("has default"),
                m.value_of("current-epoch").expect("has default").parse()?,
                m.is_present("keep-going"),
            )?,
            ("check",  Some(m)) => updates::check(
                &db,
                m.value_of("current-epoch").expect("has default").parse()?,
            )?,
            ("recover",  Some(m)) => updates::recover(
                &db,
                m.value_of("current-epoch").expect("has default").parse()?,
            )?,
            ("compact",  Some(m)) => updates::compact(
                &db,
                m.value_of("current-epoch").expect("has default").parse()?,
            )?,
            ("gc",  Some(m)) => updates::gc(
                &db,
                m.value_of("current-epoch").expect("has default").parse()?,
                m.value_of("keep").expect("has default").parse()?,
            )?,
            _ => unreachable!(),
        }
    } else {
        println!("{}", matches.usage());
    }

    Ok(())
}
