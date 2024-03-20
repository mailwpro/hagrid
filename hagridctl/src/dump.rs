use anyhow::Result;
use openpgp::parse::Parse;
use openpgp::serialize::Serialize;
use openpgp::Cert;

use std::fs::{self, File};
use std::path::Path;
use std::time::Instant;

use indicatif::{ProgressBar, ProgressStyle};
use walkdir::WalkDir;

use HagridConfig;

struct DumpStats<'a> {
    progress: &'a ProgressBar,
    prefix: String,
    count_total: u64,
    count_err: u64,
    count_partial: u64,
    start_time_partial: Instant,
    kps_partial: u64,
}

impl<'a> DumpStats<'a> {
    fn new(progress: &'a ProgressBar) -> Self {
        Self {
            progress,
            prefix: "".to_owned(),
            count_total: 0,
            count_err: 0,
            count_partial: 0,
            start_time_partial: Instant::now(),
            kps_partial: 0,
        }
    }

    fn update(&mut self, tpk: &Cert) {
        // If a new TPK starts, parse and import.
        self.count_total += 1;
        self.count_partial += 1;
        if (self.count_total % 10) == 0 {
            self.prefix = tpk.fingerprint().to_string()[0..4].to_owned();
        }
        self.progress_update();
    }

    fn progress_update(&mut self) {
        if (self.count_total % 10) != 0 {
            return;
        }
        if self.count_partial >= 1000 {
            let runtime = (self.start_time_partial.elapsed().as_millis() + 1) as u64;
            self.kps_partial = (self.count_partial * 1000) / runtime;
            self.start_time_partial = Instant::now();
            self.count_partial = 0;
        }
        self.progress.set_message(&format!(
            "prefix {} dumpd {:5} keys, {:5} Errors ({:3} keys/s)",
            self.prefix,
            self.count_total,
            self.count_err,
            self.kps_partial
        ));
    }
}

pub fn do_dump(config: &HagridConfig) -> Result<()> {
    let published_dir = config
        .keys_external_dir
        .as_ref()
        .unwrap()
        .join("links")
        .join("by-email");
    let dirs: Vec<_> = WalkDir::new(published_dir)
        .min_depth(1)
        .max_depth(1)
        .sort_by(|a, b| a.file_name().cmp(b.file_name()))
        .into_iter()
        .flatten()
        .map(|entry| entry.into_path())
        .collect();

    let progress_bar = ProgressBar::new(dirs.len() as u64);
    progress_bar.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {msg}")
            .progress_chars("##-"),
    );

    let mut stats = DumpStats::new(&progress_bar);
    let mut output_file = File::create("keyring.pub.pgp")?;

    for dir in dirs {
        progress_bar.inc(1);
        dump_dir_recursively(&mut stats, &mut output_file, &dir)?;
    }
    progress_bar.finish();

    Ok(())
}

fn dump_dir_recursively(
    stats: &mut DumpStats,
    output_file: &mut File,
    dir: &Path,
) -> Result<()> {
    for path in WalkDir::new(dir)
        .follow_links(true)
        .into_iter()
        .flatten()
        .filter(|e| e.file_type().is_file())
        .map(|entry| entry.into_path())
    {
        let result: Result<()> = (|| {
            let bytes = fs::read_to_string(path.as_path())?;
            let tpk = Cert::from_bytes(bytes.as_bytes())?;
            tpk.export(output_file)?;
            stats.update(&tpk);
            Ok(())
        })();
        if let Err(err) = result {
            stats.progress.println(format!("error: {:?}", err));
            stats.count_err += 1
        }
    }

    Ok(())
}
