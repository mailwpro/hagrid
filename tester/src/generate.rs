use std::{fs::File, path::Path, io::Write};

use anyhow::Result;

use indicatif::{ProgressBar, ProgressStyle};
use openpgp::{cert::CertBuilder, serialize::Serialize};

pub fn do_generate(count: u64, output_path: &Path, fprs_path: Option<&Path>) -> Result<()> {
    let progress_bar = ProgressBar::new(count);
    progress_bar.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} {msg}")
            .progress_chars("##-"),
    );
    progress_bar.set_draw_delta(count / 100);

    let mut output = File::create(output_path)?;
    let mut output_fprs = if let Some(p) = fprs_path {
        Some(File::create(p)?)
    } else {
        None
    };
    for i in 0..count {
        let (cert, _) =
            CertBuilder::general_purpose(None, Some(format!("{:07}@hagrid.invalid", i)))
                .generate()?;
        cert.serialize(&mut output)?;
        if let Some(ref mut output_fprs) = output_fprs {
            writeln!(output_fprs, "{}", cert)?;
        }

        progress_bar.inc(1);
    }
    progress_bar.finish();

    Ok(())
}
