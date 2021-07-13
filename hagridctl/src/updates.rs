use std::{
    convert::TryFrom,
    fs,
    io::{
        self,
        BufRead,
        BufReader,
    },
};

use anyhow::Context;

extern crate hagrid_database as database;
use database::{
    KeyDatabase,
    types::Fingerprint,
    updates::{
        Epoch,
        Manifest,
    },
};

// XXX: locking

pub fn from_log(db: &KeyDatabase, start_day: &str, current_epoch: Epoch,
                keep_going: bool)
                -> anyhow::Result<()> {
    assert_consistency(&db, current_epoch);

    // Start from `start_day`, walk backwards in time.
    let mut day = if start_day == "today" {
        chrono::offset::Utc::today().naive_local()
    } else {
        chrono::naive::NaiveDate::parse_from_str(start_day, "%Y-%m-%d")?
    };

    // We want to create zero-sized manifests because there must be no
    // gaps, so keep track of the last epoch that was written.
    let mut last_epoch = current_epoch;

    let mut found_one = false;
    const GO_BACK_DAYS: usize = 365;
    let mut go_back_days = GO_BACK_DAYS;
    loop {
        let name =
            db.keys_log_dir().join(day.format("%Y-%m-%d").to_string());

        match fs::File::open(&name) {
            Ok(f) => {
                eprintln!("Reading log for {}", day.format("%Y-%m-%d"));
                found_one = true;

                // Process all updates in this file, then update
                // manifests later.
                let mut updates = Vec::new();
                for (i, l) in BufReader::new(f).lines().enumerate() {
                    let l = l?;
                    let fields = l.split_whitespace().collect::<Vec<_>>();
                    if fields.len() != 2 {
                        return Err(anyhow::anyhow!(
                            "Malformed line {:?}:{}: {:?}",
                            name, i + 1, l));
                    }

                    let unix_epoch: u64 = fields[0].parse()
                        .with_context(|| format!(
                            "Malformed unix epoch in line {:?}:{}",
                            name, i + 1))?;
                    let fp: Fingerprint = fields[1].parse()
                        .with_context(|| format!(
                            "Malformed unix epoch in line {:?}:{}",
                            name, i + 1))?;

                    updates.push((Epoch::try_from_unix(unix_epoch)?, fp));
                }

                // Start with the most recent update.
                let mut manifest: Option<Manifest> = None;
                while let Some((epoch, fp)) = updates.pop() {
                    // Check whether epoch falls into the current
                    // manifest, else commit it and drop it.
                    if manifest.as_ref().map(|m| m.contains_epoch(epoch))
                        .unwrap_or(false)
                    {
                        if update_manifest(
                            &db,
                            manifest.take()
                                .expect("conditional checks manifest"),
                            &mut last_epoch)?
                            && ! keep_going
                        {
                            assert_consistency(&db, current_epoch);
                            return Ok(());
                        }
                    }

                    if manifest.is_none() {
                        manifest = match db.update_manifest_open(epoch) {
                            Ok(mut f) => Some(Manifest::parse(&mut f)?),
                            Err(e) => if e.kind() == io::ErrorKind::NotFound {
                                Some(Manifest::new(epoch, epoch)?)
                            } else {
                                return Err(e.into());
                            },
                        }
                    }

                    if let Some(m) = manifest.as_mut() {
                        assert!(m.contains_epoch(epoch));
                        m.insert(&fp);
                    } else {
                        unreachable!("manifest is some at this point")
                    }
                }

                if let Some(manifest) = manifest.take() {
                    if update_manifest(&db, manifest, &mut last_epoch)?
                        && ! keep_going
                    {
                        assert_consistency(&db, current_epoch);
                        return Ok(());
                    }
                }

                fn update_manifest(db: &KeyDatabase,
                                   manifest: Manifest,
                                   last_epoch: &mut Epoch,)
                                   -> anyhow::Result<bool> {
                    // Note: If you change the following lines, also
                    // change them in the loop above.
                    let start = manifest.start();
                    let end = manifest.end();

                    // Fill gaps.
                    for e in last_epoch.since(end)? {
                        if db.update_manifest_open(e).is_err() {
                            // Fill with empty manifest.
                            db.update_manifest_replace(
                                Manifest::new(e, e)?)?;
                        }
                    }
                    *last_epoch = manifest.start();
                    let changed = db.update_manifest_replace(manifest)?;

                    if changed {
                        eprintln!("Updated {}", start);
                        Ok(false) // keep going
                    } else {
                        // We reached the part of the log that is
                        // already merged into Update Manifests.
                        eprintln!("Reached end of unsync'ed history");
                        Ok(true) // abort sync
                    }
                }
            },
            Err(_) if ! found_one => {
                go_back_days -= 1;
                if go_back_days == 0 {
                    return Err(anyhow::anyhow!(
                        "Found no log entries within the last {} days",
                        GO_BACK_DAYS));
                }
                // Try the previous day.
            },
            Err(_) => {
                go_back_days -= 1;
                if go_back_days == 0 {
                    break;
                }

                // Ignore gaps.
            },
        }

        // Walk backwards in time.
        day = match day.pred_opt() {
            Some(d) => d,
            None => break,
        };
    }

    assert_consistency(&db, current_epoch);
    Ok(())
}

/// On debug builds, assert that the updates are consistent.
fn assert_consistency(db: &KeyDatabase, current_epoch: Epoch) {
    if cfg!(debug_assertions) {
        check(db, current_epoch).unwrap();
    }
}

/// Checks the Update Manifests for consistency.
///
/// Currently, this function checks that:
///
///   - The Update Manifests are continuous
///   - Every Update Manifest is well-formed
///   - Every Update Manifest contains its epoch
///
/// On debug builds, this consistency predicate is asserted before
/// (with the exception of the recover operation) and after every
/// operation.
pub fn check(db: &KeyDatabase, current_epoch: Epoch) -> anyhow::Result<()> {
    let mut e = current_epoch;

    // First, find the first existing manifest.
    while let Some(pred) = e.pred() {
        if db.update_manifest_open(e).is_ok() {
            break;
        }

        e = pred;
    }

    // Then, check every manifest for consistency.
    while let Some(pred) = e.pred() {
        match db.update_manifest_open(e) {
            Ok(mut f) => {
                let manifest = Manifest::parse(&mut f)?;

                if ! manifest.contains_epoch(e) {
                    return Err(anyhow::anyhow!(
                        "Manifest for epoch {} does not contain {}: \
                         start = {}, end = {}",
                        e, e, manifest.start(), manifest.end()));
                }
            },
            Err(e) => if e.kind() == io::ErrorKind::NotFound {
                break;
            } else {
                return Err(e.into());
            }
        }

        e = pred;
    }

    // Finally, check that one we found the last manifest, and not a
    // gap.
    let first_missing = e;
    while let Some(pred) = e.pred() {
        if db.update_manifest_open(e).is_ok() {
            return Err(anyhow::anyhow!(
                "Found a gap between {} and {}",
                e, first_missing + 1));
        }

        e = pred;
    }

    Ok(())
}

/// Recovers from inconsistencies by pruning history from the
/// inconsistent point on.
pub fn recover(db: &KeyDatabase, current_epoch: Epoch) -> anyhow::Result<()> {
    let mut e = current_epoch;

    // First, find the first existing manifest.
    while let Some(pred) = e.pred() {
        if db.update_manifest_open(e).is_ok() {
            break;
        }

        e = pred;
    }

    // Then, check every manifest for consistency.
    while let Some(pred) = e.pred() {
        match db.update_manifest_open(e) {
            Ok(mut f) => {
                let manifest = Manifest::parse(&mut f)?;

                if ! manifest.contains_epoch(e) {
                    eprintln!(
                        "Manifest for epoch {} does not contain {}: \
                         start = {}, end = {}",
                        e, e, manifest.start(), manifest.end());
                }
            },
            Err(e) => if e.kind() == io::ErrorKind::NotFound {
                break;
            } else {
                return Err(e.into());
            }
        }

        e = pred;
    }

    // Finally, check that one we found the last manifest, and not a
    // gap.
    let mut pruning_starts = Some(e);
    while let Some(pred) = e.pred() {
        let path = db.update_manifest_path(e);

        if fs::remove_file(&path).is_ok() {
            if let Some(e) = pruning_starts.take() {
                eprintln!("Pruning history from {} on", e);
            }

            eprintln!("Pruned {:?}", path);
        }

        e = pred;
    }

    assert_consistency(db, current_epoch);
    Ok(())
}

/// Compacts Update Manifest by folding them into larger manifests.
pub fn compact(db: &KeyDatabase, current_epoch: Epoch) -> anyhow::Result<()> {
    assert_consistency(db, current_epoch);

    // First, find the first Update Manifest because we want to
    // iterate from the first, the oldest epoch, to the current epoch.
    let mut first_epoch = Epoch::try_from(0).unwrap();
    while let Err(_) = db.update_manifest_open(first_epoch) {
        first_epoch = first_epoch.succ()
            .expect("we didn't hit current_epoch, so a successor must exist");
        if first_epoch == current_epoch {
            break;
        }
    }

    // Compact into buckets similar to how the client is supposed to
    // mask its identity.
    compact_into(db, first_epoch, current_epoch, 1 << 3)?;
    compact_into(db, first_epoch, current_epoch, 1 << 6)?;
    compact_into(db, first_epoch, current_epoch, 1 << 9)?;

    assert_consistency(db, current_epoch);
    Ok(())
}

/// Compacts into larger manifests of the given size.
fn compact_into(db: &KeyDatabase, first_epoch: Epoch, current_epoch: Epoch,
                bucket_size: u32)
                -> anyhow::Result<()>
{
    // From the first epoch start walking, see if we can find a
    // contiguous range of Update Manifests each smaller than
    // bucket_size.

    // For ease of comparison, convert size.
    let bucket_size = Epoch::from(bucket_size);

    // Our bucket we're merging into.
    let mut bucket: Option<Manifest> = None;

    // Our epoch pointer.
    let mut epoch = first_epoch;

    while let Ok(manifest) = db.update_manifest_open(epoch)
        .map_err(Into::into)
        .and_then(|mut f| Manifest::parse(&mut f))
    {
        let mut next_epoch = manifest.end().succ();

        if manifest.end() - manifest.start() < bucket_size {
            let new_bucket = if let Some(b) = bucket.as_mut() {
                // See if it still fits in the bucket.
                if b.end() - manifest.start() <= bucket_size {
                    b.merge(&manifest)
                } else {
                    // Write partial bucket out, then start a new one.
                    if let Some(b) = bucket.take() {
                        eprintln!("Compacting {} to {}", b.start(), b.end());
                        db.update_manifest_replace(b)?;
                    }
                    manifest
                }
            } else {
                manifest
            };
            bucket = Some(new_bucket);
        } else {
            // We wound a manifest exceeding our bucket size before we
            // could collect enough members to reach bucket_size.
            // Merge them anyway as best effort.
            if let Some(b) = bucket.take() {
                eprintln!("Compacting {} to {}", b.start(), b.end());
                db.update_manifest_replace(b)?;
            }
        }

        // Check if we filled our bucket.
        if bucket.as_ref().map(|b| b.end() - b.start() >= bucket_size)
            .unwrap_or(false)
        {
            if let Some(b) = bucket.take() {
                eprintln!("Compacting {} to {}", b.start(), b.end());
                db.update_manifest_replace(b)?;
            }
        }

        if let Some(e) = next_epoch.take() {
            epoch = e;
        } else {
            break;
        }

        if epoch <= current_epoch {
            break;
        }
    }

    Ok(())
}

pub fn gc(db: &KeyDatabase, current_epoch: Epoch, mut keep: usize)
          -> anyhow::Result<()> {
    assert_consistency(&db, current_epoch);

    let mut e = current_epoch;

    while let Some(pred) = e.pred() {
        let path = db.update_manifest_path(e);

        if keep > 0 {
            if fs::File::open(&path).is_ok() {
                eprintln!("Keeping {:?}", path);
                keep -= 1;
            }
        } else {
            if fs::remove_file(&path).is_ok() {
                eprintln!("Deleted {:?}", path);
            }
        }

        e = pred;
    }

    assert_consistency(&db, current_epoch);
    Ok(())
}
