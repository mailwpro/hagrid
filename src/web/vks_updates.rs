use std::{collections::HashMap, sync::RwLock};

use rocket::http::hyper::header::{Expires, HttpDate};

use crate::{database::updates::{Epoch, Manifest}, merge_util::merge_vectors};
use crate::database::{Database, KeyDatabase};
use crate::Result;

const EPOCH_SERVE_LIMIT: u32 = 120;

pub struct UpdateEpochCache(RwLock<HashMap<Epoch, Vec<u32>>>);

impl UpdateEpochCache {
    pub fn new() -> Self {
        UpdateEpochCache(RwLock::new(HashMap::new()))
    }
}

#[derive(Responder)]
pub enum ManifestUpdateResponse {
    #[response(status = 200, content_type = "application/pgp-keystore-update-manifest")]
    Binary(Vec<u8>, Expires),
    #[response(status = 404)]
    NotFound(String),
    #[response(status = 400)]
    BadRequest(String),
}

#[get("/vks/v1/updates/<epoch>")]
pub fn get_update_manifest(
    db: rocket::State<KeyDatabase>,
    cache: rocket::State<UpdateEpochCache>,
    epoch: u32,
) -> ManifestUpdateResponse {
    let epoch_now = Epoch::current().unwrap();
    let epoch_since = Epoch::from(epoch);
    if epoch_since >= epoch_now {
        return ManifestUpdateResponse::BadRequest("Requested epoch must be in the past and completed".to_owned());
    }
    if epoch_now - epoch_since > (EPOCH_SERVE_LIMIT as i64) {
        return ManifestUpdateResponse::NotFound(
            format!("Updafe manifest data only available for the last {} epochs", EPOCH_SERVE_LIMIT));
    }

    if let Err(e) = provision_cache_since(&db, &cache, &epoch_since) {
        return ManifestUpdateResponse::NotFound(e.to_string());
    }

    let cache_lock = cache.0.read().expect("lock can't be poisoned");
    let mut epoch_data: Vec<&[u32]> = Vec::with_capacity((epoch_now - epoch_since) as usize);
    for e in epoch_since.until(epoch_now).expect("epoch_since is before epoch_now") {
        if let Some(v) = cache_lock.get(&e) {
            epoch_data.push(&v);
        }
    }

    let prefixes = merge_vectors(epoch_data);
    let manifest = Manifest::new(epoch_since, epoch_now.pred().unwrap(), prefixes).unwrap();
    let expires = Expires(HttpDate(epoch_now.succ().expect("We're not at the end of time").into()));
    ManifestUpdateResponse::Binary(manifest.to_vec(), expires)
}

fn provision_cache_since(db: &KeyDatabase, cache: &UpdateEpochCache, epoch_since: &Epoch) -> Result<()> {
    let epoch_now = Epoch::current().expect("not the end of time");
    let mut cache_lock = cache.0.write().expect("lock can't be poisoned");

    for epoch in epoch_since.until(epoch_now).expect("epoch_since is before epoch_now") {
        if cache_lock.contains_key(&epoch) {
            continue;
        }
        match db.read_log_epoch(epoch) {
            Err(e) => {
                eprintln!("{:?}", e);
                Err(anyhow!("No update manifest data available for requested epoch"))?
            },
            Ok(None) => Err(anyhow!("No update manifest data available for requested epoch"))?,
            Ok(Some(prefixes)) => cache_lock.insert(epoch, prefixes),
        };
    }

    let ref epoch_earliest = epoch_now - EPOCH_SERVE_LIMIT;
    cache_lock.retain(|k, _| k > epoch_earliest);

    Ok(())
}
