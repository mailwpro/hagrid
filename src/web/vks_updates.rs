use std::io::{BufRead, BufReader};

use rocket::http::hyper::header::{Expires, HttpDate};

use crate::{database::updates::{Epoch, Manifest}, merge_util::merge_vectors};
use crate::database::{Database, KeyDatabase};
use crate::Result;

const EPOCH_SERVE_LIMIT: u32 = 120;

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

    let mut epoch_data: Vec<&[u32]> = Vec::with_capacity((epoch_now - epoch_since) as usize);
    for e in epoch_since.until(epoch_now).expect("epoch_since is before epoch_now") {
        match db.read_log_epoch(e) {
            Err(e) => {
                eprintln!("Error reading epoch: {:?}", e);
                return ManifestUpdateResponse::NotFound(
                    "No data found for requested update epoch".to_owned());
            }
            Ok(None) => {
                return ManifestUpdateResponse::NotFound(
                    "No data found for requested update epoch".to_owned());
            }
            Ok(Some(v)) => epoch_data.push(&v),
        }
    }

    let prefixes = merge_vectors(epoch_data);
    let manifest = Manifest::new(epoch_since, epoch_now.pred().unwrap(), prefixes).unwrap();
    let expires = Expires(HttpDate(epoch_now.succ().expect("We're not at the end of time").into()));
    ManifestUpdateResponse::Binary(manifest.to_vec(), expires)
}
