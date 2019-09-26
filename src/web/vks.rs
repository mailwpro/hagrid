use failure::Fallible as Result;

use crate::database::{Database, KeyDatabase, StatefulTokens, EmailAddressStatus, TpkStatus, ImportResult};
use crate::database::types::{Fingerprint,Email};
use crate::mail;
use crate::counters;
use crate::tokens::{self, StatelessSerializable};
use crate::rate_limiter::RateLimiter;
use crate::web::RequestOrigin;

use sequoia_openpgp::TPK;

use std::io::Read;
use std::convert::TryFrom;
use std::collections::HashMap;

use self::response::*;

pub mod request {
    #[derive(Deserialize)]
    pub struct UploadRequest {
        pub keytext: String,
    }

    #[derive(Deserialize)]
    pub struct VerifyRequest {
        pub token: String,
        pub addresses: Vec<String>,
    }
}

pub mod response {
    use crate::database::types::Email;

    #[derive(Debug,Serialize,Deserialize,PartialEq,Eq)]
    pub enum EmailStatus {
        #[serde(rename = "unpublished")]
        Unpublished,
        #[serde(rename = "pending")]
        Pending,
        #[serde(rename = "published")]
        Published,
        #[serde(rename = "revoked")]
        Revoked,
    }

    use std::collections::HashMap;

    pub enum UploadResponse {
        Ok {
            token: String,
            key_fpr: String,
            is_revoked: bool,
            status: HashMap<String,EmailStatus>,
            count_unparsed: usize,
            is_new_key: bool,
            primary_uid: Option<Email>,
        },
        OkMulti { key_fprs: Vec<String> },
        Error(String),
    }

    impl UploadResponse {
        pub fn err(err: &str) -> Self {
            UploadResponse::Error(err.to_owned())
        }
    }

    pub enum PublishResponse {
        Ok { fingerprint: String, email: String },
        Error(String),
    }

    impl PublishResponse {
        pub fn err(err: &str) -> Self {
            PublishResponse::Error(err.to_owned())
        }
    }
}

#[derive(Serialize,Deserialize)]
struct VerifyTpkState {
    fpr: Fingerprint,
    addresses: Vec<Email>,
    requested: Vec<Email>,
}

impl StatelessSerializable for VerifyTpkState {
}

pub fn process_key(
    db: &KeyDatabase,
    tokens_stateless: &tokens::Service,
    rate_limiter: &RateLimiter,
    reader: impl Read,
) -> response::UploadResponse {
    use sequoia_openpgp::parse::{Parse, PacketParserBuilder, Dearmor};
    use sequoia_openpgp::tpk::TPKParser;
    use sequoia_openpgp::armor::ReaderMode;

    // First, parse all TPKs and error out if one fails.
    let parser = match PacketParserBuilder::from_reader(reader)
        .and_then(|ppb| {
            ppb.dearmor(Dearmor::Auto(ReaderMode::VeryTolerant)).finalize()
        })
    {
        Ok(ppr) => TPKParser::from_packet_parser(ppr),
        Err(_) => return UploadResponse::err("Failed parsing key"),
    };
    let mut tpks = Vec::new();
    for tpk in parser {
        tpks.push(match tpk {
            Ok(t) => {
                if t.is_tsk() {
                    counters::inc_key_upload("secret");
                    return UploadResponse::err("Whoops, please don't upload secret keys!");
                }
                t
            },
            Err(_) => return UploadResponse::err("No keys uploaded"),
        });
    }

    match tpks.len() {
        0 => UploadResponse::err("No key submitted"),
        1 => process_key_single(db, tokens_stateless, rate_limiter, tpks.into_iter().next().unwrap()),
        _ => process_key_multiple(db, tpks),
    }
}

fn log_db_merge(import_result: Result<ImportResult>) -> Result<ImportResult> {
    match import_result {
        Ok(ImportResult::New(_)) => counters::inc_key_upload("new"),
        Ok(ImportResult::Updated(_)) => counters::inc_key_upload("updated"),
        Ok(ImportResult::Unchanged(_)) => counters::inc_key_upload("unchanged"),
        Err(_) => counters::inc_key_upload("error"),
    };

    import_result
}

fn process_key_multiple(
    db: &KeyDatabase,
    tpks: Vec<TPK>,
) -> response::UploadResponse {
    let key_fprs: Vec<_> = tpks
        .into_iter()
        .flat_map(|tpk| Fingerprint::try_from(tpk.fingerprint())
                .map(|fpr| (fpr, tpk)))
        .flat_map(|(fpr, tpk)| log_db_merge(db.merge(tpk)).map(|_| fpr.to_string()))
        .collect();

    response::UploadResponse::OkMulti { key_fprs }
}

fn process_key_single(
    db: &KeyDatabase,
    tokens_stateless: &tokens::Service,
    rate_limiter: &RateLimiter,
    tpk: TPK,
) -> response::UploadResponse {
    let fp = Fingerprint::try_from(tpk.fingerprint()).unwrap();

    let (tpk_status, is_new_key) = match log_db_merge(db.merge(tpk)) {
        Ok(ImportResult::New(tpk_status)) => (tpk_status, true),
        Ok(ImportResult::Updated(tpk_status)) => (tpk_status, false),
        Ok(ImportResult::Unchanged(tpk_status)) => (tpk_status, false),
        Err(_) => return UploadResponse::err(&format!(
            "Something went wrong processing key {}", fp)),
    };

    let verify_state = {
        let emails = tpk_status.email_status.iter()
            .map(|(email,_)| email.clone())
            .collect();
        VerifyTpkState {
            fpr: fp.clone(),
            addresses: emails,
            requested: vec!(),
        }
    };

    let token = tokens_stateless.create(&verify_state);

    show_upload_verify(rate_limiter, token, tpk_status, verify_state, is_new_key)
}

pub fn request_verify(
    db: rocket::State<KeyDatabase>,
    request_origin: RequestOrigin,
    token_stateful: rocket::State<StatefulTokens>,
    token_stateless: rocket::State<tokens::Service>,
    mail_service: rocket::State<mail::Service>,
    rate_limiter: rocket::State<RateLimiter>,
    token: String,
    addresses: Vec<String>,
) -> response::UploadResponse {
    let (verify_state, tpk_status) = match check_tpk_state(&db, &token_stateless, &token) {
        Ok(ok) => ok,
        Err(e) => return UploadResponse::err(&e.to_string()),
    };

    if tpk_status.is_revoked {
        return show_upload_verify(
                &rate_limiter, token, tpk_status, verify_state, false);
    }

    let emails_requested: Vec<_> = addresses.into_iter()
        .map(|address| address.parse::<Email>())
        .flatten()
        .filter(|email| verify_state.addresses.contains(email))
        .filter(|email| tpk_status.email_status.iter()
            .any(|(uid_email, status)|
                uid_email == email && *status == EmailAddressStatus::NotPublished
            ))
        .collect();

    for email in emails_requested {
        let rate_limit_ok = rate_limiter.action_perform(format!("verify-{}", &email));
        if rate_limit_ok {
            if send_verify_email(&request_origin, &mail_service, &token_stateful, &verify_state.fpr, &email).is_err() {
                return UploadResponse::err(&format!("error sending email to {}", &email));
            }
        }
    }

    show_upload_verify(&rate_limiter, token, tpk_status, verify_state, false)
}

fn check_tpk_state(
    db: &KeyDatabase,
    token_stateless: &tokens::Service,
    token: &str,
) -> Result<(VerifyTpkState,TpkStatus)> {
    let verify_state = token_stateless.check::<VerifyTpkState>(token)?;
    let tpk_status = db.get_tpk_status(&verify_state.fpr, &verify_state.addresses)?;
    Ok((verify_state, tpk_status))
}

fn send_verify_email(
    request_origin: &RequestOrigin,
    mail_service: &mail::Service,
    token_stateful: &StatefulTokens,
    fpr: &Fingerprint,
    email: &Email,
) -> Result<()> {
    let token_content = (fpr.clone(), email.clone());
    let token_str = serde_json::to_string(&token_content)?;
    let token_verify = token_stateful.new_token("verify", token_str.as_bytes())?;

    mail_service.send_verification(
        request_origin.get_base_uri(),
        fpr.to_string(),
        &email,
        &token_verify,
    )
}

pub fn verify_confirm(
    db: rocket::State<KeyDatabase>,
    token_service: rocket::State<StatefulTokens>,
    token: String,
) -> response::PublishResponse {
    let (fingerprint, email) = match check_publish_token(&db, &token_service, token) {
        Ok(x) => x,
        Err(_) => return PublishResponse::err("Invalid verification token!"),
    };

    response::PublishResponse::Ok {
        fingerprint: fingerprint.to_string(),
        email: email.to_string()
    }
}

fn check_publish_token(
    db: &KeyDatabase,
    token_service: &StatefulTokens,
    token: String,
) -> Result<(Fingerprint,Email)> {
    let payload = token_service.pop_token("verify", &token)?;
    let (fingerprint, email) = serde_json::from_str(&payload)?;

    db.set_email_published(&fingerprint, &email)?;
    counters::inc_address_published(&email);

    Ok((fingerprint, email))
}

fn show_upload_verify(
    rate_limiter: &RateLimiter,
    token: String,
    tpk_status: TpkStatus,
    verify_state: VerifyTpkState,
    is_new_key: bool,
) -> response::UploadResponse {
    let key_fpr = verify_state.fpr.to_string();
    if tpk_status.is_revoked {
        return response::UploadResponse::Ok {
            token,
            key_fpr,
            count_unparsed: 0,
            is_revoked: true,
            status: HashMap::new(),
            is_new_key: false,
            primary_uid: None,
        };
    }

    let status: HashMap<_,_> = tpk_status.email_status
        .iter()
        .map(|(email,status)| {
            let is_pending = (*status == EmailAddressStatus::NotPublished) &&
                !rate_limiter.action_check(format!("verify-{}", &email));
            if is_pending {
                (email.to_string(), EmailStatus::Pending)
            } else {
                (email.to_string(), match status {
                    EmailAddressStatus::NotPublished => EmailStatus::Unpublished,
                    EmailAddressStatus::Published => EmailStatus::Published,
                    EmailAddressStatus::Revoked => EmailStatus::Revoked,
                })
            }
        })
        .collect();
    let primary_uid = tpk_status.email_status
        .get(0)
        .map(|(email, _)| email)
        .cloned();

    let count_unparsed = tpk_status.unparsed_uids;

    response::UploadResponse::Ok { token, key_fpr, count_unparsed, is_revoked: false, status, is_new_key, primary_uid }
}
