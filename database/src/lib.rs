#![feature(proc_macro_hygiene, plugin, decl_macro)]
#![recursion_limit = "1024"]
#![feature(try_from)]

use std::convert::{TryFrom,TryInto};
use std::path::PathBuf;
use std::str::FromStr;

extern crate failure;
use failure::Error;
use failure::Fallible as Result;
extern crate fs2;
extern crate idna;
#[macro_use] extern crate log;
extern crate pathdiff;
extern crate rand;
extern crate serde;
extern crate serde_json;
extern crate tempfile;
extern crate time;
extern crate url;
extern crate hex;
extern crate walkdir;

use tempfile::NamedTempFile;

extern crate sequoia_openpgp as openpgp;
use openpgp::{
    TPK,
    RevocationStatus,
    packet::UserID,
    parse::Parse,
    packet::KeyFlags,
};

pub mod types;
use types::{Email, Fingerprint, KeyID};

pub mod sync;

mod fs;
pub use self::fs::Filesystem as KeyDatabase;

mod stateful_tokens;
pub use stateful_tokens::StatefulTokens;

mod openpgp_utils;
use openpgp_utils::{tpk_filter_userids, tpk_to_string, tpk_clean};

#[cfg(test)]
mod test;

/// Represents a search query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Query {
    ByFingerprint(Fingerprint),
    ByKeyID(KeyID),
    ByEmail(Email),
}

impl FromStr for Query {
    type Err = failure::Error;

    fn from_str(term: &str) -> Result<Self> {
        use self::Query::*;

        if let Ok(fp) = Fingerprint::from_str(term) {
            Ok(ByFingerprint(fp))
        } else if let Ok(keyid) = KeyID::from_str(term) {
            Ok(ByKeyID(keyid))
        } else if let Ok(email) = Email::from_str(term) {
            Ok(ByEmail(email))
        } else {
            Err(failure::err_msg("Malformed query"))
        }
    }
}

impl Query {
    pub fn describe_error(&self) -> String {
        match self {
            Query::ByFingerprint(fpr) =>
                format!("No key found for fingerprint {}", fpr),
            Query::ByKeyID(key_id) =>
                format!("No key found for key id {}", key_id),
            Query::ByEmail(email) =>
                format!("No key found for e-mail address {}", email),
        }
    }
}

#[derive(Debug,PartialEq,Eq)]
pub enum EmailAddressStatus {
    Revoked,
    NotPublished,
    Published,
}

pub enum ImportResult {
    New(TpkStatus),
    Updated(TpkStatus),
    Unchanged(TpkStatus),
}

impl ImportResult {
    pub fn into_tpk_status(self) -> TpkStatus {
        match self {
            ImportResult::New(status) => status,
            ImportResult::Updated(status) => status,
            ImportResult::Unchanged(status) => status,
        }
    }
}

#[derive(Debug,PartialEq)]
pub struct TpkStatus {
    pub is_revoked: bool,
    pub email_status: Vec<(Email,EmailAddressStatus)>,
    pub unparsed_uids: usize,
}

pub enum RegenerateResult {
    Updated,
    Unchanged,
}

pub trait Database: Sync + Send {
    type MutexGuard;

    /// Lock the DB for a complex update.
    ///
    /// All basic write operations are atomic so we don't need to lock
    /// read operations to ensure that we return something sane.
    fn lock(&self) -> Result<Self::MutexGuard>;

    /// Queries the database using Fingerprint, KeyID, or
    /// email-address.
    fn lookup(&self, term: &Query) -> Result<Option<TPK>> {
        use self::Query::*;
        let armored = match term {
            ByFingerprint(ref fp) => self.by_fpr(fp),
            ByKeyID(ref keyid) => self.by_kid(keyid),
            ByEmail(ref email) => self.by_email(&email),
        };

        match armored {
            Some(armored) => Ok(Some(TPK::from_bytes(armored.as_bytes())?)),
            None => Ok(None),
        }
    }

    /// Queries the database using Fingerprint, KeyID, or
    /// email-address, returning the primary fingerprint.
    fn lookup_primary_fingerprint(&self, term: &Query) -> Option<Fingerprint>;

    /// Gets the path to the underlying file, if any.
    fn lookup_path(&self, term: &Query) -> Option<PathBuf> {
        let _ = term;
        None
    }

    fn link_email(&self, email: &Email, fpr: &Fingerprint) -> Result<()>;
    fn unlink_email(&self, email: &Email, fpr: &Fingerprint) -> Result<()>;

    fn link_fpr(&self, from: &Fingerprint, to: &Fingerprint) -> Result<()>;
    fn unlink_fpr(&self, from: &Fingerprint, to: &Fingerprint) -> Result<()>;

    fn by_fpr(&self, fpr: &Fingerprint) -> Option<String>;
    fn by_kid(&self, kid: &KeyID) -> Option<String>;
    fn by_email(&self, email: &Email) -> Option<String>;

    /// Complex operation that updates a TPK in the database.
    ///
    /// 1. Merge new TPK with old, full TPK
    ///    - if old full TPK == new full TPK, stop
    /// 2. Prepare new published TPK
    ///    - retrieve UserIDs from old published TPK
    ///    - create new TPK from full TPK by keeping only published UserIDs
    /// 3. Write full and published TPK to temporary files
    /// 4. Check for fingerprint and long key id collisions for published TPK
    ///    - abort if any problems come up!
    /// 5. Move full and published temporary TPK to their location
    /// 6. Update all symlinks
    fn merge(&self, new_tpk: TPK) -> Result<ImportResult> {
        let fpr_primary = Fingerprint::try_from(new_tpk.primary().fingerprint())?;

        let _lock = self.lock()?;

        let known_uids: Vec<UserID> = new_tpk
            .userids()
            .map(|binding| binding.userid().clone())
            .collect();

        let full_tpk_old = self.by_fpr_full(&fpr_primary)
            .and_then(|bytes| TPK::from_bytes(bytes.as_ref()).ok());
        let is_update = full_tpk_old.is_some();
        let (full_tpk_new, full_tpk_unchanged) = if let Some(full_tpk_old) = full_tpk_old {
            let full_tpk_new = new_tpk.merge(full_tpk_old.clone())?;
            let full_tpk_unchanged = full_tpk_new == full_tpk_old;
            (full_tpk_new, full_tpk_unchanged)
        } else {
            (new_tpk, false)
        };

        let is_revoked = full_tpk_new.revoked(None) != RevocationStatus::NotAsFarAsWeKnow;

        let published_uids: Vec<UserID> = self
            .by_fpr(&fpr_primary)
            .and_then(|bytes| TPK::from_bytes(bytes.as_ref()).ok())
            .map(|tpk| tpk.userids()
                 .map(|binding| binding.userid().clone())
                 .collect()
                ).unwrap_or_default();

        let unparsed_uids = full_tpk_new
            .userids()
            .map(|binding| Email::try_from(binding.userid()).is_err())
            .filter(|x| *x)
            .count();

        let mut email_status: Vec<_> = full_tpk_new
            .userids()
            .filter(|binding| known_uids.contains(binding.userid()))
            .flat_map(|binding| {
                let uid = binding.userid();
                if let Ok(email) = Email::try_from(uid) {
                    if binding.revoked(None) != RevocationStatus::NotAsFarAsWeKnow {
                        Some((email, EmailAddressStatus::Revoked))
                    } else if published_uids.contains(uid) {
                        Some((email, EmailAddressStatus::Published))
                    } else {
                        Some((email, EmailAddressStatus::NotPublished))
                    }
                } else {
                    None
                }
            })
            .collect();
        email_status.sort_by(|(e1,_),(e2,_)| e1.cmp(e2));
        email_status.dedup_by(|(e1, _), (e2, _)| e1 == e2);

        // Abort if no changes were made
        if full_tpk_unchanged {
            return Ok(ImportResult::Unchanged(TpkStatus { is_revoked, email_status, unparsed_uids }));
        }

        let revoked_uids: Vec<UserID> = full_tpk_new
            .userids()
            .filter(|binding| binding.revoked(None) != RevocationStatus::NotAsFarAsWeKnow)
            .map(|binding| binding.userid().clone())
            .collect();

        let newly_revoked_uids: Vec<&UserID> = published_uids.iter()
            .filter(|uid| revoked_uids.contains(uid))
            .collect();

        let published_tpk_new = tpk_filter_userids(
            &full_tpk_new, |uid| {
                published_uids.contains(uid) && !newly_revoked_uids.contains(&uid)
            })?;

        let newly_revoked_emails: Vec<Email> = published_uids.iter()
            .map(|uid| Email::try_from(uid).ok())
            .flatten()
            .filter(|email| {
                let has_unrevoked_userid = published_tpk_new
                    .userids()
                    .filter(|binding| binding.revoked(None) == RevocationStatus::NotAsFarAsWeKnow)
                    .map(|binding| binding.userid())
                    .map(|uid| Email::try_from(uid).ok())
                    .flatten()
                    .any(|unrevoked_email| unrevoked_email == *email);
                !has_unrevoked_userid
            }).collect();

        let fingerprints = tpk_get_linkable_fprs(&published_tpk_new);
        println!("{:?}", fingerprints);

        let fpr_checks = fingerprints
            .iter()
            .map(|fpr| self.check_link_fpr(&fpr, &fpr_primary))
            .collect::<Vec<_>>()
            .into_iter()
            .collect::<Result<Vec<_>>>();

        if fpr_checks.is_err() {
            self.write_to_quarantine(&fpr_primary, &tpk_to_string(&full_tpk_new)?)?;
        }
        let fpr_checks = fpr_checks?;

        let fpr_not_linked = fpr_checks.into_iter().flatten();

        let full_tpk_tmp = self.write_to_temp(&tpk_to_string(&full_tpk_new)?)?;
        let published_tpk_clean = tpk_clean(&published_tpk_new)?;
        let published_tpk_tmp = self.write_to_temp(&tpk_to_string(&published_tpk_clean)?)?;

        // these are very unlikely to fail. but if it happens,
        // database consistency might be compromised!
        self.move_tmp_to_full(full_tpk_tmp, &fpr_primary)?;
        self.move_tmp_to_published(published_tpk_tmp, &fpr_primary)?;

        for fpr in fpr_not_linked {
            if let Err(e) = self.link_fpr(&fpr, &fpr_primary) {
                info!("Error ensuring symlink! {} {} {:?}",
                      &fpr, &fpr_primary, e);
            }
        }

        for revoked_email in newly_revoked_emails {
            if let Err(e) = self.unlink_email(&revoked_email, &fpr_primary) {
                info!("Error ensuring symlink! {} {} {:?}",
                      &fpr_primary, &revoked_email, e);
            }
        }

        if is_update {
            Ok(ImportResult::Updated(TpkStatus { is_revoked, email_status, unparsed_uids }))
        } else {
            Ok(ImportResult::New(TpkStatus { is_revoked, email_status, unparsed_uids }))
        }
    }

    fn get_tpk_status(&self, fpr_primary: &Fingerprint, known_addresses: &[Email]) -> Result<TpkStatus> {
        let tpk_full = self.by_fpr_full(&fpr_primary)
            .ok_or_else(|| failure::err_msg("Key not in database!"))
            .and_then(|bytes| TPK::from_bytes(bytes.as_ref()))?;

        let is_revoked = tpk_full.revoked(None) != RevocationStatus::NotAsFarAsWeKnow;

        let unparsed_uids = tpk_full
            .userids()
            .map(|binding| Email::try_from(binding.userid()).is_err())
            .filter(|x| *x)
            .count();

        let published_uids: Vec<UserID> = self
            .by_fpr(&fpr_primary)
            .and_then(|bytes| TPK::from_bytes(bytes.as_ref()).ok())
            .map(|tpk| tpk.userids()
                 .map(|binding| binding.userid().clone())
                 .collect()
                ).unwrap_or_default();

        let mut email_status: Vec<_> = tpk_full
            .userids()
            .flat_map(|binding| {
                let uid = binding.userid();
                if let Ok(email) = Email::try_from(uid) {
                    if !known_addresses.contains(&email) {
                        None
                    } else if binding.revoked(None) != RevocationStatus::NotAsFarAsWeKnow {
                        Some((email, EmailAddressStatus::Revoked))
                    } else if published_uids.contains(uid) {
                        Some((email, EmailAddressStatus::Published))
                    } else {
                        Some((email, EmailAddressStatus::NotPublished))
                    }
                } else {
                    None
                }
            })
            .collect();
        email_status.sort_by(|(e1,_),(e2,_)| e1.cmp(e2));
        email_status.dedup_by(|(e1, _), (e2, _)| e1 == e2);

        Ok(TpkStatus { is_revoked, email_status, unparsed_uids })
    }

    /// Complex operation that publishes some user id for a TPK already in the database.
    ///
    /// 1. Load published TPK
    ///     - if UserID is already in, stop
    /// 2. Load full TPK
    ///     - if requested UserID is not in, stop
    /// 3. Prepare new published TPK
    ///    - retrieve UserIDs from old published TPK
    ///    - create new TPK from full TPK by keeping only published UserIDs
    /// 4. Check for fingerprint and long key id collisions for published TPK
    ///    - abort if any problems come up!
    /// 5. Move full and published temporary TPK to their location
    /// 6. Update all symlinks
    fn set_email_published(&self, fpr_primary: &Fingerprint, email_new: &Email) -> Result<()> {
        let _lock = self.lock()?;

        self.nolock_unlink_email_if_other(fpr_primary, email_new)?;

        let full_tpk = self.by_fpr_full(&fpr_primary)
            .ok_or_else(|| failure::err_msg("Key not in database!"))
            .and_then(|bytes| TPK::from_bytes(bytes.as_ref()))?;

        let published_uids_old: Vec<UserID> = self
            .by_fpr(&fpr_primary)
            .and_then(|bytes| TPK::from_bytes(bytes.as_ref()).ok())
            .map(|tpk| tpk.userids()
                .map(|binding| binding.userid().clone())
                .collect()
            ).unwrap_or_default();
        let published_emails_old: Vec<Email> = published_uids_old.iter()
            .map(|uid| Email::try_from(uid).ok())
            .flatten()
            .collect();

        // println!("publishing: {:?}", &uid_new);
        if published_emails_old.contains(&email_new) {
            // UserID already published - just stop
            return Ok(());
        }

        let published_tpk_new = {
            tpk_filter_userids(&full_tpk,
                |uid| Email::try_from(uid).unwrap() == *email_new || published_uids_old.contains(uid))?
        };

        if ! published_tpk_new
            .userids()
            .map(|binding| binding.userid())
            .any(|uid| Email::try_from(uid).map(|email| email == *email_new).unwrap_or_default()) {
                return Err(failure::err_msg("Requested UserID not found!"));
        }

        let published_tpk_clean = tpk_clean(&published_tpk_new)?;
        let published_tpk_tmp = self.write_to_temp(&tpk_to_string(&published_tpk_clean)?)?;

        self.move_tmp_to_published(published_tpk_tmp, &fpr_primary)?;

        if let Err(e) = self.link_email(&email_new, &fpr_primary) {
            info!("Error ensuring email symlink! {} -> {} {:?}",
                  &email_new, &fpr_primary, e);
        }

        Ok(())
    }

    fn nolock_unlink_email_if_other(
        &self,
        fpr_primary: &Fingerprint,
        email: &Email,
    ) -> Result<()> {
        let current_link_fpr = self.lookup_primary_fingerprint(
            &Query::ByEmail(email.clone()));
        if let Some(current_fpr) = current_link_fpr {
            if current_fpr != *fpr_primary {
                self.nolock_set_email_unpublished_filter(
                    &current_fpr, |uid| Email::try_from(uid).unwrap() != *email)?;
            }
        }
        Ok(())
    }

    /// Complex operation that un-publishes some user id for a TPK already in the database.
    ///
    /// 1. Load published TPK
    ///     - if UserID is not in, stop
    /// 2. Load full TPK
    ///     - if requested UserID is not in, stop
    /// 3. Prepare new published TPK
    ///    - retrieve UserIDs from old published TPK
    ///    - create new TPK from full TPK by keeping only published UserIDs
    /// 4. Check for fingerprint and long key id collisions for published TPK
    ///    - abort if any problems come up!
    /// 5. Move full and published temporary TPK to their location
    /// 6. Update all symlinks
    fn set_email_unpublished_filter(
        &self,
        fpr_primary: &Fingerprint,
        email_remove: impl Fn(&UserID) -> bool,
    ) -> Result<()> {
        let _lock = self.lock()?;
        self.nolock_set_email_unpublished_filter(fpr_primary, email_remove)
    }

    fn nolock_set_email_unpublished_filter(
        &self,
        fpr_primary: &Fingerprint,
        email_remove: impl Fn(&UserID) -> bool,
    ) -> Result<()> {
        let published_tpk_old = self.by_fpr(&fpr_primary)
            .ok_or_else(|| failure::err_msg("Key not in database!"))
            .and_then(|bytes| TPK::from_bytes(bytes.as_ref()))?;

        let published_emails_old: Vec<Email> = published_tpk_old
            .userids()
            .map(|binding| binding.userid())
            .map(|uid| Email::try_from(uid))
            .flatten()
            .collect();

        let published_tpk_new = {
            tpk_filter_userids(&published_tpk_old, |uid| email_remove(uid))?
        };

        let published_emails_new: Vec<Email> = published_tpk_new
            .userids()
            .map(|binding| binding.userid())
            .map(|uid| Email::try_from(uid))
            .flatten()
            .collect();

        let unpublished_emails = published_emails_old
            .iter()
            .filter(|email| !published_emails_new.contains(email));

        let published_tpk_clean = tpk_clean(&published_tpk_new)?;
        let published_tpk_tmp = self.write_to_temp(&tpk_to_string(&published_tpk_clean)?)?;

        self.move_tmp_to_published(published_tpk_tmp, &fpr_primary)?;

        for unpublished_email in unpublished_emails {
            if let Err(e) = self.unlink_email(&unpublished_email, &fpr_primary) {
                info!("Error deleting email symlink! {} -> {} {:?}",
                    &unpublished_email, &fpr_primary, e);
            }
        }

        Ok(())
    }

    fn set_email_unpublished(
        &self,
        fpr_primary: &Fingerprint,
        email_remove: &Email,
    ) -> Result<()> {
        self.set_email_unpublished_filter(fpr_primary,
            |uid| Email::try_from(uid).unwrap() != *email_remove
        )
    }

    fn set_email_unpublished_all(
        &self,
        fpr_primary: &Fingerprint,
    ) -> Result<()> {
        self.set_email_unpublished_filter(fpr_primary, |_| false)
    }

    fn regenerate_links(
        &self,
        fpr_primary: &Fingerprint,
    ) -> Result<RegenerateResult> {
        let tpk = self.by_primary_fpr(&fpr_primary)
            .and_then(|bytes| TPK::from_bytes(bytes.as_ref()).ok())
            .ok_or_else(|| failure::err_msg("Key not in database!"))?;

        let published_emails: Vec<Email> = tpk
            .userids()
            .map(|binding| binding.userid())
            .map(|uid| Email::try_from(uid))
            .flatten()
            .collect();

        let fingerprints = tpk_get_linkable_fprs(&tpk);

        let fpr_checks = fingerprints
            .into_iter()
            .map(|fpr| self.check_link_fpr(&fpr, &fpr_primary))
            .collect::<Vec<_>>()
            .into_iter()
            .collect::<Result<Vec<_>>>()?;

        let fpr_not_linked = fpr_checks.into_iter().flatten();

        let mut keys_linked = 0;
        let mut emails_linked = 0;

        for fpr in fpr_not_linked {
            keys_linked += 1;
            if let Err(e) = self.link_fpr(&fpr, &fpr_primary) {
                info!("Error ensuring symlink! {} {} {:?}",
                      &fpr, &fpr_primary, e);
            }
        }

        for email in published_emails {
            emails_linked += 1;
            if let Err(e) = self.link_email(&email, &fpr_primary) {
                info!("Error ensuring email symlink! {} -> {} {:?}",
                    &email, &fpr_primary, e);
            }
        }

        if keys_linked != 0 || emails_linked != 0 {
            Ok(RegenerateResult::Updated)
        } else {
            Ok(RegenerateResult::Unchanged)
        }
    }

    fn check_link_fpr(&self, fpr: &Fingerprint, target: &Fingerprint) -> Result<Option<Fingerprint>>;

    fn by_fpr_full(&self, fpr: &Fingerprint) -> Option<String>;
    fn by_primary_fpr(&self, fpr: &Fingerprint) -> Option<String>;

    fn write_to_temp(&self, content: &[u8]) -> Result<NamedTempFile>;
    fn move_tmp_to_full(&self, content: NamedTempFile, fpr: &Fingerprint) -> Result<()>;
    fn move_tmp_to_published(&self, content: NamedTempFile, fpr: &Fingerprint) -> Result<()>;
    fn write_to_quarantine(&self, fpr: &Fingerprint, content: &[u8]) -> Result<()>;

    fn check_consistency(&self) -> Result<()>;
}

pub fn tpk_get_linkable_fprs(tpk: &TPK) -> Vec<Fingerprint> {
    let ref signing_capable = KeyFlags::empty()
        .set_sign(true)
        .set_certify(true);
    let ref fpr_primary = Fingerprint::try_from(tpk.fingerprint()).unwrap();
    tpk
            .keys_all()
            .into_iter()
            .flat_map(|(sig, _, key)| {
                Fingerprint::try_from(key.fingerprint())
                    .map(|fpr| (fpr, sig.map(|sig| sig.key_flags())))
            })
            .filter(|(fpr, flags)| {
                fpr == fpr_primary ||
                   flags.is_none() ||
                    !(signing_capable & flags.as_ref().unwrap()).is_empty()
            })
            .map(|(fpr,_)| fpr)
            .collect()
}
