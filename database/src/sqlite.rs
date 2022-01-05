use std::convert::TryFrom;
use std::fs::create_dir_all;
use std::path::PathBuf;
use std::str::FromStr;

use std::time::{SystemTime, UNIX_EPOCH};

use openpgp::policy::StandardPolicy;
use types::{Email, Fingerprint, KeyID};
use Result;
use {Database, Query};

use openpgp::Cert;

use r2d2_sqlite::rusqlite::params;
use r2d2_sqlite::rusqlite::OptionalExtension;
use r2d2_sqlite::SqliteConnectionManager;

use crate::wkd;

pub const POLICY: StandardPolicy = StandardPolicy::new();

pub struct Sqlite {
    pool: r2d2::Pool<SqliteConnectionManager>,
}

impl Sqlite {
    pub fn new_file(base_dir: impl Into<PathBuf>) -> Result<Self> {
        let base_dir: PathBuf = base_dir.into();

        let db_file = base_dir.join("keys.sqlite");
        let manager = SqliteConnectionManager::file(db_file);

        Self::new_internal(base_dir, manager)
    }

    pub fn new_memory(base_dir: impl Into<PathBuf>) -> Result<Self> {
        let base_dir: PathBuf = base_dir.into();

        let manager = SqliteConnectionManager::memory();

        Self::new_internal(base_dir, manager)
    }

    #[cfg(test)]
    fn build_pool(manager: SqliteConnectionManager) -> Result<r2d2::Pool<SqliteConnectionManager>> {
        #[derive(Copy, Clone, Debug)]
        pub struct LogConnectionCustomizer;
        impl<E> r2d2::CustomizeConnection<rusqlite::Connection, E> for LogConnectionCustomizer {
            fn on_acquire(&self, conn: &mut rusqlite::Connection) -> std::result::Result<(), E> {
                println!("Acquiring sqlite pool connection: {:?}", conn);
                conn.trace(Some(|query| {
                    println!("{}", query);
                }));
                std::result::Result::Ok(())
            }

            fn on_release(&self, conn: rusqlite::Connection) {
                println!("Releasing pool connection: {:?}", conn);
            }
        }

        Ok(r2d2::Pool::builder()
            .max_size(2)
            .connection_customizer(Box::new(LogConnectionCustomizer {}))
            .build(manager)?)
    }

    #[cfg(not(test))]
    fn build_pool(manager: SqliteConnectionManager) -> Result<r2d2::Pool<SqliteConnectionManager>> {
        Ok(r2d2::Pool::builder().build(manager)?)
    }

    fn new_internal(base_dir: PathBuf, manager: SqliteConnectionManager) -> Result<Self> {
        let keys_dir_log = base_dir.join("log");
        create_dir_all(&keys_dir_log)?;

        let pool = Self::build_pool(manager)?;
        let conn = pool.get()?;
        conn.pragma_update(None, "journal_mode", "wal")?;
        conn.pragma_update(None, "synchronous", "normal")?;
        conn.pragma_update(None, "user_version", "1")?;
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS certs (
                primary_fingerprint    TEXT NOT NULL PRIMARY KEY,
                full                   TEXT NOT NULL,
                published              TEXT,
                published_not_armored  BLOB,
                updated_at             TIMESTAMP NOT NULL,
                created_at             TIMESTAMP NOT NULL
            );
            CREATE TABLE IF NOT EXISTS cert_identifiers (
                fingerprint            TEXT NOT NULL PRIMARY KEY,
                keyid                  TEXT NOT NULL,
                primary_fingerprint    TEXT NOT NULL,
                created_at             TIMESTAMP NOT NULL
            );
            CREATE TABLE IF NOT EXISTS emails (
                email                  TEXT NOT NULL PRIMARY KEY,
                domain                 TEXT NOT NULL,
                wkd_hash               TEXT NOT NULL,
                primary_fingerprint    TEXT NOT NULL,
                created_at             TIMESTAMP NOT NULL
            );
            ",
        )?;

        Ok(Self { pool })
    }
}

impl Database for Sqlite {
    type MutexGuard = String;
    type TempCert = Vec<u8>;

    fn lock(&self) -> Result<Self::MutexGuard> {
        // no need to lock the db. we *should* introduce transactions, though!
        Ok("locked :)".to_owned())
    }

    fn write_to_temp(&self, content: &[u8]) -> Result<Self::TempCert> {
        Ok(content.to_vec())
    }

    fn write_log_append(&self, _filename: &str, _fpr_primary: &Fingerprint) -> Result<()> {
        // this is done implicitly via created_at in sqlite, no need to do anything here
        Ok(())
    }

    fn move_tmp_to_full(&self, file: Self::TempCert, fpr: &Fingerprint) -> Result<()> {
        let conn = self.pool.get()?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as u64;
        let file = String::from_utf8(file)?;
        conn.execute(
            "
            INSERT INTO certs (primary_fingerprint, full, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?3)
            ON CONFLICT(primary_fingerprint) DO UPDATE SET full=excluded.full, updated_at = excluded.updated_at
            ",
            params![fpr.to_string(), file, now],
        )?;
        Ok(())
    }

    fn move_tmp_to_published(&self, file: Self::TempCert, fpr: &Fingerprint) -> Result<()> {
        let conn = self.pool.get()?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as u64;
        let file = String::from_utf8(file)?;
        conn.execute(
            "
            UPDATE certs
            SET published = ?2, updated_at = ?3
            WHERE primary_fingerprint = ?1
            ",
            params![fpr.to_string(), file, now],
        )?;
        Ok(())
    }

    fn move_tmp_to_published_wkd(
        &self,
        file: Option<Self::TempCert>,
        fpr: &Fingerprint,
    ) -> Result<()> {
        let conn = self.pool.get()?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as u64;
        conn.execute(
            "
            UPDATE certs
            SET published_not_armored = ?2, updated_at = ?3
            WHERE primary_fingerprint = ?1
            ",
            params![fpr.to_string(), file, now],
        )?;
        Ok(())
    }

    fn write_to_quarantine(&self, _fpr: &Fingerprint, _content: &[u8]) -> Result<()> {
        Ok(())
    }

    fn check_link_fpr(
        &self,
        fpr: &Fingerprint,
        _fpr_target: &Fingerprint,
    ) -> Result<Option<Fingerprint>> {
        // a desync here cannot happen structurally, so always return true here
        Ok(Some(fpr.clone()))
    }

    fn lookup_primary_fingerprint(&self, term: &Query) -> Option<Fingerprint> {
        use super::Query::*;

        let conn = self.pool.get().unwrap();
        let mut stmt = conn
            .prepare(
                "
            SELECT primary_fingerprint
            FROM cert_identifiers
            WHERE ?1 = ?2
            ",
            )
            .unwrap();
        let fp: Option<String> = match term {
            ByFingerprint(ref fp) => stmt
                .query_row(["fingerprint", &fp.to_string()], |row| row.get(0))
                .optional()
                .unwrap(),
            ByKeyID(ref keyid) => stmt
                .query_row(["keyid", &keyid.to_string()], |row| row.get(0))
                .optional()
                .unwrap(),
            ByEmail(ref email) => conn
                .query_row(
                    "
                    SELECT primary_fingerprint
                    FROM emails
                    WHERE email = ?1
                    ",
                    [email.to_string()],
                    |row| row.get(0),
                )
                .optional()
                .unwrap(),
            _ => None,
        };
        fp.and_then(|fp| Fingerprint::from_str(&fp).ok())
    }

    fn link_email(&self, email: &Email, fpr: &Fingerprint) -> Result<()> {
        let conn = self.pool.get()?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as u64;
        let (domain, wkd_hash) = wkd::encode_wkd(email.as_str()).expect("email must be vaild");
        conn.execute(
            "
            INSERT INTO emails (email, wkd_hash, domain, primary_fingerprint, created_at)
            VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(email) DO UPDATE SET primary_fingerprint = excluded.primary_fingerprint
            ",
            params![email.to_string(), domain, wkd_hash, fpr.to_string(), now],
        )?;
        Ok(())
    }

    fn unlink_email(&self, email: &Email, fpr: &Fingerprint) -> Result<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "
            DELETE FROM emails
            WHERE email = ?1
                AND primary_fingerprint = ?2
            ",
            params![email.to_string(), fpr.to_string(),],
        )
        .unwrap();
        Ok(())
    }

    fn link_fpr(&self, from: &Fingerprint, primary_fpr: &Fingerprint) -> Result<()> {
        let conn = self.pool.get()?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as u64;
        conn.execute(
            "
            INSERT INTO cert_identifiers (fingerprint, keyid, primary_fingerprint, created_at)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(fingerprint) DO UPDATE SET primary_fingerprint = excluded.primary_fingerprint;
            ",
            params![
                from.to_string(),
                KeyID::try_from(from)?.to_string(),
                primary_fpr.to_string(),
                now,
            ],
        )?;
        Ok(())
    }

    fn unlink_fpr(&self, from: &Fingerprint, primary_fpr: &Fingerprint) -> Result<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "
            DELETE FROM cert_identifiers
            WHERE primary_fingerprint = ?1
                AND fingerprint = ?2
                AND keyid = ?3
            ",
            params![
                primary_fpr.to_string(),
                from.to_string(),
                KeyID::try_from(from)?.to_string()
            ],
        )?;
        Ok(())
    }

    // Lookup straight from certs table, no link resolution
    fn by_fpr_full(&self, fpr: &Fingerprint) -> Option<String> {
        let conn = self.pool.get().unwrap();
        let armored_cert: Option<String> = conn
            .query_row(
                "
            SELECT full
            FROM certs
            WHERE primary_fingerprint = ?1
            ",
                [fpr.to_string()],
                |row| row.get(0),
            )
            .optional()
            .unwrap();
        armored_cert
    }

    // XXX: rename! to by_primary_fpr_published
    // Lookup the published cert straight from certs table, no link resolution
    fn by_primary_fpr(&self, fpr: &Fingerprint) -> Option<String> {
        let conn = self.pool.get().unwrap();
        let armored_cert: Option<Option<String>> = conn
            .query_row(
                "
            SELECT published
            FROM certs
            WHERE primary_fingerprint = ?1
            ",
                [fpr.to_string()],
                |row| row.get(0),
            )
            .optional()
            .unwrap();
        armored_cert.flatten()
    }

    fn by_fpr(&self, fpr: &Fingerprint) -> Option<String> {
        let conn = self.pool.get().unwrap();
        let primary_fingerprint: Option<String> = conn
            .query_row(
                "
            SELECT primary_fingerprint
            FROM cert_identifiers
            WHERE fingerprint = ?1
            ",
                [fpr.to_string()],
                |row| row.get(0),
            )
            .optional()
            .unwrap();
        if let Some(primary_fingerprint) = primary_fingerprint {
            self.by_primary_fpr(&Fingerprint::from_str(&primary_fingerprint).unwrap())
        } else {
            None
        }
    }

    fn by_email(&self, email: &Email) -> Option<String> {
        let conn = self.pool.get().unwrap();
        let primary_fingerprint: Option<String> = conn
            .query_row(
                "
            SELECT primary_fingerprint
            FROM emails
            WHERE email = ?1
            ",
                [email.to_string()],
                |row| row.get(0),
            )
            .optional()
            .unwrap();
        if let Some(primary_fingerprint) = primary_fingerprint {
            self.by_primary_fpr(&Fingerprint::from_str(&primary_fingerprint).unwrap())
        } else {
            None
        }
    }

    fn by_email_wkd(&self, email: &Email) -> Option<Vec<u8>> {
        let conn = self.pool.get().unwrap();
        let primary_fingerprint: Option<String> = conn
            .query_row(
                "
            SELECT primary_fingerprint
            FROM emails
            WHERE email = ?1
            ",
                [email.to_string()],
                |row| row.get(0),
            )
            .optional()
            .unwrap();
        let binary_cert: Option<Vec<u8>> = conn
            .query_row(
                "
            SELECT published_not_armored
            FROM certs
            WHERE primary_fingerprint = ?1
            ",
                [primary_fingerprint],
                |row| row.get(0),
            )
            .optional()
            .unwrap();
        binary_cert
    }

    fn by_kid(&self, kid: &KeyID) -> Option<String> {
        let conn = self.pool.get().unwrap();
        let primary_fingerprint: Option<String> = conn
            .query_row(
                "
            SELECT primary_fingerprint
            FROM cert_identifiers
            WHERE keyid = ?1
            ",
                [kid.to_string()],
                |row| row.get(0),
            )
            .optional()
            .unwrap();
        if let Some(primary_fingerprint) = primary_fingerprint {
            self.by_primary_fpr(&Fingerprint::from_str(&primary_fingerprint).unwrap())
        } else {
            None
        }
    }

    fn by_domain_and_hash_wkd(&self, domain: &str, wkd_hash: &str) -> Option<Vec<u8>> {
        let conn = self.pool.get().unwrap();
        let primary_fingerprint: Option<String> = conn
            .query_row(
                "
            SELECT primary_fingerprint
            FROM emails
            WHERE domain = ?1, wkd_hash = ?2
            ",
                [domain, wkd_hash],
                |row| row.get(0),
            )
            .optional()
            .unwrap();
        let binary_cert: Option<Vec<u8>> = conn
            .query_row(
                "
            SELECT published_not_armored
            FROM certs
            WHERE primary_fingerprint = ?1
            ",
                [primary_fingerprint],
                |row| row.get(0),
            )
            .optional()
            .unwrap();
        binary_cert
    }

    /// Checks the database for consistency.
    ///
    /// Note that this operation may take a long time, and is
    /// generally only useful for testing.
    fn check_consistency(&self) -> Result<()> {
        let conn = self.pool.get().unwrap();
        let mut stmt = conn.prepare("SELECT primary_fingerprint, published FROM certs")?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let primary_fpr: Fingerprint = row.get(0)?;
            let published: String = row.get(1)?;
            let cert = Cert::from_str(&published).unwrap();

            let mut cert_emails: Vec<Email> = cert
                .userids()
                .map(|uid| uid.userid().email2().unwrap())
                .flatten()
                .map(|email| Email::from_str(&email))
                .flatten()
                .collect();
            let mut db_emails: Vec<Email> = conn
                .prepare("SELECT email FROM emails WHERE primary_fingerprint = ?1")?
                .query_map([primary_fpr.to_string()], |row| row.get::<_, String>(0))
                .unwrap()
                .map(|email| Email::from_str(&email.unwrap()))
                .flatten()
                .collect();
            cert_emails.sort();
            cert_emails.dedup();
            db_emails.sort();
            if cert_emails != db_emails {
                return Err(format_err!(
                    "{:?} does not have correct emails indexed, cert ${:?} db {:?}",
                    primary_fpr,
                    cert_emails,
                    db_emails,
                ));
            }

            let policy = &POLICY;
            let mut cert_fprs: Vec<Fingerprint> = cert
                .keys()
                .with_policy(policy, None)
                .for_certification()
                .for_signing()
                .map(|amalgamation| amalgamation.key().fingerprint())
                .map(Fingerprint::try_from)
                .flatten()
                .collect();
            let mut db_fprs: Vec<Fingerprint> = conn
                .prepare("SELECT fingerprint FROM cert_identifiers WHERE primary_fingerprint = ?1")?
                .query_map([primary_fpr.to_string()], |row| {
                    row.get::<_, Fingerprint>(0)
                })
                .unwrap()
                .flatten()
                .collect();
            cert_fprs.sort();
            db_fprs.sort();
            if cert_fprs != db_fprs {
                return Err(format_err!(
                    "{:?} does not have correct fingerprints indexed, cert ${:?} db {:?}",
                    primary_fpr,
                    cert_fprs,
                    db_fprs,
                ));
            }
        }
        Ok(())
    }

    fn get_last_log_entry(&self) -> Result<Fingerprint> {
        let conn = self.pool.get().unwrap();
        Ok(conn.query_row(
            "SELECT primary_fingerprint FROM certs ORDER BY updated_at DESC LIMIT 1",
            [],
            |row| row.get::<_, Fingerprint>(0),
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openpgp::cert::CertBuilder;
    use tempfile::TempDir;
    use test;

    const DATA_1: &str = "data, content doesn't matter";
    const DATA_2: &str = "other data, content doesn't matter";
    const FINGERPRINT_1: &str = "D4AB192964F76A7F8F8A9B357BD18320DEADFA11";

    fn open_db() -> (TempDir, Sqlite) {
        let tmpdir = TempDir::new().unwrap();
        let db = Sqlite::new_file(tmpdir.path()).unwrap();
        (tmpdir, db)
    }

    #[test]
    fn new() {
        let (_tmp_dir, db) = open_db();
        let k1 = CertBuilder::new()
            .add_userid("a@invalid.example.org")
            .generate()
            .unwrap()
            .0;
        let k2 = CertBuilder::new()
            .add_userid("b@invalid.example.org")
            .generate()
            .unwrap()
            .0;
        let k3 = CertBuilder::new()
            .add_userid("c@invalid.example.org")
            .generate()
            .unwrap()
            .0;

        assert!(db.merge(k1).unwrap().into_tpk_status().email_status.len() > 0);
        assert!(
            db.merge(k2.clone())
                .unwrap()
                .into_tpk_status()
                .email_status
                .len()
                > 0
        );
        assert!(!db.merge(k2).unwrap().into_tpk_status().email_status.len() > 0);
        assert!(
            db.merge(k3.clone())
                .unwrap()
                .into_tpk_status()
                .email_status
                .len()
                > 0
        );
        assert!(
            !db.merge(k3.clone())
                .unwrap()
                .into_tpk_status()
                .email_status
                .len()
                > 0
        );
        assert!(!db.merge(k3).unwrap().into_tpk_status().email_status.len() > 0);
    }

    #[test]
    fn xx_by_fpr_full() -> Result<()> {
        let (_tmp_dir, db) = open_db();
        let fpr1 = Fingerprint::from_str(FINGERPRINT_1)?;

        db.move_tmp_to_full(db.write_to_temp(DATA_1.as_bytes())?, &fpr1)?;
        db.link_fpr(&fpr1, &fpr1)?;

        assert_eq!(db.by_fpr_full(&fpr1).expect("must find key"), DATA_1);
        Ok(())
    }

    #[test]
    fn xx_by_kid() -> Result<()> {
        let (_tmp_dir, db) = open_db();
        let fpr1 = Fingerprint::from_str(FINGERPRINT_1)?;

        db.move_tmp_to_full(db.write_to_temp(DATA_1.as_bytes())?, &fpr1)?;
        db.move_tmp_to_published(db.write_to_temp(DATA_2.as_bytes())?, &fpr1)?;
        db.link_fpr(&fpr1, &fpr1)?;

        assert_eq!(db.by_kid(&fpr1.into()).expect("must find key"), DATA_2);
        Ok(())
    }

    #[test]
    fn xx_by_primary_fpr() -> Result<()> {
        let (_tmp_dir, db) = open_db();
        let fpr1 = Fingerprint::from_str(FINGERPRINT_1)?;

        db.move_tmp_to_full(db.write_to_temp(DATA_1.as_bytes())?, &fpr1)?;
        db.move_tmp_to_published(db.write_to_temp(DATA_2.as_bytes())?, &fpr1)?;

        assert_eq!(db.by_primary_fpr(&fpr1).expect("must find key"), DATA_2);
        Ok(())
    }

    #[test]
    fn uid_verification() {
        let (_tmp_dir, mut db) = open_db();
        test::test_uid_verification(&mut db);
        db.check_consistency().expect("inconsistent database");
    }

    #[test]
    fn uid_deletion() {
        let (_tmp_dir, mut db) = open_db();
        test::test_uid_deletion(&mut db);
        db.check_consistency().expect("inconsistent database");
    }

    #[test]
    fn subkey_lookup() {
        let (_tmp_dir, mut db) = open_db();
        test::test_subkey_lookup(&mut db);
        db.check_consistency().expect("inconsistent database");
    }

    #[test]
    fn kid_lookup() {
        let (_tmp_dir, mut db) = open_db();
        test::test_kid_lookup(&mut db);
        db.check_consistency().expect("inconsistent database");
    }

    #[test]
    fn upload_revoked_tpk() {
        let (_tmp_dir, mut db) = open_db();
        test::test_upload_revoked_tpk(&mut db);
        db.check_consistency().expect("inconsistent database");
    }

    #[test]
    fn uid_revocation() {
        let (_tmp_dir, mut db) = open_db();
        test::test_uid_revocation(&mut db);
        db.check_consistency().expect("inconsistent database");
    }

    #[test]
    fn regenerate() {
        let (_tmp_dir, mut db) = open_db();
        test::test_regenerate(&mut db);
        db.check_consistency().expect("inconsistent database");
    }

    #[test]
    fn key_reupload() {
        let (_tmp_dir, mut db) = open_db();
        test::test_reupload(&mut db);
        db.check_consistency().expect("inconsistent database");
    }

    #[test]
    fn uid_replacement() {
        let (_tmp_dir, mut db) = open_db();
        test::test_uid_replacement(&mut db);
        db.check_consistency().expect("inconsistent database");
    }

    #[test]
    fn uid_unlinking() {
        let (_tmp_dir, mut db) = open_db();
        test::test_unlink_uid(&mut db);
        db.check_consistency().expect("inconsistent database");
    }

    #[test]
    fn same_email_1() {
        let (_tmp_dir, mut db) = open_db();
        test::test_same_email_1(&mut db);
        db.check_consistency().expect("inconsistent database");
    }

    #[test]
    fn same_email_2() {
        let (_tmp_dir, mut db) = open_db();
        test::test_same_email_2(&mut db);
        db.check_consistency().expect("inconsistent database");
    }

    #[test]
    fn same_email_3() {
        let (_tmp_dir, mut db) = open_db();
        test::test_same_email_3(&mut db);
        db.check_consistency().expect("inconsistent database");
    }

    #[test]
    fn same_email_4() {
        let (_tmp_dir, mut db) = open_db();
        test::test_same_email_4(&mut db);
        db.check_consistency().expect("inconsistent database");
    }

    #[test]
    fn no_selfsig() {
        let (_tmp_dir, mut db) = open_db();
        test::test_no_selfsig(&mut db);
        db.check_consistency().expect("inconsistent database");
    }

    #[test]
    fn bad_uids() {
        let (_tmp_dir, mut db) = open_db();
        test::test_bad_uids(&mut db);
        db.check_consistency().expect("inconsistent database");
    }

    #[test]
    fn reverse_fingerprint_to_path() {
        let tmpdir = TempDir::new().unwrap();
        let db = Sqlite::new_file(tmpdir.path()).unwrap();

        let _fp: Fingerprint = "CBCD8F030588653EEDD7E2659B7DD433F254904A".parse().unwrap();

        // XXX: fixme
        //assert_eq!(Sqlite::path_to_fingerprint(&db.link_by_fingerprint(&fp)),
        //           Some(fp.clone()));
        db.check_consistency().expect("inconsistent database");
    }

    #[test]
    fn attested_key_signatures() -> Result<()> {
        let (_tmp_dir, mut db) = open_db();
        test::attested_key_signatures(&mut db)?;
        db.check_consistency()?;
        Ok(())
    }

    #[test]
    fn nonexportable_sigs() -> Result<()> {
        let (_tmp_dir, mut db) = open_db();
        test::nonexportable_sigs(&mut db)?;
        db.check_consistency()?;
        Ok(())
    }
}
