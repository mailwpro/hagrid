use std::convert::TryFrom;
use std::fs::{create_dir_all, File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::str::FromStr;

use std::time::SystemTime;

use sync::FlockMutexGuard;
use types::{Email, Fingerprint, KeyID};
use Result;
use {Database, Query};

use wkd;

use openpgp::parse::Parse;
use openpgp::Cert;
use openpgp_utils::POLICY;

use r2d2_sqlite::rusqlite::params;
use r2d2_sqlite::rusqlite::OptionalExtension;
use r2d2_sqlite::rusqlite::Result as RusqliteResult;
use r2d2_sqlite::SqliteConnectionManager;

pub struct Sqlite {
    pool: r2d2::Pool<SqliteConnectionManager>,
    keys_db_file: PathBuf,
    keys_dir_log: PathBuf,
    dry_run: bool,
}

impl Sqlite {
    pub fn new(base_dir: impl Into<PathBuf>) -> Result<Self> {
        let base_dir: PathBuf = base_dir.into();

        let keys_db_file = base_dir.join("keys.sqlite");
        let manager = SqliteConnectionManager::file(&keys_db_file);

        let keys_dir_log = base_dir.join("log");
        create_dir_all(&keys_dir_log)?;

        let dry_run = false;

        let pool = Self::build_pool(manager)?;
        let conn = pool.get()?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS certs (
                fingerprint            TEXT NOT NULL PRIMARY KEY,
                full                   TEXT NOT NULL,
                published              TEXT, --make this NOT NULL later
                published_not_armored  BLOB
            )",
            [],
        )?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS cert_identifiers (
                fingerprint            TEXT NOT NULL UNIQUE,
                keyid                  TEXT NOT NULL UNIQUE AS (substr(fingerprint, -16)),

                primary_fingerprint    TEXT NOT NULL
            )",
            [],
        )?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS emails (
                email                  TEXT NOT NULL UNIQUE,
                primary_fingerprint    TEXT NOT NULL
            )",
            [],
        )?;

        Ok(Self { pool, keys_db_file, keys_dir_log, dry_run })
    }

    #[cfg(test)]
    fn build_pool(
        manager: SqliteConnectionManager,
    ) -> Result<r2d2::Pool<SqliteConnectionManager>> {
        #[derive(Copy, Clone, Debug)]
        pub struct LogConnectionCustomizer;
        impl<E> r2d2::CustomizeConnection<rusqlite::Connection, E>
            for LogConnectionCustomizer
        {
            fn on_acquire(
                &self,
                conn: &mut rusqlite::Connection,
            ) -> std::result::Result<(), E> {
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
    fn build_pool(
        manager: SqliteConnectionManager,
    ) -> Result<r2d2::Pool<SqliteConnectionManager>> {
        Ok(r2d2::Pool::builder().max_size(2).build(manager)?)
    }

    fn primary_fpr_by_any_fpr(
        &self,
        fpr: &Fingerprint,
    ) -> Result<Option<Fingerprint>> {
        let conn = self.pool.get().unwrap();
        let primary_fingerprint: Option<Fingerprint> = conn
            .query_row(
                "
                SELECT primary_fingerprint
                FROM cert_identifiers
                WHERE fingerprint = ?1
                ",
                [fpr.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        Ok(primary_fingerprint)
    }

    fn primary_fpr_by_any_kid(
        &self,
        kid: &KeyID,
    ) -> Result<Option<Fingerprint>> {
        let conn = self.pool.get().unwrap();
        let primary_fingerprint: Option<Fingerprint> = conn
            .query_row(
                "
                SELECT primary_fingerprint
                FROM cert_identifiers
                WHERE keyid = ?1
                ",
                [kid.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        Ok(primary_fingerprint)
    }

    fn open_logfile(&self, file_name: &str) -> Result<File> {
        let file_path = self.keys_dir_log.join(file_name);
        Ok(OpenOptions::new().create(true).append(true).open(file_path)?)
    }
}

impl Database for Sqlite {
    type MutexGuard = FlockMutexGuard;
    type TempCert = Vec<u8>;

    fn lock(&self) -> Result<Self::MutexGuard> {
        FlockMutexGuard::lock(&self.keys_db_file)
    }

    fn write_to_temp(&self, content: &[u8]) -> Result<Self::TempCert> {
        Ok(content.to_vec())
    }

    fn write_log_append(
        &self,
        filename: &str,
        fpr_primary: &Fingerprint,
    ) -> Result<()> {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let fingerprint_line =
            format!("{:010} {}\n", timestamp, fpr_primary.to_string());

        self.open_logfile(filename)?.write_all(fingerprint_line.as_bytes())?;

        Ok(())
    }

    fn move_tmp_to_full(
        &self,
        file: Self::TempCert,
        fpr: &Fingerprint,
    ) -> Result<()> {
        let conn = self.pool.get()?;
        let file = String::from_utf8(file)?;
        conn.execute(
            "
            INSERT INTO certs (fingerprint, full)
            VALUES (?1, ?2)
            ON CONFLICT(fingerprint) DO UPDATE SET full=excluded.full;
            ",
            params![fpr.to_string(), file],
        )?;
        Ok(())
    }

    fn move_tmp_to_published(
        &self,
        file: Self::TempCert,
        fpr: &Fingerprint,
    ) -> Result<()> {
        let conn = self.pool.get()?;
        let file = String::from_utf8(file)?;
        conn.execute(
            "
            UPDATE certs
            SET published = ?2
            WHERE fingerprint = ?1
            ",
            params![fpr.to_string(), file],
        )?;
        Ok(())
    }

    fn move_tmp_to_published_wkd(
        &self,
        file: Option<Self::TempCert>,
        fpr: &Fingerprint,
    ) -> Result<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "
            UPDATE certs
            SET published_not_armored = ?2
            WHERE fingerprint = ?1
            ",
            params![fpr.to_string(), file],
        )?;
        Ok(())
    }

    // TODO!
    fn write_to_quarantine(
        &self,
        fpr: &Fingerprint,
        content: &[u8],
    ) -> Result<()> {
        Ok(())
    }

    fn check_link_fpr(
        &self,
        fpr: &Fingerprint,
        fpr_target: &Fingerprint,
    ) -> Result<Option<Fingerprint>> {
        let fpr_check = match self.primary_fpr_by_any_fpr(fpr)? {
            None => Some(fpr.clone()),
            Some(actual_primary) => {
                if &actual_primary == fpr_target {
                    None
                } else {
                    info!(
                        "Fingerprint points to different key for {}
                          (already links to {:?} but {:?} requested)",
                        fpr, actual_primary, fpr_target
                    );
                    return Err(anyhow!(format!(
                        "Fingerprint collision for key {}",
                        fpr
                    )));
                }
            }
        };
        let kid_check = match self.primary_fpr_by_any_kid(&KeyID::from(fpr))? {
            None => Some(fpr.clone()),
            Some(actual_primary) => {
                if &actual_primary == fpr_target {
                    None
                } else {
                    info!(
                        "KeyID points to different key for {}
                          (already links to {:?} but {:?} requested)",
                        fpr, actual_primary, fpr_target
                    );
                    return Err(anyhow!(format!(
                        "KeyID collision for key {}",
                        fpr
                    )));
                }
            }
        };
        Ok(fpr_check.and(kid_check))
    }

    fn lookup_primary_fingerprint(&self, term: &Query) -> Option<Fingerprint> {
        use super::Query::*;

        let conn = self.pool.get().unwrap();
        let fp: Option<Option<Fingerprint>> = match term {
            ByFingerprint(ref fp) => {
                conn.query_row(
                    "
                    SELECT primary_fingerprint
                    FROM cert_identifiers
                    WHERE fingerprint = ?1
                    ",
                    [&fp.to_string()],
                    |row| row.get(0),
                )
                .optional()
                .unwrap()
            }
            ByKeyID(ref keyid) => {
                conn.query_row(
                    "
                    SELECT primary_fingerprint
                    FROM cert_identifiers
                    WHERE keyid = ?1
                    ",
                    [&keyid.to_string()],
                    |row| row.get(0),
                )
                .optional()
                .unwrap()
            }
            ByEmail(ref email) => {
                conn.query_row(
                    "
                    SELECT primary_fingerprint
                    FROM emails
                    WHERE email = ?1
                    ",
                    [email.to_string()],
                    |row| row.get(0),
                )
                .optional()
                .unwrap()
            }
            _ => None,
        };
        fp.flatten()
    }

    fn link_email(&self, email: &Email, fpr: &Fingerprint) -> Result<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "
            INSERT INTO emails (email, primary_fingerprint)
            VALUES (?1, ?2)
            ON CONFLICT(email) DO UPDATE
                SET email=excluded.email, primary_fingerprint=excluded.primary_fingerprint
            ",
            params![
                email.to_string(),
                fpr.to_string(),
            ],
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
        )?;
        Ok(())
    }

    // XXX: Rename to link_fpr_kid
    fn link_fpr(
        &self,
        from: &Fingerprint,
        primary_fpr: &Fingerprint,
    ) -> Result<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "
            INSERT INTO cert_identifiers (primary_fingerprint, fingerprint)
            VALUES (?1, ?2)
            ON CONFLICT(fingerprint) DO UPDATE
                SET fingerprint=excluded.fingerprint,
                    primary_fingerprint=excluded.primary_fingerprint;
            ",
            params![primary_fpr.to_string(), from.to_string(),],
        )?;
        Ok(())
    }

    // XXX: Rename to unlink_fpr_kid
    fn unlink_fpr(
        &self,
        from: &Fingerprint,
        primary_fpr: &Fingerprint,
    ) -> Result<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "
            DELETE FROM cert_identifiers
            WHERE primary_fingerprint = ?1
                AND fingerprint = ?2
            ",
            params![primary_fpr.to_string(), from.to_string(),],
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
                WHERE fingerprint = ?1
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
        let armored_cert: Option<String> = conn
            .query_row(
                "
                SELECT published
                FROM certs
                WHERE fingerprint = ?1
                ",
                [fpr.to_string()],
                |row| row.get(0),
            )
            .optional()
            .unwrap();
        armored_cert
    }

    // XXX: Rename: armored_cert_by_any_fpr
    fn by_fpr(&self, fpr: &Fingerprint) -> Option<String> {
        let primary_fingerprint = self.primary_fpr_by_any_fpr(fpr).unwrap();
        primary_fingerprint.and_then(|fp| self.by_primary_fpr(&fp))
    }

    // XXX: slow
    // XXX: Rename: armored_cert_by_email
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
            self.by_primary_fpr(
                &Fingerprint::from_str(&primary_fingerprint).unwrap(),
            )
        } else {
            None
        }
    }

    // XXX: return results
    // TODO: Test!
    // XXX: Rename: binary_cert_by_email
    fn by_email_wkd(&self, email: &Email) -> Option<Vec<u8>> {
        let conn = self.pool.get().unwrap();
        let primary_fingerprint: Option<Fingerprint> = conn
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
        match primary_fingerprint {
            Some(primary_fingerprint) => {
                let binary_cert: Option<Vec<u8>> = conn
                    .query_row(
                        "
                        SELECT published_not_armored
                        FROM certs
                        WHERE fingerprint = ?1
                        ",
                        [primary_fingerprint.to_string()],
                        |row| row.get(0),
                    )
                    .optional()
                    .unwrap();
                binary_cert
            }
            None => None,
        }
    }

    // XXX: Rename: armored_cert_by_any_kid
    fn by_kid(&self, kid: &KeyID) -> Option<String> {
        // XXX: error handling
        let primary_fingerprint = self.primary_fpr_by_any_kid(kid).unwrap();
        primary_fingerprint.and_then(|fp| self.by_primary_fpr(&fp))
    }

    /// Checks the database for consistency.
    ///
    /// Note that this operation may take a long time, and is
    /// generally only useful for testing.
    fn check_consistency(&self) -> Result<()> {
        // Check for each published cert:
        // - all userids (emails) from the published cert point to the cert
        // - no other userids point to the cert
        // - all fingerprints of published signing subkeys point to the cert
        //   (cert_identifiers)
        // - no other subkey fingerprints point to the cert
        // - all keyids of signing subkeys and of the primary key point to the cert
        //   (cert_identifiers)
        // - no other subkey fingerprints point to the cert
        // - Published armored and published binary must match
        let conn = self.pool.get().unwrap();
        let mut cert_stmt = conn.prepare(
            "
            SELECT fingerprint, published, published_not_armored
            FROM certs
            ",
        )?;
        for row in cert_stmt.query_map([], |row| {
            // TODO: create a struct which implements FromSql for this
            Ok((
                row.get::<_, Fingerprint>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<Vec<u8>>>(2)?,
            ))
        })? {
            let (primary_fp, published, published_not_armored) = row?;
            let tpk = Cert::from_str(&published)?;

            // - all userids (emails) from the published cert point to the cert
            // - no other userids point to the cert
            let mut published_userids = tpk
                .userids()
                .map(|binding| binding.userid().clone())
                .map(|userid| Email::try_from(&userid).unwrap())
                .collect::<Vec<Email>>();
            published_userids.sort_unstable();
            published_userids.dedup();
            let mut stmt = conn.prepare(
                "
                SELECT email
                FROM emails
                WHERE primary_fingerprint = ?1
                ",
            )?;
            let mut linking_userids = stmt
                .query_map([&primary_fp.to_string()], |row| {
                    row.get::<_, Email>(0)
                })?
                .collect::<RusqliteResult<Vec<Email>>>()?;
            linking_userids.sort_unstable();
            if linking_userids != published_userids {
                return Err(anyhow!(
                    "For fingerprint {}, published {:?} but linked {:?}",
                    primary_fp,
                    published_userids,
                    linking_userids
                ));
            }

            // - all fingerprints of published signing subkeys point to the cert
            //   (cert_identifiers)
            // - no other subkey fingerprints point to the cert
            let policy = &POLICY;
            let mut published_fps = tpk
                .keys()
                .with_policy(policy, None)
                .for_certification()
                .for_signing()
                .map(|amalgamation| amalgamation.key().fingerprint())
                .flat_map(Fingerprint::try_from)
                .collect::<Vec<_>>();
            published_fps.sort_unstable();
            published_fps.dedup();
            let mut stmt = conn.prepare(
                "
                SELECT fingerprint
                FROM cert_identifiers
                WHERE primary_fingerprint = ?1
                ",
            )?;
            let mut linking_fps = stmt
                .query_map([&primary_fp.to_string()], |row| {
                    row.get::<_, Fingerprint>(0)
                })?
                .collect::<RusqliteResult<Vec<Fingerprint>>>()?;
            linking_fps.sort_unstable();
            if linking_fps != published_fps {
                return Err(anyhow!(
                    "For fingerprint {}, published subkeys Fingerprints {:?}
                        but linked {:?}",
                    primary_fp,
                    published_fps,
                    linking_fps
                ));
            }

            // - all keyids of signing subkeys and of the primary key point to the cert
            //   (cert_identifiers)
            // - no other subkey fingerprints point to the cert
            let policy = &POLICY;
            let mut published_kids = tpk
                .keys()
                .with_policy(policy, None)
                .for_certification()
                .for_signing()
                .map(|amalgamation| amalgamation.key().fingerprint())
                .flat_map(KeyID::try_from)
                .collect::<Vec<_>>();
            published_kids.sort_unstable();
            published_kids.dedup();
            let mut stmt = conn.prepare(
                "
                SELECT keyid
                FROM cert_identifiers
                WHERE primary_fingerprint = ?1
                ",
            )?;
            let mut linking_kids = stmt
                .query_map([&primary_fp.to_string()], |row| {
                    row.get::<_, KeyID>(0)
                })?
                .collect::<RusqliteResult<Vec<KeyID>>>()?;
            linking_kids.sort_unstable();
            if linking_kids != published_kids {
                return Err(anyhow!(
                    "For fingerprint {}, published subkey KeyIDs {:?}
                        but linked {:?}",
                    primary_fp,
                    published_kids,
                    linking_kids
                ));
            }

            // - Published armored and published binary must match
            if let Some(pna) = published_not_armored {
                if Cert::from_bytes(&pna)? != tpk {
                    return Err(anyhow!(
                        "For fingerprint {}, published and
                                published_not_armored do not match",
                        primary_fp,
                    ));
                }
            }
        }
        Ok(())
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

    fn open_db() -> (TempDir, Sqlite, PathBuf) {
        let tmpdir = TempDir::new().unwrap();

        let db = Sqlite::new(tmpdir.path()).unwrap();
        let log_path = db.keys_dir_log.join(db.get_current_log_filename());

        (tmpdir, db, log_path)
    }

    #[test]
    fn new() {
        use crate::ImportResult;

        let (_tmp_dir, db, _log_path) = open_db();
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
            .add_userid("d@invalid.example.org")
            .generate()
            .unwrap()
            .0;

        assert!(matches!(
                db.merge(k1).unwrap(),
                ImportResult::New(status) if status.email_status.len() == 1));
        assert!(matches!(
                db.merge(k2.clone()).unwrap(),
                ImportResult::New(status) if status.email_status.len() == 1));
        assert!(matches!(
                db.merge(k2).unwrap(),
                ImportResult::Unchanged(status) if status.email_status.len() == 1));
        assert!(matches!(
                db.merge(k3.clone()).unwrap(),
                ImportResult::New(status) if status.email_status.len() == 2));
        assert!(matches!(
                db.merge(k3).unwrap(),
                ImportResult::Unchanged(status) if status.email_status.len() == 2));
    }

    #[test]
    fn xx_by_fpr_full() -> Result<()> {
        let (_tmp_dir, db, _log_path) = open_db();
        let fpr1 = Fingerprint::from_str(FINGERPRINT_1)?;

        db.move_tmp_to_full(db.write_to_temp(DATA_1.as_bytes())?, &fpr1)?;
        db.link_fpr(&fpr1, &fpr1)?;

        assert_eq!(db.by_fpr_full(&fpr1).expect("must find key"), DATA_1);
        Ok(())
    }

    #[test]
    fn xx_by_kid() -> Result<()> {
        let (_tmp_dir, db, _log_path) = open_db();
        let fpr1 = Fingerprint::from_str(FINGERPRINT_1)?;

        db.move_tmp_to_full(db.write_to_temp(DATA_1.as_bytes())?, &fpr1)?;
        db.move_tmp_to_published(db.write_to_temp(DATA_2.as_bytes())?, &fpr1)?;
        db.link_fpr(&fpr1, &fpr1)?;

        assert_eq!(db.by_kid(&fpr1.into()).expect("must find key"), DATA_2);
        Ok(())
    }

    #[test]
    fn xx_by_primary_fpr() -> Result<()> {
        let (_tmp_dir, db, _log_path) = open_db();
        let fpr1 = Fingerprint::from_str(FINGERPRINT_1)?;

        db.move_tmp_to_full(db.write_to_temp(DATA_1.as_bytes())?, &fpr1)?;
        db.move_tmp_to_published(db.write_to_temp(DATA_2.as_bytes())?, &fpr1)?;

        assert_eq!(db.by_primary_fpr(&fpr1).expect("must find key"), DATA_2);
        Ok(())
    }

    #[test]
    fn lookup_primary_fingerprint() -> Result<()> {
        use TryFrom;
        let (_tmp_dir, db, _log_path) = open_db();

        let email = Email::from_str("a@invalid.example.org")?;
        let cert = CertBuilder::new()
            .add_userid(email.to_string())
            .generate()
            .unwrap()
            .0;
        let expected_fp =
            Fingerprint::try_from(cert.primary_key().fingerprint())?;

        db.merge(cert)?;
        db.link_email(&email, &expected_fp)?;

        assert_eq!(
            expected_fp,
            db.lookup_primary_fingerprint(&crate::Query::ByFingerprint(
                expected_fp.clone()
            ))
            .unwrap()
        );
        assert_eq!(
            expected_fp,
            db.lookup_primary_fingerprint(&crate::Query::ByKeyID(
                expected_fp.clone().into()
            ))
            .unwrap()
        );
        assert_eq!(
            expected_fp,
            db.lookup_primary_fingerprint(&crate::Query::ByEmail(email))
                .unwrap()
        );
        Ok(())
    }

    #[test]
    fn uid_verification() {
        let (_tmp_dir, mut db, log_path) = open_db();
        test::test_uid_verification(&mut db, &log_path);
        db.check_consistency().expect("inconsistent database");
    }

    #[test]
    fn uid_deletion() {
        let (_tmp_dir, mut db, log_path) = open_db();
        test::test_uid_deletion(&mut db, &log_path);
        db.check_consistency().expect("inconsistent database");
    }

    #[test]
    fn subkey_lookup() {
        let (_tmp_dir, mut db, log_path) = open_db();
        test::test_subkey_lookup(&mut db, &log_path);
        db.check_consistency().expect("inconsistent database");
    }

    #[test]
    fn kid_lookup() {
        let (_tmp_dir, mut db, log_path) = open_db();
        test::test_kid_lookup(&mut db, &log_path);
        db.check_consistency().expect("inconsistent database");
    }

    #[test]
    fn upload_revoked_tpk() {
        let (_tmp_dir, mut db, log_path) = open_db();
        test::test_upload_revoked_tpk(&mut db, &log_path);
        db.check_consistency().expect("inconsistent database");
    }

    #[test]
    fn uid_revocation() {
        let (_tmp_dir, mut db, log_path) = open_db();
        test::test_uid_revocation(&mut db, &log_path);
        db.check_consistency().expect("inconsistent database");
    }

    #[test]
    fn regenerate() {
        let (_tmp_dir, mut db, log_path) = open_db();
        test::test_regenerate(&mut db, &log_path);
        db.check_consistency().expect("inconsistent database");
    }

    #[test]
    fn key_reupload() {
        let (_tmp_dir, mut db, log_path) = open_db();
        test::test_reupload(&mut db, &log_path);
        db.check_consistency().expect("inconsistent database");
    }

    #[test]
    fn uid_replacement() {
        let (_tmp_dir, mut db, log_path) = open_db();
        test::test_uid_replacement(&mut db, &log_path);
        db.check_consistency().expect("inconsistent database");
    }

    #[test]
    fn uid_unlinking() {
        let (_tmp_dir, mut db, log_path) = open_db();
        test::test_unlink_uid(&mut db, &log_path);
        db.check_consistency().expect("inconsistent database");
    }

    #[test]
    fn same_email_1() {
        let (_tmp_dir, mut db, log_path) = open_db();
        test::test_same_email_1(&mut db, &log_path);
        db.check_consistency().expect("inconsistent database");
    }

    #[test]
    fn same_email_2() {
        let (_tmp_dir, mut db, log_path) = open_db();
        test::test_same_email_2(&mut db, &log_path);
        db.check_consistency().expect("inconsistent database");
    }

    #[test]
    fn same_email_3() {
        let (_tmp_dir, mut db, log_path) = open_db();
        test::test_same_email_3(&mut db, &log_path);
        db.check_consistency().expect("inconsistent database");
    }

    #[test]
    fn same_email_4() {
        let (_tmp_dir, mut db, log_path) = open_db();
        test::test_same_email_4(&mut db, &log_path);
        db.check_consistency().expect("inconsistent database");
    }

    #[test]
    fn no_selfsig() {
        let (_tmp_dir, mut db, log_path) = open_db();
        test::test_no_selfsig(&mut db, &log_path);
        db.check_consistency().expect("inconsistent database");
    }

    #[test]
    fn bad_uids() {
        let (_tmp_dir, mut db, log_path) = open_db();
        test::test_bad_uids(&mut db, &log_path);
        db.check_consistency().expect("inconsistent database");
    }

    #[test]
    fn reverse_fingerprint_to_path() {
        let tmpdir = TempDir::new().unwrap();
        let db = Sqlite::new(tmpdir.path()).unwrap();

        let fp: Fingerprint =
            "CBCD8F030588653EEDD7E2659B7DD433F254904A".parse().unwrap();

        // XXX: fixme
        //assert_eq!(Sqlite::path_to_fingerprint(&db.link_by_fingerprint(&fp)),
        //           Some(fp.clone()));
        db.check_consistency().expect("inconsistent database");
    }

    #[test]
    fn attested_key_signatures() -> Result<()> {
        let (_tmp_dir, mut db, log_path) = open_db();
        test::attested_key_signatures(&mut db, &log_path)?;
        db.check_consistency()?;
        Ok(())
    }

    #[test]
    fn nonexportable_sigs() -> Result<()> {
        let (_tmp_dir, mut db, log_path) = open_db();
        test::nonexportable_sigs(&mut db, &log_path)?;
        db.check_consistency()?;
        Ok(())
    }
}
