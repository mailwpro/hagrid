use std::collections::HashMap;
use std::convert::TryFrom;
use std::fs::{create_dir_all, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use std::time::SystemTime;

use types::{Email, Fingerprint, KeyID};
use Result;
use {Database, Query};

use openpgp::Cert;

use r2d2_sqlite::rusqlite::params;
use r2d2_sqlite::rusqlite::OptionalExtension;
use r2d2_sqlite::SqliteConnectionManager;

pub struct Sqlite {
    pool: r2d2::Pool<SqliteConnectionManager>,

    keys_dir_log: PathBuf,
    dry_run: bool,
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

    fn new_internal(base_dir: PathBuf, manager: SqliteConnectionManager) -> Result<Self> {
        let keys_dir_log = base_dir.join("log");
        create_dir_all(&keys_dir_log)?;

        let dry_run = false;

        let pool = r2d2::Pool::builder().max_size(2).build(manager)?;
        let conn = pool.get()?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS certs (
                fingerprint            TEXT NOT NULL PRIMARY KEY,
                full                   TEXT NOT NULL,
                published              TEXT,
                published_not_armored  BLOB
            )",
            [],
        )?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS cert_identifiers (
                primary_fingerprint    TEXT NOT NULL,
                fingerprint            TEXT NOT NULL,
                keyid                  TEXT NOT NULL
            )",
            [],
        )?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS emails (
                email                  TEXT NOT NULL PRIMARY KEY,
                primary_fingerprint    TEXT NOT NULL
            )",
            [],
        )?;

        Ok(Self {
            pool,
            keys_dir_log,
            dry_run,
        })
    }

    fn link_email_vks(&self, email: &Email, fpr: &Fingerprint) -> Result<()> {
        todo!()
    }

    fn link_email_wkd(&self, email: &Email, fpr: &Fingerprint) -> Result<()> {
        todo!()
    }

    fn unlink_email_vks(&self, email: &Email, fpr: &Fingerprint) -> Result<()> {
        todo!()
    }

    fn unlink_email_wkd(&self, email: &Email, fpr: &Fingerprint) -> Result<()> {
        todo!()
    }

    fn open_logfile(&self, file_name: &str) -> Result<File> {
        let file_path = self.keys_dir_log.join(file_name);
        Ok(OpenOptions::new()
            .create(true)
            .append(true)
            .open(file_path)?)
    }

    fn perform_checks(
        &self,
        checks_dir: &Path,
        tpks: &mut HashMap<Fingerprint, Cert>,
        check: impl Fn(&Path, &Cert, &Fingerprint) -> Result<()>,
    ) -> Result<()> {
        // XXX: stub
        Ok(())
    }
}

impl Database for Sqlite {
    type MutexGuard = String;
    type TempCert = Vec<u8>;

    fn lock(&self) -> Result<Self::MutexGuard> {
        Ok("locked :)".to_owned())
    }

    fn write_to_temp(&self, content: &[u8]) -> Result<Self::TempCert> {
        Ok(content.to_vec())
    }

    fn write_log_append(&self, filename: &str, fpr_primary: &Fingerprint) -> Result<()> {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let fingerprint_line = format!("{:010} {}\n", timestamp, fpr_primary.to_string());

        self.open_logfile(filename)?
            .write_all(fingerprint_line.as_bytes())?;

        Ok(())
    }

    fn move_tmp_to_full(&self, file: Self::TempCert, fpr: &Fingerprint) -> Result<()> {
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

    fn move_tmp_to_published(&self, file: Self::TempCert, fpr: &Fingerprint) -> Result<()> {
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

    fn write_to_quarantine(&self, fpr: &Fingerprint, content: &[u8]) -> Result<()> {
        Ok(())
    }

    fn check_link_fpr(
        &self,
        fpr: &Fingerprint,
        fpr_target: &Fingerprint,
    ) -> Result<Option<Fingerprint>> {
        Ok(None)
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
        conn.execute(
            "
            INSERT INTO emails (email, primary_fingerprint)
            VALUES (?1, ?2)
            ON CONFLICT(email) DO UPDATE
                SET email=excluded.email, primary_fingerprint=excluded.primary_fingerprint
            ",
            params![email.to_string(), fpr.to_string(),],
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

    fn link_fpr(&self, from: &Fingerprint, primary_fpr: &Fingerprint) -> Result<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "
            INSERT INTO cert_identifiers (primary_fingerprint, fingerprint, keyid)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(primary_fingerprint) DO UPDATE
                SET fingerprint=excluded.fingerprint, keyid=excluded.keyid;
            ",
            params![
                primary_fpr.to_string(),
                from.to_string(),
                KeyID::try_from(from)?.to_string()
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

    // XXX: slow
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

    // XXX: slow
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

    // XXX: slow
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

    // XXX: slow
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
            WHERE fingerprint = ?1
            ",
                [primary_fingerprint],
                |row| row.get(0),
            )
            .optional()
            .unwrap();
        binary_cert
    }

    // XXX: slow
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

    /// Checks the database for consistency.
    ///
    /// Note that this operation may take a long time, and is
    /// generally only useful for testing.
    fn check_consistency(&self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openpgp::cert::CertBuilder;
    use tempfile::TempDir;
    use test;

    fn open_db() -> (TempDir, Sqlite, PathBuf) {
        let tmpdir = TempDir::new().unwrap();

        let db = Sqlite::new_file(tmpdir.path()).unwrap();
        let log_path = db.keys_dir_log.join(db.get_current_log_filename());

        (tmpdir, db, log_path)
    }

    #[test]
    fn new() {
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
    fn uid_verification() {
        let (_tmp_dir, mut db, log_path) = open_db();
        test::test_uid_verification(&mut db);
        db.check_consistency().expect("inconsistent database");
    }

    #[test]
    fn uid_deletion() {
        let (_tmp_dir, mut db, log_path) = open_db();
        test::test_uid_deletion(&mut db);
        db.check_consistency().expect("inconsistent database");
    }

    #[test]
    fn subkey_lookup() {
        let (_tmp_dir, mut db, log_path) = open_db();
        test::test_subkey_lookup(&mut db);
        db.check_consistency().expect("inconsistent database");
    }

    #[test]
    fn kid_lookup() {
        let (_tmp_dir, mut db, log_path) = open_db();
        test::test_kid_lookup(&mut db);
        db.check_consistency().expect("inconsistent database");
    }

    #[test]
    fn upload_revoked_tpk() {
        let (_tmp_dir, mut db, log_path) = open_db();
        test::test_upload_revoked_tpk(&mut db);
        db.check_consistency().expect("inconsistent database");
    }

    #[test]
    fn uid_revocation() {
        let (_tmp_dir, mut db, log_path) = open_db();
        test::test_uid_revocation(&mut db);
        db.check_consistency().expect("inconsistent database");
    }

    #[test]
    fn regenerate() {
        let (_tmp_dir, mut db, log_path) = open_db();
        test::test_regenerate(&mut db);
        db.check_consistency().expect("inconsistent database");
    }

    #[test]
    fn key_reupload() {
        let (_tmp_dir, mut db, log_path) = open_db();
        test::test_reupload(&mut db);
        db.check_consistency().expect("inconsistent database");
    }

    #[test]
    fn uid_replacement() {
        let (_tmp_dir, mut db, log_path) = open_db();
        test::test_uid_replacement(&mut db);
        db.check_consistency().expect("inconsistent database");
    }

    #[test]
    fn uid_unlinking() {
        let (_tmp_dir, mut db, log_path) = open_db();
        test::test_unlink_uid(&mut db);
        db.check_consistency().expect("inconsistent database");
    }

    #[test]
    fn same_email_1() {
        let (_tmp_dir, mut db, log_path) = open_db();
        test::test_same_email_1(&mut db);
        db.check_consistency().expect("inconsistent database");
    }

    #[test]
    fn same_email_2() {
        let (_tmp_dir, mut db, log_path) = open_db();
        test::test_same_email_2(&mut db);
        db.check_consistency().expect("inconsistent database");
    }

    #[test]
    fn same_email_3() {
        let (_tmp_dir, mut db, log_path) = open_db();
        test::test_same_email_3(&mut db);
        db.check_consistency().expect("inconsistent database");
    }

    #[test]
    fn same_email_4() {
        let (_tmp_dir, mut db, log_path) = open_db();
        test::test_same_email_4(&mut db);
        db.check_consistency().expect("inconsistent database");
    }

    #[test]
    fn no_selfsig() {
        let (_tmp_dir, mut db, log_path) = open_db();
        test::test_no_selfsig(&mut db);
        db.check_consistency().expect("inconsistent database");
    }

    #[test]
    fn bad_uids() {
        let (_tmp_dir, mut db, log_path) = open_db();
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
        let (_tmp_dir, mut db, log_path) = open_db();
        test::attested_key_signatures(&mut db)?;
        db.check_consistency()?;
        Ok(())
    }

    #[test]
    fn nonexportable_sigs() -> Result<()> {
        let (_tmp_dir, mut db, log_path) = open_db();
        test::nonexportable_sigs(&mut db)?;
        db.check_consistency()?;
        Ok(())
    }
}
