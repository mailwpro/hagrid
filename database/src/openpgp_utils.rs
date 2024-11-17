use openpgp::Result;
use std::convert::TryFrom;

use openpgp::{
    cert::prelude::*, policy::StandardPolicy, serialize::SerializeInto as _,
    types::RevocationStatus, Cert,
};

use Email;

pub const POLICY: StandardPolicy = StandardPolicy::new();

pub fn is_status_revoked(status: RevocationStatus) -> bool {
    match status {
        RevocationStatus::Revoked(_) => true,
        RevocationStatus::CouldBe(_) => false,
        RevocationStatus::NotAsFarAsWeKnow => false,
    }
}

pub fn tpk_to_string(tpk: &Cert) -> Result<Vec<u8>> {
    tpk.armored().export_to_vec()
}

pub fn tpk_clean(tpk: &Cert) -> Result<Cert> {
    // Iterate over the Cert, pushing packets we want to merge
    // into the accumulator.
    let mut acc = Vec::new();

    // The primary key and related signatures.
    let pk_bundle = tpk.primary_key().bundle();
    acc.push(pk_bundle.key().clone().into());
    for s in pk_bundle.self_signatures() {
        acc.push(s.clone().into())
    }
    for s in pk_bundle.self_revocations() {
        acc.push(s.clone().into())
    }
    for s in pk_bundle.other_revocations() {
        acc.push(s.clone().into())
    }

    // The subkeys and related signatures.
    for skb in tpk.keys().subkeys() {
        acc.push(skb.key().clone().into());
        for s in skb.self_signatures() {
            acc.push(s.clone().into())
        }
        for s in skb.self_revocations() {
            acc.push(s.clone().into())
        }
        for s in skb.other_revocations() {
            acc.push(s.clone().into())
        }
    }

    // The UserIDs.
    for uidb in tpk.userids() {
        acc.push(uidb.userid().clone().into());
        for s in uidb.self_signatures() {
            acc.push(s.clone().into())
        }
        for s in uidb.self_revocations() {
            acc.push(s.clone().into())
        }
        for s in uidb.other_revocations() {
            acc.push(s.clone().into())
        }

        // Reasoning about the currently attested certifications
        // requires a policy.
        if let Ok(vuid) = uidb.with_policy(&POLICY, None) {
            for s in vuid.attestation_key_signatures() {
                acc.push(s.clone().into());
            }
            for s in vuid.attested_certifications() {
                acc.push(s.clone().into());
            }
        }
    }

    Cert::from_packets(acc.into_iter())
}

/// Filters the Cert, keeping only UserIDs that aren't revoked, and whose emails match the given list
pub fn tpk_filter_alive_emails(tpk: &Cert, emails: &[Email]) -> Cert {
    tpk.clone().retain_userids(|uid| {
        if is_status_revoked(uid.revocation_status(&POLICY, None)) {
            false
        } else if let Ok(email) = Email::try_from(uid.userid()) {
            emails.contains(&email)
        } else {
            false
        }
    })
}

#[cfg(test)]
mod tests {
    use openpgp::{cert::CertParser, parse::Parse};

    use crate::openpgp_utils::{tpk_filter_alive_emails, tpk_to_string};

    use super::tpk_clean;

    #[test]
    fn works_with_sequoia_1_17_but_not_1_18() {
        let armored = "-----BEGIN PGP PUBLIC KEY BLOCK-----
Comment: 7E07 FFC5 F4B9 8B1B 9CE3  61E9 4B99 3AA2 D89A 0A17
Comment: test1@example.com

xjMEZznx5BYJKwYBBAHaRw8BAQdA5MD1f/NiHYZUrlLIAqfYgA4SkoHr7QpFjPcC
FhqB10LNEXRlc3QxQGV4YW1wbGUuY29twsAOBBMWCgCABYJnOfHkAwsJBwkQS5k6
otiaChdHFAAAAAAAHgAgc2FsdEBub3RhdGlvbnMuc2VxdW9pYS1wZ3Aub3Jn6ckh
AdD+if9Ap8p6xuufUCIZeO25LoF9MbEcs3CR9eEDFQoIApkBApsBAh4BFiEEfgf/
xfS5ixuc42HpS5k6otiaChcAACxYAP4x/Cbw7VbODuGXz0zFYizRiibK58oePhiK
c+6pYRBORgD/a5QcY57MexWD07wMGKmWiwwB45EhfF3QebgUKSEdaAo=
=8MtF
-----END PGP PUBLIC KEY BLOCK-----
";
        let cert = CertParser::from_bytes(armored).expect("").into_iter().next().unwrap().unwrap();
        let cleaned = tpk_clean(&tpk_filter_alive_emails(&cert, &[])).expect("tpk_clean should succeed");

        let other = tpk_to_string(&cleaned).unwrap();

        assert!(other.len() > 0);
    }
}
