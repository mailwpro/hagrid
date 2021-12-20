use openpgp::Result;
use std::collections::{HashSet, HashMap};
use std::convert::TryFrom;

use openpgp::{
    Cert,
    KeyHandle,
    types::RevocationStatus,
    cert::prelude::*,
    serialize::SerializeInto as _,
    packet::Signature,
    parse::Parse,
    policy::StandardPolicy,
};

use Email;
use Database;

pub const POLICY: StandardPolicy = StandardPolicy::new();

/// How many of the most recent certifications to publish.
const PUBLISH_N_MOST_RECENT_CERTIFICATIONS: usize = 3;

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

pub fn tpk_clean<D, M>(db: &D, tpk: Cert,
                       mut boundary: Option<&mut HashMap<openpgp::Fingerprint, Cert>>)
                       -> Result<Cert>
where
    D: Database<MutexGuard = M>,
    D: ?Sized,
{
    // Iterate over the Cert, pushing packets we want to merge
    // into the accumulator.
    let mut acc = Vec::new();

    // The primary key and related signatures.
    let pk_bundle = tpk.primary_key().bundle();
    acc.push(pk_bundle.key().clone().into());
    for s in pk_bundle.self_signatures() { acc.push(s.clone().into()) }
    for s in pk_bundle.self_revocations()  { acc.push(s.clone().into()) }
    for s in pk_bundle.other_revocations() { acc.push(s.clone().into()) }

    // Keep symmetric certifications.  These are useful to delegate
    // trust to a CA.
    let (accepted, _rejected) =
        filter_symmetric(db,
                         &mut boundary,
                         &tpk,
                         pk_bundle.certifications().iter().collect(),
                         |mut s, other|
                         s.verify_direct_key(&other.primary_key(),
                                             &tpk.primary_key()).is_ok());
    for s in accepted {
        acc.push(s.clone().into());
    }

    // The subkeys and related signatures.
    for skb in tpk.keys().subkeys() {
        acc.push(skb.key().clone().into());
        for s in skb.self_signatures()   { acc.push(s.clone().into()) }
        for s in skb.self_revocations()  { acc.push(s.clone().into()) }
        for s in skb.other_revocations() { acc.push(s.clone().into()) }
    }

    // The UserIDs.
    for uidb in tpk.userids() {
        let userid = uidb.userid();

        acc.push(uidb.userid().clone().into());
        for s in uidb.self_signatures()   { acc.push(s.clone().into()) }
        for s in uidb.self_revocations()  { acc.push(s.clone().into()) }
        for s in uidb.other_revocations() { acc.push(s.clone().into()) }

        // Put all certifications in a set, deal with them using the
        // cheapest method first, only using more expensive ones if
        // necessary.
        let mut certifications: HashSet<_> = uidb.certifications().collect();

        // Reasoning about the currently attested certifications
        // requires a policy.
        if let Ok(vuid) = uidb.with_policy(&POLICY, None) {
            for s in vuid.attestation_key_signatures() {
                acc.push(s.clone().into());
            }
            for s in vuid.attested_certifications() {
                certifications.remove(s);
                acc.push(s.clone().into());
            }
        }

        // Keep the N most recent ones made by the domain's openpgp-ca.
        if ! certifications.is_empty() {
            if let Some(ca) = Email::try_from(userid).ok()
                .map(|m| m.corresponding_openpgp_ca())
                .and_then(|ca| db.by_email(&ca))
                .and_then(|s| Cert::from_bytes(s.as_bytes()).ok())
            {
                let handle = ca.key_handle();
                let mut ca_certifications = Vec::new();
                for c in std::mem::take(&mut certifications) {
                    // See if it is made by the CA.
                    if c.get_issuers().iter().any(|i| i.aliases(&handle)) {
                        // It is.
                        ca_certifications.push(c);
                    } else {
                        // Try the next expensive method.
                        certifications.insert(c);
                    }
                }

                // Keep the most recent valid certification.
                ca_certifications.sort_unstable_by_key(|s| {
                    s.signature_creation_time().unwrap_or(std::time::UNIX_EPOCH)
                });

                let mut n = PUBLISH_N_MOST_RECENT_CERTIFICATIONS;
                while let Some(last) = ca_certifications.pop() {
                    // Check the signature.
                    if last.clone().verify_userid_binding(&ca.primary_key(),
                                                          &tpk.primary_key(),
                                                          userid).is_ok()
                    {
                        // Checked out, include it.
                        acc.push(last.clone().into());
                        n -= 1;
                        if n == 0 {
                            break; // N are enough.
                        }
                    }
                }
            }
        }

        // Keep symmetric certifications.
        let (accepted, _rejected) =
            filter_symmetric(db,
                             &mut boundary,
                             &tpk,
                             certifications.into_iter().collect(),
                             |mut s, other|
                             s.verify_userid_binding(&other.primary_key(),
                                                     &tpk.primary_key(),
                                                     userid).is_ok());
        for s in accepted {
            acc.push(s.clone().into());
        }
    }

    Cert::from_packets(acc.into_iter())
}

fn filter_symmetric<'a, D, M, C>(db: &D,
                                 boundary: &mut Option<&mut HashMap<openpgp::Fingerprint, Cert>>,
                                 us: &Cert,
                                 mut sigs: Vec<&'a Signature>,
                                 check: C)
                                 -> (Vec<&'a Signature>, Vec<&'a Signature>)
where
    D: Database<MutexGuard = M>,
    D: ?Sized,
    C: Fn(Signature, &Cert) -> bool,
{
    let our_handle = us.key_handle();
    let mut accepted = Vec::new();
    let mut rejected = Vec::new();

    while let Some(c) = sigs.pop() {
        // Get the issuer.  Don't bother with signatures that
        // don't include an issuer fingerprint.
        let issuer = if let Some(i) = c.issuer_fingerprints().next() {
            i
        } else {
            rejected.push(c);
            continue;
        };
        let handle = KeyHandle::from(issuer.clone());

        // Collect all the signatures from the same issuer.  This
        // way, we can batch all of them together and only once
        // lookup the issuer's cert.
        let mut batch = vec![c];
        // XXX: Replace this with drain_filter once stabilized.
        for c in std::mem::take(&mut sigs) {
            if c.get_issuers().iter().any(|i| i.aliases(&handle)) {
                batch.push(c);
            } else {
                // Not the same issuer, put it back.
                sigs.push(c);
            }
        }

        // Locate the issuer.  Note that we do a "full" lookup for
        // the issuer.  If we didn't, then there would be no way
        // to add the first certification.
        if let Some(other) =
            crate::types::Fingerprint::try_from(issuer.clone()).ok()
            .and_then(|fp| db.by_fpr_full(&fp))
            .and_then(|s| Cert::from_bytes(s.as_bytes()).ok())
        {
            // XXX: If we want certifications to not be considered if
            // they involve unpublished identities, we need to
            // restrict other to the published identities here.  If we
            // do change this, also change
            // Database::set_email_published to recurse like
            // Database::merge does.

            // Did we certify any of other's User IDs?
            if ! other.userids()
                .any(|uidb| uidb.certifications()
                     .filter(|c| c.get_issuers().iter().any(|i| i.aliases(&our_handle)))
                     .any(|c| c.clone().verify_userid_binding(
                         &us.primary_key(),
                         &other.primary_key(),
                         uidb.userid()).is_ok()))
            {
                // No.  This is not symmetric.  Put all
                // certifications back.
                rejected.append(&mut batch);
                continue;
            }

            // We know the signature relation is symmetric.

            // Keep the N most recent valid certifications.
            batch.sort_unstable_by_key(|s| {
                s.signature_creation_time().unwrap_or(std::time::UNIX_EPOCH)
            });

            let mut n = PUBLISH_N_MOST_RECENT_CERTIFICATIONS;
            while let Some(last) = batch.pop() {
                // Check the signature.
                if check(c.clone(), &other) {
                    // Checked out, include it.
                    accepted.push(last);
                    n -= 1;
                    if n == 0 {
                        break; // N are enough.
                    }
                }
            }

            // Recursively reconsider cert.
            if let Some(boundary) = boundary {
                boundary.insert(other.fingerprint(), other);
            }
        } else {
            // Try the next expensive method.
            rejected.append(&mut batch);
        }
    }

    (accepted, rejected)
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
