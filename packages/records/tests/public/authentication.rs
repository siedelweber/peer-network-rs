use pn_records::authentication::{AuthenticationDisclosure, MissingField};
use pn_records::{InvalidCause, Layout, ValidationError, validate_history, validate_record};

/// Claim: Named untrusted authentication disclosures retain every supplied byte and edition; omission of each field refuses presence construction and local record construction, without claiming a signature or binding verdict.
/// ´claim:acts:authentication-fields-refuse-absence-and-retain-disclosures´
/// ´test:integration:authentication-disclosures´
#[test]
fn authentication_disclosures() {
    let original = crate::common::act(1, Layout::Binary);
    let fields = original.authentication_evidence.clone();
    let disclosed = AuthenticationDisclosure::new(fields.clone()).unwrap();
    assert_eq!(disclosed.fields(), &fields);
    let history = crate::common::resolved();
    let records = validate_record(std::slice::from_ref(&original), &history, &[]).unwrap();
    assert_eq!(records.acts()[0].authentication_evidence(), &fields);
    let names = [crate::common::named("left"), crate::common::named("right")];
    let restored = validate_history(std::slice::from_ref(&original), &names).unwrap();
    assert_eq!(restored.acts()[0].authentication_evidence(), &fields);
    for missing in [
        MissingField::ApprovalBinding,
        MissingField::ContentEdition,
        MissingField::HostSeal,
        MissingField::ActorProposalSignature,
        MissingField::PublicVerificationMaterial,
        MissingField::DependencyEdition,
        MissingField::ProposalPrecommitment,
        MissingField::AuthenticationEdition,
        MissingField::VerifiedHeader,
    ] {
        let mut candidate = original.clone();
        let field = &mut candidate.authentication_evidence;
        match missing {
            MissingField::ProposalPrecommitment => field.proposal_precommitment.clear(),
            MissingField::ActorProposalSignature => field.actor_proposal_signature.clear(),
            MissingField::ContentEdition => field.content_edition.clear(),
            MissingField::DependencyEdition => field.dependency_edition.clear(),
            MissingField::VerifiedHeader => field.verified_header.clear(),
            MissingField::HostSeal => field.host_seal.clear(),
            MissingField::ApprovalBinding => field.approval_binding.clear(),
            MissingField::AuthenticationEdition => field.authentication_edition.clear(),
            MissingField::PublicVerificationMaterial => field.public_verification_material.clear(),
        }
        assert_eq!(AuthenticationDisclosure::new(field.clone()).unwrap_err(), missing);
        let expected = ValidationError::InvalidRepresentation {
            act: candidate.id.clone(),
            cause: InvalidCause::EmptyAuthentication,
        };
        assert_eq!(
            validate_record(std::slice::from_ref(&candidate), &history, &[]).unwrap_err(),
            expected
        );
        assert_eq!(validate_history(&[candidate], &names).unwrap_err(), expected);
    }
    // Nonempty changes are retained, not silently certified as matching P or V.
    let mut changed = fields.clone();
    changed.host_seal = b"different-unverified-seal".to_vec();
    let other = AuthenticationDisclosure::new(changed.clone()).unwrap();
    assert_eq!(other.fields(), &changed);
    assert_ne!(other.fields(), disclosed.fields());
}
