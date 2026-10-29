//! Process witness for (´[ROOT-inv:observe:noninterference]´).

#[path = "../tests/common/mod.rs"]
mod common;

use cli_common::observation::{BootstrapError, bootstrap};
use pn_records::{
    Declaration, DeclarationId, DependencyStatus, Layout, PublicReference, assemble_boundary_inputs, dependency_status,
    resolve_public_reference, select_effective_declaration, validate_record,
};
use std::process::ExitCode;

fn main() -> ExitCode {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "default".into());
    let guard = match bootstrap(mode != "disabled", false, tracing::Level::INFO) {
        Ok(guard) => Some(guard),
        Err(BootstrapError::Unavailable(_)) => None,
        Err(error @ BootstrapError::Configuration(_)) => {
            let mut record = cli_common::ControlPlaneRecord::usage_error("records-observation", "observation_configuration");
            record.message = error.to_string();
            let _ignored = cli_common::emit_control_plane_record(&record);
            return cli_common::CommandExit::Usage.exit_code();
        }
    };
    let records = [common::act(1, Layout::Binary), common::act(2, Layout::Paired)];
    let declarations = [Declaration {
        id: DeclarationId {
            namespace: "rules".into(),
            name: "edition".into(),
            edition: 1,
        },
        announced_at: 1,
        effective_at: 2,
        content: pn_records::DeclarationContent::Opaque,
    }];
    let history = common::resolved();
    let accepted = validate_record(&records, &history, &declarations).expect("complete fixture");
    let complete = accepted.acts();
    let count = complete.len();
    let empty_dependencies = dependency_status(&accepted, &records[0].legs[0].id).unwrap() == DependencyStatus::FullEmpty;
    let reference = PublicReference::Act(records[0].id.clone());
    let resolved = resolve_public_reference(&accepted, &reference).is_ok();
    let unresolved = resolve_public_reference(&accepted, &common::named("absent")).is_err();
    let selected = select_effective_declaration(&accepted, "rules", "edition", 2)
        .unwrap()
        .id
        .edition;
    let no_edition = select_effective_declaration(&accepted, "rules", "edition", 0).is_err();
    let mut missing = common::act(3, Layout::Paired);
    missing.legs.pop();
    let refused = validate_record(&[missing], &history, &[]).is_err();
    let boundary = assemble_boundary_inputs(&accepted, (5, 1)).unwrap();
    let assembled = boundary.acts().len();
    for _ in 0..3 {
        for act in complete {
            std::hint::black_box((
                act.id(),
                act.body(),
                act.legs(),
                act.projections(),
                act.protocol_references(),
                act.authentication_evidence(),
                act.finalization_epoch(),
                act.authoritative_position(),
            ));
            for leg in act.legs() {
                std::hint::black_box((leg.id(), leg.source(), leg.target()));
            }
        }
        for closure in boundary.closures() {
            std::hint::black_box((closure.root(), closure.members()));
        }
        std::hint::black_box((boundary.boundary(), boundary.acts(), boundary.closures(), boundary.work()));
    }
    let misplaced = assemble_boundary_inputs(&accepted, (5, 2)).is_err();
    let exit = if cli_common::emit(&serde_json::json!({"empty_dependencies":empty_dependencies,"assembled":assembled,"misplaced":misplaced,"accepted_acts":count,"missing_co_leg_refused":refused,"resolved":resolved,"unresolved":unresolved,"edition":selected,"no_edition":no_edition})).is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    };
    drop(guard);
    if std::env::var_os("PN_TEST_OBSERVATION_RENDEZVOUS").is_some() {
        let mut release = [0];
        let _ignored = std::io::Read::read_exact(&mut std::io::stdin(), &mut release);
    }
    exit
}
