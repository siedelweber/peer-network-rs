#[path = "common/allocation.rs"]
mod allocation;
mod common;

#[path = "common/package.rs"]
mod package_inputs;
use package_inputs::{Published, fixture};
use pn_epoch::package::{PackageError, verify_package};
use pn_records::numerics::{ComparisonLimits, ExactLimits, NumericContext};

fn other_inputs(boundary: u64, edition_number: u64) -> pn_epoch::CompilerInputs {
    let (mut declaration, mut edition, mut parameters) = common::fixture();
    declaration.id.edition = edition_number;
    edition.id = declaration.id.clone();
    parameters.edition = declaration.id.clone();
    parameters.boundary = boundary;
    for profile in &mut parameters.profiles {
        profile.edition = declaration.id.clone();
    }
    let history = pn_records::validate_history(&[], &[]).unwrap();
    let records = pn_records::validate_record(&[], &history, &[declaration]).unwrap();
    let constants = pn_records::constants::bind_constants(&records, vec![edition]).unwrap();
    pn_epoch::bind_inputs(&constants, parameters, ExactLimits::default()).unwrap()
}

fn predecessor_cases(mut input: pn_epoch::package::PackageInput) {
    let second_inputs = other_inputs(2, 1);
    let second_price = input.prices[0].clone();
    input.bindings.push(pn_epoch::package::EpochBinding {
        marker: input.markers.markers()[2].identity().clone(),
        predecessor: input.markers.markers()[1].identity().clone(),
        inputs: second_inputs.clone(),
        price: second_price.clone(),
        sequence: vec![],
    });
    input.inputs.push(second_inputs);
    input.prices.push(second_price);
    let published = Published(input.bindings.clone());
    verify_package(input.clone(), &published).unwrap();
    input.bindings[1].predecessor.accepted = pn_records::burn::AcceptedSet::CompleteList(std::collections::BTreeSet::new());
    assert_eq!(verify_package(input, &published).unwrap_err(), PackageError::Predecessor);
}

/// Claim: Structural package verification separates burn-marker acceptance from complete act sequences and refuses mismatched histories, policies, predecessor markers, constants, writing prices, sequences and epoch alignment before public binding verification; matching epoch numbers alone do not establish a package.
/// ´claim:compiler:completed-packages-require-explicit-coherent-bindings´
/// ´test:integration:package-bindings´
#[test]
fn package_bindings() {
    let original = fixture();
    let verifier = Published(original.bindings.clone());
    let accepted = verify_package(original.clone(), &verifier).unwrap();
    assert_eq!(accepted.input().bindings, original.bindings);
    pn_graph::formation::reconstruct_replay(&accepted.input().history, &allocation::Verifier).unwrap();
    for (case, expected) in [
        (0, PackageError::History),
        (1, PackageError::Policy),
        (2, PackageError::Predecessor),
        (3, PackageError::Constants),
        (4, PackageError::Sequence),
        (5, PackageError::Sequence),
        (6, PackageError::Alignment),
        (7, PackageError::Alignment),
        (8, PackageError::Vintage),
        (9, PackageError::Policy),
        (10, PackageError::Constants),
        (11, PackageError::Sequence),
    ] {
        let mut input = original.clone();
        match case {
            0 => input.bindings[0].marker.history.push_str("-foreign"),
            1 => input.bindings[0].marker.policy_edition.push_str("-foreign"),
            2 => input.bindings[0].predecessor = input.bindings[0].marker.clone(),
            3 => input.bindings[0].inputs = allocation::inputs_for_depth(&["one"]),
            4 => {
                input.bindings[0].sequence.pop();
            }
            5 => input.bindings[0].sequence.swap(0, 1),
            6 => input.bindings[0].marker.index = 2,
            7 => input.bindings.clear(),
            8 => {
                let mut numeric = NumericContext::new(ExactLimits::default(), ComparisonLimits::new(1000, 1000)).unwrap();
                let literal = numeric.literal("3").unwrap();
                let wall = numeric.computed(&literal).unwrap();
                input.bindings[0].price = numeric
                    .charged_price(
                        &wall,
                        &input.inputs[0].parameters().numeraire,
                        input.inputs[0].constants().content().floor,
                    )
                    .unwrap();
            }
            9 => input.bindings[0].predecessor.policy_identity.push_str("-foreign"),
            10 => input.bindings[0].inputs = other_inputs(1, 2),
            _ => {
                let mut acts = allocation::acts();
                acts[3].body.quantities[0].1.value = 0;
                input.history = allocation::history(&acts);
            }
        }
        assert_eq!(verify_package(input, &verifier).unwrap_err(), expected);
    }
    assert_eq!(
        verify_package(original.clone(), &Published(vec![])).unwrap_err(),
        PackageError::Binding
    );
    predecessor_cases(original);
}
