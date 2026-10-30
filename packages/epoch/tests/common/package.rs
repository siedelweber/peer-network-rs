use pn_epoch::package::{EpochBinding, PackageInput, PackageVerifier};
use pn_records::numerics::{ComparisonLimits, ExactLimits, NumericContext};

#[derive(Debug)]
pub(crate) struct Published(pub(crate) Vec<EpochBinding>);
impl PackageVerifier for Published {
    fn published_package(&self, input: &PackageInput) -> bool {
        input.bindings == self.0
    }
}

pub(crate) fn fixture() -> PackageInput {
    let markers = pn_records::test_support::burn::recognize(pn_records::test_support::burn::generate(&[9])).unwrap();
    let inputs = crate::allocation::inputs();
    let mut numeric = NumericContext::new(ExactLimits::default(), ComparisonLimits::new(1000, 1000)).unwrap();
    let literal = numeric.literal("2").unwrap();
    let wall = numeric.computed(&literal).unwrap();
    let price = numeric
        .charged_price(&wall, &inputs.parameters().numeraire, inputs.constants().content().floor)
        .unwrap();
    let history = crate::allocation::history(&crate::allocation::acts());
    let mut sequence = history.acts().to_vec();
    sequence.sort_by_key(pn_records::ValidatedAct::position);
    let binding = EpochBinding {
        marker: markers.markers()[1].identity().clone(),
        predecessor: markers.markers()[0].identity().clone(),
        inputs: inputs.clone(),
        price: price.clone(),
        sequence,
    };
    PackageInput {
        markers,
        history,
        inputs: vec![inputs],
        prices: vec![price],
        bindings: vec![binding],
    }
}
