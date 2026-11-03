use super::*;

/// Claim: On the declared singleton source with a non-point wall enclosure, the image-first residual is exactly zero while the source image retains its wall uncertainty. Independent replay preserves the zero radius and enclosure and refuses a changed singleton assertion. This is a structural constant-row witness, not arbitrary-map or deployment coverage.
/// ´claim:numerics:singleton-image-residual-keeps-wall-uncertainty´
/// ´test:integration:singleton-image-residual´
#[test]
fn singleton_image_residual() {
    use pn_graph::numeric::verification;
    let mut p = verification_policy();
    // Exact structural identity, checked at the supported solve scope floor.
    p.precision = Precision::AbsoluteWidthBits(vec![2]);
    p.enclosure.as_mut().unwrap().refinement.precision = 2;
    let mut input = verification_reference();
    input.edges.clear();
    input.sources.truncate(1);
    let coordinate = NumberId::NumbersReferenceCandidateCoordinate.value();
    let candidate = vec![range(coordinate, coordinate); input.sources.len()];
    let result = verification::two_map(&p, &input, &candidate).unwrap();
    assert!(result.first.singleton.iter().all(|singleton| *singleton));
    assert!(result.first.image.iter().any(|value| value.lower != value.upper));
    assert_eq!(result.radius, "0");
    assert_eq!(result.enclosure, result.first.image);
    let checked = verification::replay_two_map(&p, &input, &candidate, &result).unwrap();
    assert_eq!(checked.radius, result.radius);
    assert_eq!(checked.enclosure, result.enclosure);
    let mut changed = result;
    changed.first.singleton[0] = false;
    assert!(verification::replay_two_map(&p, &input, &candidate, &changed).is_err());
}
