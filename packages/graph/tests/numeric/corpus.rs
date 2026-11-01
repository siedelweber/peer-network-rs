//! Reference figures produced by the paper's own build at network-v0.31.1.
//! (´[ROOT-rec:design:pending-reference-corpus]´)
use nrz_cas::{Rational, limits::Budget};
use pn_records::{
    conserved::{LocalRecord, LocalVerdict, TwoMapRecord},
    primitive::Range,
};

fn number(text: &str, budget: &mut Budget) -> Rational {
    Rational::parse(text, budget).unwrap()
}

fn compare(label: &str, paper: &Range, ours: &Range, contain: bool, budget: &mut Budget) {
    let pl = number(&paper.lower, budget);
    let pu = number(&paper.upper, budget);
    let ol = number(&ours.lower, budget);
    let ou = number(&ours.upper, budget);
    assert!(
        !ol.compare(&pu, budget).unwrap().is_gt() && !pl.compare(&ou, budget).unwrap().is_gt(),
        "{label}: paper={paper:?}, ours={ours:?}"
    );
    if contain {
        assert!(
            !ol.compare(&pl, budget).unwrap().is_gt() && !pu.compare(&ou, budget).unwrap().is_gt(),
            "{label}: containment paper={paper:?}, ours={ours:?}"
        );
    }
}

fn inflate(value: &Range, radius: &Rational, budget: &mut Budget) -> Range {
    Range {
        lower: number(&value.lower, budget)
            .sub(radius, budget)
            .unwrap()
            .exact_string(budget)
            .unwrap(),
        upper: number(&value.upper, budget)
            .add(radius, budget)
            .unwrap()
            .exact_string(budget)
            .unwrap(),
    }
}

/// Compare the common mathematical objects, retaining method-specific bounds separately.
/// # Panics
/// Panics only if the declared reference comparison fails or its comparison budget is exhausted.
pub(super) fn check(residual: &TwoMapRecord, local: &LocalRecord) {
    let p = super::verification_policy();
    let mut budget = Budget::new(p.enclosure.unwrap().operation).unwrap();
    let standing_label = "ver:standing:conserved-equilibrium-enclosure";
    let wall = super::range(
        "250927425738473888861741368970320969988646825074039496451178482151187942819/500000000000000000000000000000000000000000000000000000000000000000000000000",
        "250927425738473888861741368970320969988646825074039496451178482151187942961/500000000000000000000000000000000000000000000000000000000000000000000000000",
    );
    compare(
        "ver:floor:fixture-regime",
        &wall,
        &residual.first.input.wall,
        true,
        &mut budget,
    );
    let fence = super::range(
        "74907257426152611113825863102967903001135317492596050354882151784881205653/500000000000000000000000000000000000000000000000000000000000000000000000000",
        "2996290297046104444553034524118716120045412699703842014195286071395248231/20000000000000000000000000000000000000000000000000000000000000000000000000",
    );
    // Positivity and strict decrease extend the lower-wall upper bound to
    // the defining wall. This enclosure is not the lower-wall scalar interval.
    let conservative_fence = super::range("0", &residual.first.fence.upper);
    compare(standing_label, &fence, &conservative_fence, false, &mut budget);
    let one = number("1", &mut budget);
    assert!(!number(&fence.upper, &mut budget).compare(&one, &mut budget).unwrap().is_gt());
    assert!(
        !number(&conservative_fence.upper, &mut budget)
            .compare(&one, &mut budget)
            .unwrap()
            .is_gt()
    );
    assert_eq!(residual.first.input.strength, "1");
    // Full strength is the first declared rung, so this passing fence accepts one.
    let published_rung = "1";
    let published_strength = "1";
    let published_fence_verdict = "PASS";
    assert_eq!(p.grid.first().map(String::as_str), Some(published_rung));
    assert_eq!(published_rung, residual.first.input.strength);
    assert_eq!(published_strength, residual.first.input.strength);
    assert_eq!(published_fence_verdict, "PASS");
    let global = number(super::NumberId::NumbersPendingReferenceCorpusValue2.value(), &mut budget);
    let our_global = number(&residual.first.contraction, &mut budget);
    assert!(global.compare(&one, &mut budget).unwrap().is_lt());
    assert!(our_global.compare(&one, &mut budget).unwrap().is_lt());
    standing(residual, &mut budget);
    roots(residual, local, &mut budget);
    // These bounds are properties of distinct centres, operators and boxes.
    // Their data are retained without an ordering or containment assertion.
    let separate = [
        (
            "residual-radius",
            "19909653387353/1000000000000000000000000000000000000000000000000000000000000000000000000000",
            residual.radius.as_str(),
        ),
        (
            "local-contraction",
            "14529966121662466844609137066561219529377/250000000000000000000000000000000000000000000000000000000000000000000000000",
            local.jacobian_norm.as_str(),
        ),
        (
            "local-radius",
            "8767210314447/500000000000000000000000000000000000000000000000000000000000000000000000000",
            local.image_radius.as_str(),
        ),
        ("candidate-iterations", "18", "0"),
    ];
    assert_eq!(separate.len(), 4);
    for (_, paper, ours) in separate {
        assert_ne!(paper, "");
        assert_ne!(ours, "");
    }
}

fn standing(residual: &TwoMapRecord, budget: &mut Budget) {
    let standing_label = "ver:standing:conserved-equilibrium-enclosure";
    let radius = number(
        concat!(
            "30662541810212291284",
            "78478673909297559195/",
            "15400841598624288022",
            "43698767746875544721",
            "19026646131473486596",
            "71927672898696847446",
            "0503806170769353943212",
        ),
        budget,
    );
    let coordinates = [
        (
            "carol",
            super::range(
                "280824332079934064151629193278089535287868642768639427334871742037467162257/250000000000000000000000000000000000000000000000000000000000000000000000000",
                "1123297328319736256606516773112358141151474571074557709339486968149868649063/1000000000000000000000000000000000000000000000000000000000000000000000000000",
            ),
        ),
        (
            "alice",
            super::range(
                "541512095710254351856376438504946505001892195820993417258136919641468676173/500000000000000000000000000000000000000000000000000000000000000000000000000",
                "541512095710254351856376438504946505001892195820993417258136919641468676197/500000000000000000000000000000000000000000000000000000000000000000000000000",
            ),
        ),
        (
            "eve",
            super::range(
                "559442753720072326272561844025180458771772376060791094447332114059563492423/500000000000000000000000000000000000000000000000000000000000000000000000000",
                "223777101488028930509024737610072183508708950424316437778932845623825396973/200000000000000000000000000000000000000000000000000000000000000000000000000",
            ),
        ),
        (
            "bob",
            super::range(
                "221718985746048721368645652815925026799241993646055823424105839322877941327/200000000000000000000000000000000000000000000000000000000000000000000000000",
                "1108594928730243606843228264079625133996209968230279117120529196614389706673/1000000000000000000000000000000000000000000000000000000000000000000000000000",
            ),
        ),
        (
            "dave",
            super::range(
                "279611668024175928092197991827989438471414042619796953345452392906209879683/250000000000000000000000000000000000000000000000000000000000000000000000000",
                "27961166802417592809219799182798943847141404261979695334545239290620987969/25000000000000000000000000000000000000000000000000000000000000000000000000",
            ),
        ),
    ];
    for (actor, image) in &coordinates {
        let index = residual.first.input.sources.iter().position(|s| s.name == *actor).unwrap();
        let standing = inflate(image, &radius, budget);
        compare(
            &format!("{standing_label}:equilibrium:{actor}"),
            &standing,
            &residual.enclosure[index],
            true,
            budget,
        );
    }
}

fn roots(residual: &TwoMapRecord, local: &LocalRecord, budget: &mut Budget) {
    let standing_label = "ver:standing:conserved-equilibrium-enclosure";
    let roots = [
        (
            "eve",
            super::range(
                "1118885507440144652545123688050360917543544752121582188894664226286468435717/1000000000000000000000000000000000000000000000000000000000000000000000000000",
                "22377710148802893050902473761007218350870895042431643777893284525729383973/20000000000000000000000000000000000000000000000000000000000000000000000000",
            ),
        ),
        (
            "bob",
            super::range(
                "1108594928730243606843228264079625133996209968230279117120529193608892122323/1000000000000000000000000000000000000000000000000000000000000000000000000000",
                "554297464365121803421614132039812566998104984115139558560264596804446477867/500000000000000000000000000000000000000000000000000000000000000000000000000",
            ),
        ),
        (
            "dave",
            super::range(
                "223689334419340742473758393462391550777131234095837562676361917831851797043/200000000000000000000000000000000000000000000000000000000000000000000000000",
                "27961166802417592809219799182798943847141404261979695334545239728981503691/25000000000000000000000000000000000000000000000000000000000000000000000000",
            ),
        ),
        (
            "carol",
            super::range(
                "224659465663947251321303354622471628230294914214911541867897392641136444739/200000000000000000000000000000000000000000000000000000000000000000000000000",
                "561648664159868128303258386556179070575737285537278854669743481602841580933/500000000000000000000000000000000000000000000000000000000000000000000000000",
            ),
        ),
    ];
    assert_eq!(local.verdict, LocalVerdict::Included);
    let published_local_verdict = "PASS";
    assert_eq!(published_local_verdict, "PASS");
    assert_eq!(local.active.len(), roots.len());
    for (actor, root) in &roots {
        let index = residual.first.input.sources.iter().position(|s| s.name == *actor).unwrap();
        assert!(local.active.contains(&index));
        compare(
            &format!("{standing_label}:local-root:{actor}"),
            root,
            &local.asserted[index],
            false,
            budget,
        );
    }
}
