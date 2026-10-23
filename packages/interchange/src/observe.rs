//! Scoped observation for capabilities without an eager Debug representation.
//! (´[ROOT-rule:observe:spans]´) and (´[ROOT-inv:observe:noninterference]´)
//! require lazy inputs to be observed as consumed, never advanced for telemetry.

pub(crate) struct Scope(tracing::span::EnteredSpan);

pub(crate) fn scope(owner: &'static str, label: &'static str, item: &'static str, arguments: &dyn std::fmt::Debug) -> Scope {
    Scope(tracing::info_span!("rule:observe:spans",execution_owner=owner,claim_owner="ROOT",claim_label=label,source_item=item,arguments=?arguments).entered())
}

impl Scope {
    pub(crate) fn finish(self, result: &dyn std::fmt::Debug) {
        tracing::info!("return"=?result);
        drop(self.0);
    }
}
