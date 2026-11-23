//! Public, typed descriptions of independently selected boundary cases.
//! Neither a descriptor nor its equality authenticates its selection.
//! (´[ROOT-amend:identity:paper-case-declaration]´)

/// A bounded successor reference. Historical `DeclarationId` is unchanged.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ComponentRef {
    pub namespace: String,
    pub name: String,
    pub edition: u64,
}

/// The exact selected run and starting context, with an inclusive effective epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaseScope {
    pub run: [u8; 32],
    pub history_scope: Vec<u8>,
    pub announced_at: u64,
    pub effective_at: u64,
}

/// The selected external predicate family; the local deployment extension is separate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaperCaseKind {
    Provenance,
    AuthorAuthority,
}

/// A paper case descriptor. Its proof language is not admitted by this representation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaperCaseDeclaration {
    pub reference: ComponentRef,
    pub kind: PaperCaseKind,
    pub scope: CaseScope,
    pub second_party: ComponentRef,
    pub rules: ComponentRef,
    pub convention: ComponentRef,
    pub projection: ComponentRef,
    pub published_data_rule: ComponentRef,
    pub unit: Option<ComponentRef>,
}

/// The mandatory local predicate descriptor, outside the paper case set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalAuthorityDeclaration {
    pub reference: ComponentRef,
    pub scope: CaseScope,
    pub second_party: ComponentRef,
    pub genesis_hash: [u8; 32],
    pub rules: ComponentRef,
    pub authorization_convention: ComponentRef,
    pub projection: ComponentRef,
    pub run_configuration: Vec<u8>,
}

/// Structural refusal for a typed successor declaration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaseError {
    Shape,
    Field,
    Kind,
    Scope,
}

impl ComponentRef {
    /// Check the admitted name grammar and byte bounds without narrowing historical ids.
    /// # Errors
    /// Refuses a member outside the successor reference grammar.
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "cases-component-ref-validate",
            source_item = "cases::ComponentRef::validate"
        ),
        ret
    )]
    pub fn validate(&self) -> Result<(), CaseError> {
        fn atom(value: &str) -> bool {
            !value.is_empty()
                && value.len() <= 255
                && value
                    .as_bytes()
                    .first()
                    .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
                && value
                    .as_bytes()
                    .last()
                    .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        }
        if self.namespace.is_empty()
            || self.namespace.len() > 255
            || self.namespace.split('.').count() < 2
            || !self.namespace.split('.').all(atom)
            || !atom(&self.name)
        {
            return Err(CaseError::Field);
        }
        Ok(())
    }
}

impl CaseScope {
    /// Check the standalone scope shape; timing is a contextual comparison.
    /// # Errors
    /// Refuses an empty starting context.
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "cases-case-scope-validate",
            source_item = "cases::CaseScope::validate"
        ),
        ret
    )]
    pub fn validate(&self) -> Result<(), CaseError> {
        if self.history_scope.is_empty() {
            return Err(CaseError::Field);
        }
        Ok(())
    }
}

impl PaperCaseDeclaration {
    /// Check all typed members in their admitted order.
    /// # Errors
    /// Refuses malformed nested members or a kind/unit mismatch.
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "cases-paper-case-declaration-validate",
            source_item = "cases::PaperCaseDeclaration::validate"
        ),
        ret
    )]
    pub fn validate(&self) -> Result<(), CaseError> {
        self.reference.validate()?;
        self.scope.validate()?;
        self.second_party.validate()?;
        self.rules.validate()?;
        self.convention.validate()?;
        self.projection.validate()?;
        self.published_data_rule.validate()?;
        match (&self.kind, &self.unit) {
            (PaperCaseKind::Provenance, Some(unit)) => unit.validate(),
            (PaperCaseKind::AuthorAuthority, None) => Ok(()),
            _ => Err(CaseError::Kind),
        }
    }
}

impl LocalAuthorityDeclaration {
    /// Check all typed members before their independent contextual comparison.
    /// # Errors
    /// Refuses malformed nested members; descriptor identity is compared at Declaration.
    #[tracing::instrument(
        name = "sig:design:records",
        fields(
            execution_owner = "RECORDS",
            claim_owner = "ROOT",
            claim_label = "sig:design:records",
            operation = "cases-local-authority-declaration-validate",
            source_item = "cases::LocalAuthorityDeclaration::validate"
        ),
        ret
    )]
    pub fn validate(&self) -> Result<(), CaseError> {
        self.reference.validate()?;
        self.scope.validate()?;
        self.second_party.validate()?;
        self.rules.validate()?;
        self.authorization_convention.validate()?;
        self.projection.validate()?;
        if self.run_configuration.is_empty() {
            return Err(CaseError::Field);
        }
        Ok(())
    }
}
