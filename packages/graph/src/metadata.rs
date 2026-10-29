//! Inherited act metadata and the fixed diagnostic projection presentation.
//! (´def:formation:act-metadata´)

use pn_records::{ActId, Position, TimeEvidence, ValidatedAct, ValidatedHistory};

/// Shared finalization metadata copied from the owning validated act.
/// Projection metadata retains the published stamp; observer-specific recomputation
/// and stamp evidence are joined here from the owning immutable history snapshot.
/// Neither field is an authored identity or a canonical publication encoding.
/// (´def:formation:act-metadata´)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ActMetadata {
    /// Retained epoch-qualified published placement.
    pub position: Position,
    /// Retained host attachment, never recomputed by formation.
    pub logical_time: u64,
}

impl ActMetadata {
    pub(crate) fn evidence<'a>(self, id: &ActId, history: &'a ValidatedHistory) -> Option<&'a TimeEvidence> {
        let act = history.acts().iter().find(|act| act.id() == id)?;
        if self != Self::from_act(act) {
            return None;
        }
        history.time_evidence().iter().find(|row| &row.act == id)
    }

    pub(crate) fn from_act(act: &ValidatedAct) -> Self {
        Self {
            position: act.position(),
            logical_time: act.logical_time(),
        }
    }
}

// The wire structs deliberately keep the pre-carrier struct name, field order,
// field types and unknown-field refusal. Unlike flatten, this keeps Serde's
// struct data model (including sequence deserializers), not just JSON keys.
// Debug uses the same flat fields so existing observation payloads do not change.
// Future metadata changes must explicitly decide their presentation here rather
// than silently adding published fields through a nested carrier derive.
macro_rules! projection {
    ($(#[$attr:meta])* pub struct $name:ident {
        before { $($(#[$before_attr:meta])* pub $before:ident: $before_ty:ty,)* }
        after { $($(#[$after_attr:meta])* pub $after:ident: $after_ty:ty,)* }
    }) => {
        $(#[$attr])*
        #[derive(Clone, PartialEq, Eq)]
        pub struct $name {
            $($(#[$before_attr])* pub $before: $before_ty,)*
            /// Inherited finalization metadata; not an independent edge stamp.
            pub metadata: $crate::metadata::ActMetadata,
            $($(#[$after_attr])* pub $after: $after_ty,)*
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.debug_struct(stringify!($name))
                    $(.field(stringify!($before), &self.$before))*
                    .field("position", &self.metadata.position)
                    .field("logical_time", &self.metadata.logical_time)
                    $(.field(stringify!($after), &self.$after))*
                    .finish()
            }
        }

        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                #[derive(serde::Serialize)]
                struct $name<'wire> {
                    $($before: &'wire $before_ty,)*
                    position: &'wire pn_records::Position,
                    logical_time: &'wire u64,
                    $($after: &'wire $after_ty,)*
                }
                let wire = $name {
                    $($before: &self.$before,)*
                    position: &self.metadata.position,
                    logical_time: &self.metadata.logical_time,
                    $($after: &self.$after,)*
                };
                serde::Serialize::serialize(&wire, serializer)
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                #[derive(serde::Deserialize)]
                #[serde(deny_unknown_fields)]
                struct $name {
                    $($before: $before_ty,)*
                    position: pn_records::Position,
                    logical_time: u64,
                    $($after: $after_ty,)*
                }
                let wire = <$name as serde::Deserialize>::deserialize(deserializer)?;
                Ok(Self {
                    $($before: wire.$before,)*
                    metadata: $crate::metadata::ActMetadata {
                        position: wire.position,
                        logical_time: wire.logical_time,
                    },
                    $($after: wire.$after,)*
                })
            }
        }
    };
}

pub(crate) use projection;
