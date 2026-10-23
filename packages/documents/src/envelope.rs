use std::collections::BTreeMap;
use std::fmt;

use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::{Error, Result};

#[derive(Clone, Debug, Serialize)]
pub struct Dataset {
    pub namespace: String,
    pub version: [u64; 3],
    pub rows: Vec<BTreeMap<String, Value>>,
}

fn namespace_valid(namespace: &str) -> bool {
    let atoms: Vec<_> = namespace.split('.').collect();
    atoms.len() == 4
        && atoms.starts_with(&["org", "peer-network"])
        && atoms.iter().all(|atom| {
            !atom.is_empty()
                && atom
                    .split('-')
                    .all(|word| !word.is_empty() && word.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit()))
        })
}

fn version_from_text(text: &str) -> Result<[u64; 3]> {
    let text = text.trim();
    let inner = text
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .ok_or("version: expected triple")?;
    let words: Vec<_> = inner.split(',').map(str::trim).collect();
    if words.len() != 3
        || words.iter().any(|word| {
            word.is_empty() || !word.bytes().all(|byte| byte.is_ascii_digit()) || (word.len() > 1 && word.starts_with('0'))
        })
    {
        return Err("version: expected shortest-spelled triple".into());
    }
    let version = [words[0].parse()?, words[1].parse()?, words[2].parse()?];
    if version[0] != 1 {
        return Err("version: unsupported major".into());
    }
    Ok(version)
}

fn require_namespace(namespace: &str) -> Result<()> {
    if namespace_valid(namespace) {
        Ok(())
    } else {
        Err("namespace: expected org.peer-network.<area>.<name>".into())
    }
}

struct DatasetVisitor;

impl<'de> Visitor<'de> for DatasetVisitor {
    type Value = Dataset;

    /// Justified: This private serde adapter inherits the dataset input boundary, which records the complete source and parsed result without adding Debug bounds to the deserializer.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("namespace then version then rows")
    }

    /// Justified: This private serde adapter inherits the dataset input boundary, which records the complete source and parsed result without adding Debug bounds to the deserializer.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> std::result::Result<Dataset, M::Error> {
        if map.next_key::<String>()?.as_deref() != Some("namespace") {
            return Err(de::Error::custom("namespace: missing, misspelled or misordered first key"));
        }
        let namespace = map.next_value::<String>()?;
        require_namespace(&namespace).map_err(de::Error::custom)?;
        if map.next_key::<String>()?.as_deref() != Some("version") {
            return Err(de::Error::custom("version: missing, misspelled or misordered second key"));
        }
        let raw = map.next_value::<Box<serde_json::value::RawValue>>()?;
        let version = version_from_text(raw.get()).map_err(de::Error::custom)?;
        if map.next_key::<String>()?.as_deref() != Some("rows") {
            return Err(de::Error::custom("rows: expected payload array"));
        }
        let rows = map.next_value()?;
        if let Some(key) = map.next_key::<String>()? {
            return Err(de::Error::custom(format!("unexpected or duplicate key: {key}")));
        }
        Ok(Dataset {
            namespace,
            version,
            rows,
        })
    }
}

impl<'de> Deserialize<'de> for Dataset {
    /// Justified: This private serde adapter inherits the dataset input boundary, which records the complete source and parsed result without adding Debug bounds to the deserializer.
    /// Coverage exception for (´[ROOT-rule:observe:spans]´); the checked operation registry binds this item to its enclosing boundary and executed witness.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        deserializer.deserialize_map(DatasetVisitor)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    namespace: String,
    version: [u64; 3],
    rows: Vec<BTreeMap<String, toml::Value>>,
}

fn json_value(value: toml::Value, key: &str) -> Result<Value> {
    match value {
        toml::Value::Datetime(_) => Err(format!("{key}: datetime is outside the dataset model").into()),
        toml::Value::Float(number) if !number.is_finite() => {
            Err(format!("{key}: non-finite value is outside the dataset model").into())
        }
        toml::Value::Array(values) => values
            .into_iter()
            .enumerate()
            .map(|(index, value)| json_value(value, &format!("{key}[{index}]")))
            .collect::<Result<Vec<_>>>()
            .map(Value::Array),
        toml::Value::Table(values) => values
            .into_iter()
            .map(|(name, value)| Ok((name.clone(), json_value(value, &format!("{key}.{name}"))?)))
            .collect::<Result<serde_json::Map<_, _>>>()
            .map(Value::Object),
        value => Ok(serde_json::to_value(value)?),
    }
}

#[tracing::instrument(
    name = "rule:observe:spans",
    fields(
        execution_owner = "DOCUMENTS",
        claim_owner = "ROOT",
        claim_label = "rule:observe:spans",
        source_item = "envelope::input"
    ),
    ret
)]
pub fn input(text: &str) -> Result<Dataset> {
    let mut lines = text
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'));
    let first = lines.next().ok_or("namespace: missing first key")?;
    let header: toml::Table = toml::from_str(first).map_err(|error| format!("namespace: {error}"))?;
    let namespace = header
        .get("namespace")
        .and_then(toml::Value::as_str)
        .ok_or("namespace: missing, misspelled or misordered first key")?
        .to_owned();
    if header.len() != 1 {
        return Err("namespace: expected exactly one first key".into());
    }
    require_namespace(&namespace)?;
    let second = lines.next().ok_or("version: missing second key")?;
    let (key, raw) = second.split_once('=').ok_or("version: missing second key")?;
    if key.trim() != "version" {
        return Err("version: missing, misspelled or misordered second key".into());
    }
    let raw = raw.split('#').next().unwrap_or_default();
    let version = version_from_text(raw)?;
    let payload: Input = toml::from_str(text)?;
    if payload.namespace != namespace || payload.version != version {
        return Err("envelope: duplicate or inconsistent declaration".into());
    }
    Ok(Dataset {
        namespace,
        version,
        rows: payload
            .rows
            .into_iter()
            .enumerate()
            .map(|(index, row)| {
                row.into_iter()
                    .map(|(name, value)| Ok((name.clone(), json_value(value, &format!("rows[{index}].{name}"))?)))
                    .collect()
            })
            .collect::<Result<_>>()?,
    })
}

#[tracing::instrument(
    name = "rule:observe:spans",
    fields(
        execution_owner = "DOCUMENTS",
        claim_owner = "ROOT",
        claim_label = "rule:observe:spans",
        source_item = "envelope::json"
    ),
    ret
)]
pub fn json(text: &str) -> Result<Dataset> {
    serde_json::from_str(text).map_err(Error::from)
}

#[tracing::instrument(
    name = "rule:observe:spans",
    fields(
        execution_owner = "DOCUMENTS",
        claim_owner = "ROOT",
        claim_label = "rule:observe:spans",
        source_item = "envelope::bytes"
    ),
    ret
)]
pub fn bytes(dataset: &Dataset) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(dataset)?;
    bytes.push(b'\n');
    Ok(bytes)
}
