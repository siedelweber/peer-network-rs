use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use crate::envelope::Dataset;

fn field<'a>(row: &'a BTreeMap<String, Value>, name: &str) -> crate::Result<&'a str> {
    row.get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("kind registry: expected string field {name}").into())
}

pub fn view(dataset: &Dataset) -> crate::Result<Value> {
    let mut sections: BTreeMap<String, Vec<_>> = BTreeMap::new();
    let mut base = BTreeSet::new();
    let mut extensions = BTreeSet::new();
    let mut names = BTreeSet::new();
    let mut kinds = BTreeSet::new();
    let mut devices = 0;
    let mut hybrids = 0;
    let mut effective = BTreeMap::new();
    for row in &dataset.rows {
        let section = field(row, "section")?;
        let environment = field(row, "environment")?;
        let kind = field(row, "kind")?;
        let category = field(row, "category")?;
        let status = field(row, "status")?;
        sections.entry(section.to_owned()).or_default().push(row);
        if category == "device" {
            if !kind.is_empty() || status != "device" {
                return Err("kind registry: a presentation device has no kind or attestation".into());
            }
            devices += 1;
            continue;
        }
        if environment.is_empty() || kind.is_empty() || !matches!(status, "firm" | "borderline") {
            return Err("kind registry: expected a named firm or borderline pair".into());
        }
        let pair = (environment.to_owned(), kind.to_owned());
        let relation = if category == "extension" {
            &mut extensions
        } else if matches!(category, "ordinary" | "hybrid") {
            names.insert(environment);
            kinds.insert(kind);
            hybrids += usize::from(category == "hybrid");
            &mut base
        } else {
            return Err(format!("kind registry: unknown row category {category}").into());
        };
        if !relation.insert(pair.clone()) || effective.insert(pair, row).is_some() {
            return Err(format!("kind registry: duplicate pair {environment}/{kind}").into());
        }
    }
    let mut senses: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for (name, kind) in effective.keys() {
        senses.entry(name).or_default().insert(kind);
    }
    let homonyms: Vec<_> = effective
        .iter()
        .filter(|((name, _), _)| senses.get(name.as_str()).is_some_and(|values| values.len() > 1))
        .map(|(_, row)| *row)
        .collect();
    let catalogue: Vec<_> = effective
        .iter()
        .filter(|(pair, _)| base.contains(*pair))
        .map(|(_, row)| *row)
        .collect();
    let extension_rows: Vec<_> = effective
        .iter()
        .filter(|(pair, _)| extensions.contains(*pair))
        .map(|(_, row)| *row)
        .collect();
    Ok(json!({
        "sections": sections,
        "catalogue": catalogue,
        "extensions": extension_rows,
        "homonyms": homonyms,
        "counts": [
            {"measure": "Names", "count": names.len()},
            {"measure": "Rows", "count": base.len()},
            {"measure": "Kinds", "count": kinds.len()},
            {"measure": "Declared hybrids", "count": hybrids},
            {"measure": "Device classes", "count": devices},
        ],
    }))
}
