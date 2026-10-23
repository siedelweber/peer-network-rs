use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use minijinja::value::{Kwargs, Serde, Value};
use minijinja::{AutoEscape, Environment, Error, ErrorKind, UndefinedBehavior};

use crate::envelope::Dataset;

fn failure(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::InvalidOperation, message.into())
}

fn number(value: &Value) -> std::result::Result<String, Error> {
    if value.kind() == minijinja::value::ValueKind::Number {
        Ok(value.to_string())
    } else {
        Err(failure("number: expected a number"))
    }
}

fn exhibit(text: &str, labels: &Value) -> std::result::Result<String, Error> {
    let mut rendered = text.to_owned();
    for label in labels.try_iter()? {
        let label = label.as_str().ok_or_else(|| failure("exhibit: expected label strings"))?;
        rendered = rendered.replace(&format!("({label})"), &format!("(``{label}``)"));
    }
    Ok(rendered)
}

fn split(value: &str, separator: &str) -> Vec<String> {
    value.split(separator).map(str::to_owned).collect()
}

fn install_registry(
    environment: &mut Environment<'_>,
    datasets: Arc<BTreeMap<String, Dataset>>,
    used: Arc<Mutex<BTreeSet<String>>>,
) {
    environment.add_function("kinds_registry", move || -> std::result::Result<Value, Error> {
        let name = "org.peer-network.kinds.registry";
        let dataset = datasets.get(name).ok_or_else(|| failure(format!("absent dataset: {name}")))?;
        used.lock()
            .map_err(|_| failure("dataset census lock poisoned"))?
            .insert(name.to_owned());
        let view = crate::registry::view(dataset).map_err(|error| failure(error.to_string()))?;
        Ok(Value::from(Serde(view)))
    });
}

#[tracing::instrument(
    name = "rule:observe:spans",
    fields(
        execution_owner = "DOCUMENTS",
        claim_owner = "ROOT",
        claim_label = "rule:observe:spans",
        source_item = "rendering::render"
    ),
    ret
)]
pub fn render(
    source: &str,
    fragments: &BTreeMap<String, String>,
    datasets: &BTreeMap<String, Dataset>,
    document: &str,
) -> crate::Result<(String, Vec<String>)> {
    let mut environment = Environment::new();
    environment.set_undefined_behavior(UndefinedBehavior::Strict);
    environment.set_auto_escape_callback(|_| AutoEscape::None);
    environment.set_syntax(
        minijinja::syntax::SyntaxConfig::builder()
            .keep_trailing_newline(true)
            .build()?,
    );
    let datasets = Arc::new(datasets.clone());
    let used = Arc::new(Mutex::new(BTreeSet::new()));
    let record_path = crate::census::record(document).then(|| document.to_owned());
    let collection_record = record_path.clone();
    let row_data = Arc::clone(&datasets);
    let row_used = Arc::clone(&used);
    environment.add_function(
        "row",
        move |name: String, kwargs: Kwargs| -> std::result::Result<Value, Error> {
            let dataset = row_data
                .get(&name)
                .ok_or_else(|| failure(format!("absent dataset: {name}")))?;
            row_used
                .lock()
                .map_err(|_| failure("dataset census lock poisoned"))?
                .insert(name.clone());
            let mut criteria = Vec::new();
            for key in kwargs.args() {
                criteria.push((key.to_owned(), kwargs.get::<Value>(key)?));
            }
            kwargs.assert_all_used()?;
            if name == "org.peer-network.records.index"
                && let Some(expected) = &record_path
                && !criteria
                    .iter()
                    .any(|(key, value)| key == "path" && value.as_str() == Some(expected.as_str()))
            {
                return Err(failure(format!("record row key differs from document path: {expected}")));
            }
            if criteria.is_empty() {
                return Err(failure(format!("row: {name}: expected key=value")));
            }
            let matches: Vec<_> = dataset
                .rows
                .iter()
                .filter(|row| {
                    criteria
                        .iter()
                        .all(|(key, wanted)| row.get(key).is_some_and(|value| Value::from(Serde(value)) == *wanted))
                })
                .collect();
            match matches.as_slice() {
                [row] => Ok(Value::from(Serde(row))),
                [] => Err(failure(format!("absent row: {name}: {criteria:?}"))),
                _ => Err(failure(format!("ambiguous row: {name}: {criteria:?}"))),
            }
        },
    );
    let collection_usage = Arc::clone(&used);
    install_registry(&mut environment, Arc::clone(&datasets), Arc::clone(&used));
    environment.add_function("rows", move |name: String| -> std::result::Result<Value, Error> {
        if name == "org.peer-network.records.index"
            && let Some(path) = &collection_record
        {
            return Err(failure(format!(
                "record must read its own keyed row, not records-index rows: {path}"
            )));
        }
        let dataset = datasets
            .get(&name)
            .ok_or_else(|| failure(format!("absent dataset: {name}")))?;
        collection_usage
            .lock()
            .map_err(|_| failure("dataset census lock poisoned"))?
            .insert(name);
        Ok(Value::from(Serde(&dataset.rows)))
    });
    environment.add_function(
        "require",
        |condition: bool, message: String| -> std::result::Result<String, Error> {
            if condition { Ok(String::new()) } else { Err(failure(message)) }
        },
    );
    environment.add_filter("number", number);
    environment.add_filter("split", split);
    environment.add_filter("exhibit", exhibit);
    environment.add_filter("toml_string", |value: String| toml::Value::String(value).to_string());
    environment.add_filter("length", |value: Value| -> std::result::Result<usize, Error> {
        value.len().ok_or_else(|| failure("length: expected a collection"))
    });
    for (name, fragment) in fragments {
        environment.add_template(name, fragment)?;
    }
    environment.add_template("document", source)?;
    let rendered = environment.get_template("document")?.render(())?;
    let namespaces = used
        .lock()
        .map_err(|_| "dataset census lock poisoned")?
        .iter()
        .cloned()
        .collect();
    Ok((rendered, namespaces))
}
