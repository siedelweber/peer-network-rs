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

fn display(value: &Value, form: Option<&str>, relation: Option<bool>) -> std::result::Result<String, Error> {
    let form = form.unwrap_or("num");
    if !["num", "exact"].contains(&form) {
        return Err(failure(format!("display: unknown form {form}")));
    }
    let text = value.get_attr(form)?;
    let text = text
        .as_str()
        .ok_or_else(|| failure(format!("display: omitted form {form}")))?;
    let exact = value.get_attr(&format!("{form}_exact"))?;
    let exact = if exact == Value::from(true) {
        true
    } else if exact == Value::from(false) {
        false
    } else {
        return Err(failure("display: absent exactness"));
    };
    if relation.unwrap_or(false) {
        let symbol = value.get_attr(&format!("{form}_relation"))?;
        let symbol = symbol
            .as_str()
            .filter(|symbol| {
                if exact {
                    *symbol == "="
                } else {
                    ["≈", "≤", "≥"].contains(symbol)
                }
            })
            .ok_or_else(|| failure("display: absent or inconsistent relation"))?;
        Ok(format!("{symbol} {text}"))
    } else {
        Ok(text.to_owned())
    }
}

fn carrier_fields(
    record: &Value,
    datasets: &BTreeMap<String, Dataset>,
    used: &Mutex<BTreeSet<String>>,
) -> std::result::Result<Value, Error> {
    let record = serde_json::to_value(record).map_err(|error| failure(error.to_string()))?;
    let mut forms = record
        .get("number_forms")
        .and_then(serde_json::Value::as_object)
        .cloned()
        .unwrap_or_default();
    if let Some(references) = record.get("numeric_refs") {
        for (alias, reference) in references
            .as_object()
            .ok_or_else(|| failure("number_text: expected reference map"))?
        {
            let namespace = reference
                .get("dataset")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| failure("number_text: absent reference dataset"))?;
            let key = reference.get("key").and_then(serde_json::Value::as_str).unwrap_or("name");
            let name = reference
                .get("row")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| failure("number_text: absent reference row"))?;
            let dataset = datasets
                .get(namespace)
                .ok_or_else(|| failure("number_text: unknown reference dataset"))?;
            let matches: Vec<_> = dataset
                .rows
                .iter()
                .filter(|row| row.get(key).and_then(serde_json::Value::as_str) == Some(name))
                .collect();
            let [row] = matches.as_slice() else {
                return Err(failure("number_text: unknown or ambiguous reference row"));
            };
            let value = if let Some(field) = reference.get("field").and_then(serde_json::Value::as_str) {
                row.get("number_forms")
                    .and_then(|fields| fields.get(field))
                    .cloned()
                    .ok_or_else(|| failure("number_text: absent projected reference field"))?
            } else if namespace == crate::numbers::NAMESPACE {
                serde_json::to_value(row).map_err(|error| failure(error.to_string()))?
            } else {
                return Err(failure("number_text: absent reference field"));
            };
            let value = if let Some(index) = reference.get("index") {
                let index = index
                    .as_u64()
                    .and_then(|index| usize::try_from(index).ok())
                    .ok_or_else(|| failure("number_text: invalid reference index"))?;
                value
                    .get(index)
                    .cloned()
                    .ok_or_else(|| failure("number_text: absent reference element"))?
            } else {
                value
            };
            if forms.insert(alias.clone(), value).is_some() {
                return Err(failure("number_text: duplicate local and referenced field"));
            }
            used.lock()
                .map_err(|_| failure("dataset census lock poisoned"))?
                .insert(namespace.to_owned());
        }
    }
    Ok(Value::from(Serde(forms)))
}

fn number_text(text: &str, forms: &Value) -> std::result::Result<String, Error> {
    let mut result = String::new();
    let mut remaining = text;
    while let Some((prefix, suffix)) = remaining.split_once("[[") {
        result.push_str(prefix);
        let (field, tail) = suffix
            .split_once("]]")
            .ok_or_else(|| failure("number_text: unclosed field"))?;
        let (field, mode) = field.split_once(':').unwrap_or((field, "num"));
        let (form, relation) = match mode {
            "num" => (None, None),
            "exact" => (Some("exact"), None),
            "relation" => (None, Some(true)),
            _ => return Err(failure("number_text: unknown display mode")),
        };
        let values = forms.get_attr(field)?;
        if values.is_undefined() {
            return Err(failure(format!("number_text: unknown numeric field {field}")));
        }
        if values.kind() == minijinja::value::ValueKind::Seq {
            let rendered = values
                .try_iter()?
                .map(|value| display(&value, form, relation))
                .collect::<std::result::Result<Vec<_>, _>>()?;
            result.push_str(&rendered.join(", "));
        } else {
            result.push_str(&display(&values, form, relation)?);
        }
        remaining = tail;
    }
    result.push_str(remaining);
    Ok(result)
}

fn present_row(
    row: &BTreeMap<String, serde_json::Value>,
    datasets: &BTreeMap<String, Dataset>,
    used: &Mutex<BTreeSet<String>>,
) -> std::result::Result<Value, Error> {
    let Some(fields) = row.get("numeric_text") else {
        return Ok(Value::from(Serde(row)));
    };
    let fields = fields
        .as_array()
        .ok_or_else(|| failure("number_text: expected text field list"))?;
    let forms = carrier_fields(&Value::from(Serde(row)), datasets, used)?;
    let mut view = row.clone();
    for field in fields {
        let field = field
            .as_str()
            .ok_or_else(|| failure("number_text: expected text field name"))?;
        let text = row
            .get(field)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| failure("number_text: absent text field"))?;
        view.insert(field.to_owned(), serde_json::Value::String(number_text(text, &forms)?));
    }
    Ok(Value::from(Serde(view)))
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

fn present_rows(
    dataset: &Dataset,
    datasets: &BTreeMap<String, Dataset>,
    used: &Mutex<BTreeSet<String>>,
) -> std::result::Result<Value, Error> {
    let views = dataset
        .rows
        .iter()
        .map(|row| present_row(row, datasets, used))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(Value::from(Serde(views)))
}

fn install_numeric_text(
    environment: &mut Environment<'_>,
    datasets: &Arc<BTreeMap<String, Dataset>>,
    used: &Arc<Mutex<BTreeSet<String>>>,
) {
    environment.add_filter("number", number);
    environment.add_filter("display", display);
    let text_data = Arc::clone(datasets);
    let text_used = Arc::clone(used);
    environment.add_filter("number_text", move |text: String, record: Value| {
        let forms = carrier_fields(&record, &text_data, &text_used)?;
        number_text(&text, &forms)
    });
}

fn install_registry(
    environment: &mut Environment<'_>,
    datasets: Arc<BTreeMap<String, Dataset>>,
    used: Arc<Mutex<BTreeSet<String>>>,
) {
    install_numbers(environment, &datasets, &used);
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

fn install_numbers(
    environment: &mut Environment<'_>,
    datasets: &Arc<BTreeMap<String, Dataset>>,
    used: &Arc<Mutex<BTreeSet<String>>>,
) {
    for (name, relation) in [("numval", false), ("numrel", true)] {
        let data = Arc::clone(datasets);
        let usage = Arc::clone(used);
        environment.add_function(
            name,
            move |id: String, form: Option<String>| -> std::result::Result<String, Error> {
                let namespace = crate::numbers::NAMESPACE;
                let dataset = data.get(namespace).ok_or_else(|| failure("absent number registry"))?;
                usage
                    .lock()
                    .map_err(|_| failure("dataset census lock poisoned"))?
                    .insert(namespace.to_owned());
                let form = form.as_deref().unwrap_or("num");
                if !["num", "exact"].contains(&form) {
                    return Err(failure(format!("number: unknown form {id}.{form}")));
                }
                let matches: Vec<_> = dataset
                    .rows
                    .iter()
                    .filter(|row| row.get("id").and_then(serde_json::Value::as_str) == Some(id.as_str()))
                    .collect();
                let [row] = matches.as_slice() else {
                    return Err(failure(format!("number: unknown or duplicate id {id}")));
                };
                let value = row
                    .get(form)
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| failure(format!("number: omitted form {id}.{form}")))?;
                let exact = row
                    .get(&format!("{form}_exact"))
                    .and_then(serde_json::Value::as_bool)
                    .ok_or_else(|| failure(format!("number: missing exactness {id}.{form}")))?;
                Ok(if relation {
                    let symbol = row
                        .get(&format!("{form}_relation"))
                        .and_then(serde_json::Value::as_str)
                        .filter(|symbol| {
                            if exact {
                                *symbol == "="
                            } else {
                                ["≈", "≤", "≥"].contains(symbol)
                            }
                        })
                        .ok_or_else(|| failure(format!("number: missing or invalid relation {id}.{form}")))?;
                    format!("{symbol} {value}")
                } else {
                    value.to_owned()
                })
            },
        );
    }
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
                [row] => present_row(row, &row_data, &row_used),
                [] => Err(failure(format!("absent row: {name}: {criteria:?}"))),
                _ => Err(failure(format!("ambiguous row: {name}: {criteria:?}"))),
            }
        },
    );
    install_numeric_text(&mut environment, &datasets, &used);
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
        present_rows(dataset, &datasets, &collection_usage)
    });
    environment.add_function(
        "require",
        |condition: bool, message: String| -> std::result::Result<String, Error> {
            if condition { Ok(String::new()) } else { Err(failure(message)) }
        },
    );

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
