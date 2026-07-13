use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

fn canonicalize(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<_> = map.keys().cloned().collect();
            keys.sort();

            let mut ordered = Map::new();
            for key in keys {
                if let Some(v) = map.get(&key) {
                    ordered.insert(key, canonicalize(v.clone()));
                }
            }

            Value::Object(ordered)
        }
        Value::Array(items) => {
            Value::Array(items.into_iter().map(canonicalize).collect())
        }
        other => other,
    }
}

pub fn canonical_event_hash(events: Vec<Value>) -> anyhow::Result<String> {
    let stable = canonicalize(Value::Array(events));
    let payload = serde_json::to_string(&stable)?;

    let mut hasher = Sha256::new();
    hasher.update(payload.as_bytes());

    Ok(format!("{:x}", hasher.finalize()))
}

pub fn calculate_next_event_hash(previous_hash: Option<&str>, event: &Value) -> anyhow::Result<String> {
    let stable = canonicalize(event.clone());
    let payload = serde_json::to_string(&stable)?;

    let mut hasher = Sha256::new();
    if let Some(prev) = previous_hash {
        hasher.update(prev.as_bytes());
    }
    hasher.update(payload.as_bytes());

    Ok(format!("{:x}", hasher.finalize()))
}
