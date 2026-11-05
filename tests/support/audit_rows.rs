//! Reading the daemon's audit rows back by the name they record.

/// Every row naming `name`, whole rather than one field, so a case can read
/// `source` and `age_ms` alongside `decision` — in the order they were
/// written, since a caller comparing two calls for the same name needs that.
pub fn rows_for(rows: &str, name: &str) -> Vec<serde_json::Value> {
    rows.lines()
        .map(|line| serde_json::from_str(line).expect("an audit row is JSON"))
        .filter(|row: &serde_json::Value| {
            row["names"]
                .as_array()
                .is_some_and(|names| names.len() == 1 && names[0].as_str() == Some(name))
        })
        .collect()
}

/// The `decision` on the one row that named `name`.
pub fn decision_for(rows: &str, name: &str) -> String {
    let mut found: Vec<String> = Vec::new();
    for line in rows.lines() {
        let row: serde_json::Value = serde_json::from_str(line).expect("an audit row is JSON");
        let names = row["names"].as_array().expect("a row carries names");
        if names.len() == 1 && names[0].as_str() == Some(name) {
            found.push(
                row["decision"]
                    .as_str()
                    .expect("a row carries a decision")
                    .to_owned(),
            );
        }
    }
    assert_eq!(found.len(), 1, "rows naming {name} in:\n{rows}");
    found.remove(0)
}
