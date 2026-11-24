//! `prepare` — what each backend hears once, before a run asks for every name.

use std::sync::{Arc, Mutex};

use crate::error::StoreError;
use crate::secret::Secret;
use crate::store::{Registry, Store};

/// Every `prepare` call a backend received, one entry per call.
type Heard = Arc<Mutex<Vec<Vec<String>>>>;

/// A backend that holds nothing and records each `prepare` it is given.
struct Recording {
    id: &'static str,
    heard: Heard,
}

impl Store for Recording {
    fn id(&self) -> &str {
        self.id
    }
    fn resolve(&self, _name: &str) -> Result<Option<Secret>, StoreError> {
        Ok(None)
    }
    fn health(&self) -> Result<(), StoreError> {
        Ok(())
    }
    fn prepare(&self, names: &[&str]) {
        self.heard
            .lock()
            .expect("the record lock")
            .push(names.iter().map(|name| (*name).to_owned()).collect());
    }
}

fn recording(id: &'static str) -> (Box<dyn Store>, Heard) {
    let heard = Heard::default();
    let store = Recording {
        id,
        heard: Arc::clone(&heard),
    };
    (Box::new(store), heard)
}

fn calls(heard: &Heard) -> Vec<Vec<String>> {
    heard.lock().expect("the record lock").clone()
}

fn routes(pairs: &[(&str, &str)]) -> std::collections::BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(name, store)| ((*name).to_owned(), (*store).to_owned()))
        .collect()
}

#[test]
fn each_backend_is_prepared_once_with_only_the_names_routed_to_it() {
    let (company, company_heard) = recording("company");
    let (personal, personal_heard) = recording("personal");
    let registry = Registry::new(vec![company, personal]).with_routes(routes(&[
        ("A", "company"),
        ("B", "personal"),
        ("C", "company"),
    ]));

    registry.prepare(&["A", "B", "C"]);

    assert_eq!(calls(&company_heard), [["A", "C"]]);
    assert_eq!(calls(&personal_heard), [["B"]]);
}

#[test]
fn a_backend_no_name_is_routed_to_is_not_prepared() {
    let (company, company_heard) = recording("company");
    let (personal, personal_heard) = recording("personal");
    let registry = Registry::new(vec![company, personal]).with_routes(routes(&[("A", "company")]));

    registry.prepare(&["A"]);

    assert_eq!(calls(&company_heard), [["A"]]);
    assert!(calls(&personal_heard).is_empty(), "nothing routes to it");
}

#[test]
fn a_name_that_would_ask_several_backends_prepares_none_of_them() {
    // The shape `resolve` reports as `Ambiguous`: no single backend to name,
    // so none is told the name is coming.
    let (company, company_heard) = recording("company");
    let (personal, personal_heard) = recording("personal");
    let registry = Registry::new(vec![company, personal]);

    registry.prepare(&["DATABASE_URL"]);

    assert!(calls(&company_heard).is_empty());
    assert!(calls(&personal_heard).is_empty());
}
