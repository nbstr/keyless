use super::Store;
use crate::error::StoreError;
use crate::secret::Secret;

mod asks;
mod daemon_suppression;
mod declared;
mod explicit;
mod ordered;

struct Fixed {
    id: &'static str,
    value: Option<&'static str>,
}

impl Store for Fixed {
    fn id(&self) -> &str {
        self.id
    }
    fn resolve(&self, _name: &str) -> Result<Option<Secret>, StoreError> {
        Ok(self.value.map(|v| Secret::new(v.to_owned())))
    }
    fn health(&self) -> Result<(), StoreError> {
        Ok(())
    }
}

struct Broken(&'static str);

impl Store for Broken {
    fn id(&self) -> &str {
        self.0
    }
    fn resolve(&self, _name: &str) -> Result<Option<Secret>, StoreError> {
        Err(StoreError::Unavailable {
            store: self.0.to_owned(),
            detail: "stub is always down".to_owned(),
        })
    }
    fn health(&self) -> Result<(), StoreError> {
        Err(StoreError::Unavailable {
            store: self.0.to_owned(),
            detail: "stub is always down".to_owned(),
        })
    }
}

/// Two backends that both hold the name, which is the shape the policy is
/// about: a company vault and a personal one, each with a `DATABASE_URL`.
fn two_tenants() -> Vec<Box<dyn Store>> {
    vec![
        Box::new(Fixed {
            id: "company",
            value: Some("decoy-company-value"),
        }),
        Box::new(Fixed {
            id: "personal",
            value: Some("decoy-personal-value"),
        }),
    ]
}
