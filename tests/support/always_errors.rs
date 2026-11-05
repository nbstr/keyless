use keyless::error::StoreError;
use keyless::secret::Secret;
use keyless::store::Store;

/// A backend that fails every call.
///
/// Defined here, in a separate crate, which also proves the `Store` seam is
/// genuinely public: another agent can add Infisical or Proton Pass without
/// touching `run`.
pub struct AlwaysErrors(pub &'static str);

impl Store for AlwaysErrors {
    fn id(&self) -> &str {
        self.0
    }
    fn resolve(&self, _name: &str) -> Result<Option<Secret>, StoreError> {
        Err(StoreError::Backend {
            store: self.0.to_owned(),
            detail: "deliberately broken for the test".to_owned(),
        })
    }
    fn health(&self) -> Result<(), StoreError> {
        Err(StoreError::Unavailable {
            store: self.0.to_owned(),
            detail: "deliberately broken for the test".to_owned(),
        })
    }
}
