use std::path::Path;
use std::time::{Duration, Instant};

use crate::support::generations::current_generation;

/// Wait until `<root>/current` names something other than `held`, and hand back
/// what it names instead.
pub fn until_current_moves_past(root: &Path, held: &str, patience: Duration) -> String {
    let deadline = Instant::now() + patience;
    loop {
        if let Some(name) = current_generation(root)
            && name != held
        {
            return name;
        }
        assert!(
            Instant::now() < deadline,
            "`current` still names {held} after {patience:?}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Wait for the renewal loop's first generation and hand back its name.
pub fn until_a_generation_is_published(root: &Path, patience: Duration) -> String {
    let deadline = Instant::now() + patience;
    loop {
        if let Some(name) = current_generation(root) {
            return name;
        }
        assert!(
            Instant::now() < deadline,
            "no generation was published within {patience:?}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}
