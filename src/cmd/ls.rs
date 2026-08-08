//! `keyless ls` — names and where they point, never values.
//!
//! Lists what has been declared in the config. It does not contact a store, so
//! it cannot prompt for keychain access and cannot be slow; and it makes no
//! statement about whether a name currently resolves, which is `doctor --probe`'s
//! job.
//!
//! # Why the environment is a column
//!
//! For Infisical, the environment decides **which real value** comes back:
//! `prod` and `staging` hold the same key names with different secrets. A name
//! whose environment is invisible here is the same hazard as a name that
//! resolves against an invisible default — one layer up, and just as quiet.
//!
//! So every Infisical name shows `<env>:<path>`, and a name with no environment
//! shows `no-env:<path>` — which is the exact set of names that will degrade
//! until they are given one. Backends whose coordinates pick an *item* rather
//! than a *tenant* show `-`; printing a keychain account here would be a lookup
//! detail, not a boundary.

use std::io::{self, Write};

use crate::config::Config;
use crate::store::infisical::Routing;
use crate::store::{self, infisical};

/// What the location column holds for a store whose coordinates name no tenant.
const NO_LOCATION: &str = "-";

/// Write the declared names to `out`.
///
/// Plain columns rather than a table renderer: the output is read by agents at
/// least as often as by people. Exactly four tab-separated fields on every line
/// — `name`, `store`, `location`, `note` — with `-` where there is nothing to
/// say, so a parser never has to count them.
pub fn ls(config: &Config, out: &mut dyn Write) -> io::Result<()> {
    if config.secrets.is_empty() {
        return Ok(());
    }

    let width = config
        .secrets
        .keys()
        .map(String::len)
        .max()
        .unwrap_or(0)
        .max(4);

    // Built once. `ls` describes the config, so it passes no invocation
    // environment: `--env` belongs to a `run`, and claiming it here would show
    // an environment this listing cannot know a future command will supply.
    let routing = Routing::from_config(config, None);

    for (name, route) in &config.secrets {
        let store = route.store.as_deref().unwrap_or("*");
        let location = location_of(config, &routing, name);
        let note = route.note.as_deref().unwrap_or(NO_LOCATION);
        writeln!(out, "{name:<width$}\t{store}\t{location}\t{note}")?;
    }
    Ok(())
}

/// Where a name points, when that is a question with an answer worth printing.
///
/// The store is chosen by [`store::choose_store`] — the same rule a lookup
/// applies — so this column cannot disagree with the backend that will actually
/// answer. An ambiguous name has no answer yet, and says so with `-` rather than
/// guessing a store in a listing when the resolver refuses to guess one in a run.
fn location_of(config: &Config, routing: &Routing, name: &str) -> String {
    match store::choose_store(config, Some(name), None) {
        Ok(store) if store == infisical::STORE_ID => routing.route(name).describe(),
        _ => NO_LOCATION.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::ls;
    use crate::config::Config;

    fn render(json: &str) -> String {
        let config: Config = serde_json::from_str(json).expect("valid config");
        let mut out: Vec<u8> = Vec::new();
        ls(&config, &mut out).expect("writing to a Vec cannot fail");
        String::from_utf8(out).expect("utf-8")
    }

    #[test]
    fn an_empty_config_prints_nothing() {
        assert_eq!(render("{}"), "");
    }

    #[test]
    fn names_are_listed_in_a_stable_order() {
        let output = render(r#"{"secrets":{"ZED":{},"ALPHA":{},"MID":{}}}"#);
        let names: Vec<&str> = output
            .lines()
            .map(|l| l.split('\t').next().unwrap_or("").trim())
            .collect();
        assert_eq!(names, ["ALPHA", "MID", "ZED"]);
    }

    /// The tab-separated fields of one line, by name.
    fn fields<'a>(output: &'a str, name: &str) -> Vec<&'a str> {
        output
            .lines()
            .find(|line| line.split('\t').next().is_some_and(|n| n.trim() == name))
            .unwrap_or_else(|| panic!("`{name}` is not in the listing:\n{output}"))
            .split('\t')
            .collect()
    }

    /// A config where Infisical is the only backend, so no name is ambiguous.
    fn infisical_only(secrets: &str) -> String {
        format!(
            r#"{{"stores":{{"keychain":{{"enabled":false}},
                 "infisical":{{"enabled":true,"path":"/backend"}}}},
                "secrets":{secrets}}}"#
        )
    }

    #[test]
    fn an_infisical_name_shows_the_environment_it_would_resolve_against() {
        // The hazard one layer up from the lookup: an environment decides WHICH
        // REAL VALUE comes back, so a listing that does not say which one is a
        // listing that hides the difference between staging and production.
        let output = render(&infisical_only(r#"{"PINNED":{"env":"prod"}}"#));
        assert_eq!(fields(&output, "PINNED")[2], "prod:/backend");
    }

    #[test]
    fn a_name_with_no_environment_is_visibly_missing_one() {
        // Exactly the set of names that will degrade until somebody gives them
        // an environment, readable without contacting anything.
        let output = render(&infisical_only(r#"{"LOOSE":{}}"#));
        assert_eq!(fields(&output, "LOOSE")[2], "no-env:/backend");
    }

    #[test]
    fn a_backend_whose_coordinates_name_no_tenant_shows_nothing() {
        // A keychain account picks an item, not a tenancy boundary. Printing it
        // here would be a lookup detail leaking into a listing.
        let output = render(
            r#"{"stores":{"keychain":{"enabled":true}},
                "secrets":{"GH":{"store":"keychain","account":"demo-token"}}}"#,
        );
        let line = fields(&output, "GH");
        assert_eq!(line[2], "-");
        assert!(!output.contains("demo-token"));
    }

    #[test]
    fn an_ambiguous_name_claims_no_location() {
        // The resolver refuses to guess a store for this name, so the listing
        // must not guess one either — a column that disagreed with the run
        // would be worse than an empty one.
        let output = render(
            r#"{"stores":{"keychain":{"enabled":true},
                          "infisical":{"enabled":true}},
                "secrets":{"EITHER":{"env":"prod"}}}"#,
        );
        assert_eq!(fields(&output, "EITHER")[2], "-");
    }

    #[test]
    fn every_line_has_the_same_four_fields() {
        // Read by agents at least as often as by people. A fixed field count
        // means a parser never has to work out whether a note was present.
        let output = render(
            r#"{"stores":{"keychain":{"enabled":true}},
                "secrets":{"WITH":{"note":"a note"},"WITHOUT":{}}}"#,
        );
        for line in output.lines() {
            assert_eq!(line.split('\t').count(), 4, "line was: {line}");
        }
        assert_eq!(fields(&output, "WITH")[3], "a note");
        assert_eq!(fields(&output, "WITHOUT")[3], "-");
    }

    #[test]
    fn no_field_that_could_hold_a_value_is_printed() {
        // The config has no value field at all, which is the point; this test
        // exists so that adding one is visibly a breaking change here.
        let output = render(r#"{"secrets":{"A":{"account":"acct-name","note":"prod db"}}}"#);
        assert!(output.starts_with('A'));
        assert!(output.contains("prod db"));
        assert!(
            !output.contains("acct-name"),
            "the account is a lookup detail, not for ls"
        );
    }
}
