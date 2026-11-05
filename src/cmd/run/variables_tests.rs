use super::Binding;
use super::binding_tests::config_of;

/// Two labels for one variable is the ordinary shape of one credential per
/// environment. Asked for together, ordering must not pick the winner.
#[test]
fn a_variable_two_names_answer_to_is_set_by_neither() {
    let config = config_of(r#"{"secrets":{"A":{"key":"SHARED"},"B":{"key":"SHARED"}}}"#);
    let bindings = [
        Binding::declared("A", &config).expect("valid"),
        Binding::declared("B", &config).expect("valid"),
    ];
    let mut notes: Vec<u8> = Vec::new();
    let plans = super::deconflict(&bindings, &mut notes);
    assert_eq!(plans, [["A"], ["B"]]);
    let said = String::from_utf8_lossy(&notes);
    assert!(said.contains("SHARED"), "{said}");
}

/// Reversing the flags must not reverse the outcome — which is the property
/// the test above cannot see on its own.
#[test]
fn the_undecidable_case_does_not_depend_on_flag_order() {
    let config = config_of(r#"{"secrets":{"A":{"key":"SHARED"},"B":{"key":"SHARED"}}}"#);
    let forwards = [
        Binding::declared("A", &config).expect("valid"),
        Binding::declared("B", &config).expect("valid"),
    ];
    let backwards = [
        Binding::declared("B", &config).expect("valid"),
        Binding::declared("A", &config).expect("valid"),
    ];
    let mut sink: Vec<u8> = Vec::new();
    let one = super::deconflict(&forwards, &mut sink);
    let other = super::deconflict(&backwards, &mut sink);
    assert_eq!(one, [["A"], ["B"]]);
    assert_eq!(other, [["B"], ["A"]]);
}

#[test]
fn one_name_asked_for_twice_collides_with_nothing() {
    // Two `-s LABEL` are one credential requested twice, not two claimants.
    let config = config_of(r#"{"secrets":{"LABEL":{"key":"THE_VARIABLE"}}}"#);
    let bindings = [
        Binding::declared("LABEL", &config).expect("valid"),
        Binding::declared("LABEL", &config).expect("valid"),
    ];
    let mut notes: Vec<u8> = Vec::new();
    let plans = super::deconflict(&bindings, &mut notes);
    assert_eq!(
        plans,
        [["LABEL", "THE_VARIABLE"], ["LABEL", "THE_VARIABLE"]]
    );
    assert_eq!(String::from_utf8_lossy(&notes), "");
}

#[test]
fn an_inference_never_overwrites_an_instruction() {
    let config = config_of(r#"{"secrets":{"OTHER":{"key":"TARGET"}}}"#);
    let bindings = [
        Binding::declared("TARGET=CHOSEN", &config).expect("valid"),
        Binding::declared("OTHER", &config).expect("valid"),
    ];
    let mut notes: Vec<u8> = Vec::new();
    let plans = super::deconflict(&bindings, &mut notes);
    assert_eq!(plans, [["TARGET"], ["OTHER"]]);
    assert!(String::from_utf8_lossy(&notes).contains("TARGET"));
}

/// The wall, removed rather than documented.
///
/// Every one of these was a paragraph in somebody's rules file, which is a
/// deferred fix: it reaches whoever read it, once, before they made the
/// mistake. The warning reaches them at the moment they make it.
#[test]
fn a_literal_dollar_name_handed_to_a_non_shell_is_reported() {
    use super::quoting_warnings;
    use std::ffi::OsString;

    let plans = vec![vec!["TOKEN".to_owned()]];
    let args: Vec<OsString> = ["-H", "Authorization: Bearer $TOKEN"]
        .iter()
        .map(OsString::from)
        .collect();
    let warnings = quoting_warnings(&OsString::from("curl"), &args, &plans);
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(warnings[0].contains("$TOKEN"), "{warnings:?}");
    assert!(warnings[0].contains("sh -c"), "{warnings:?}");
    // `${TOKEN}` is the same mistake with braces, and it used to slip past
    // a check that only looked for the bare spelling.
    let braced: Vec<OsString> = vec![OsString::from("Bearer ${TOKEN}")];
    assert_eq!(
        quoting_warnings(&OsString::from("curl"), &braced, &plans).len(),
        1
    );
}

/// THE CONTROL, and it is the reason the list of interpreters exists.
///
/// `sh -c '… $TOKEN …'` is the CORRECT form and contains the same literal.
/// A check that warned on it would fire on every properly written command
/// in the tool's own documentation — and a warning that fires on the right
/// answer is one people learn to ignore, which costs more than it saves.
#[test]
fn the_sanctioned_shell_form_is_never_warned_about() {
    use super::quoting_warnings;
    use std::ffi::OsString;

    let plans = vec![vec!["TOKEN".to_owned()]];
    for program in ["sh", "/bin/bash", "zsh", "env", "ssh"] {
        let args: Vec<OsString> = ["-c", "curl -H \"Authorization: Bearer $TOKEN\" $URL"]
            .iter()
            .map(OsString::from)
            .collect();
        assert!(
            quoting_warnings(&OsString::from(program), &args, &plans).is_empty(),
            "`{program}` was warned about, and it expands its own arguments"
        );
    }
    // A name nobody asked for is not this tool's business either.
    let args = vec![OsString::from("$SOMETHING_ELSE")];
    assert!(quoting_warnings(&OsString::from("curl"), &args, &plans).is_empty());
}
