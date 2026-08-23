//! The vocabulary every status surface shares: a mark, a state word, an action.
//!
//! # Why the axis is DEPTH OF PROOF, not "connected"
//!
//! `keyless` holds no connection to anything. Every backend call is a fresh
//! subprocess spawn or a fresh socket round trip, and nothing is kept open
//! between two of them. So "connected" is a property this tool cannot have and
//! cannot report; what it can report is **what was proven, just now, and how far
//! the proof reached**.
//!
//! That is not a wording preference. It is the difference between a report that
//! flatters and one that is true, and the codebase has the measurement: `store
//! keychain ok` was printed after running `security list-keychains` — a command
//! that proves a binary answered and touches no item at all. Three depths exist
//! and only the third is worth a tick:
//!
//! 1. the vendor binary ran,
//! 2. a **read path** answered — a search reached the item store and came back
//!    with a definite yes or no,
//! 3. a **declared name** came back, which is `doctor --probe` and which reads a
//!    real credential to do it.
//!
//! Depth 1 dressed as depth 3 is exactly the false green this module exists to
//! make unsayable. A store row is [`Mark::Proven`] only at depth 2 or better; a
//! NAME row is [`Mark::Proven`] only at depth 3.
//!
//! # Why colour is never the only carrier
//!
//! A reader may have `NO_COLOR` set, may be piping into a file, may be reading a
//! transcript, or may not distinguish red from green. So every state carries a
//! distinct **glyph** and a distinct **word**, and colour is a third, redundant
//! signal layered on top. Drop the colour and the report loses nothing but its
//! looks. That is the property [`Style::PLAIN`] exists to make testable.
//!
//! # Why the glyphs degrade
//!
//! Not every terminal renders `✔`. The marks and the action arrow fall back to
//! ASCII when the locale does not say UTF-8, and `KEYLESS_ASCII=1` forces the
//! fallback anywhere. The ASCII set is chosen so the five marks stay distinct
//! from each other -- `+ x X - ~` -- because a fallback that collapses two
//! states into one character reintroduces the ambiguity the glyphs were for.
//!
//! **The prose this crate writes is ASCII already**, so the fallback is total
//! for anything `keyless` authored. What it cannot cover is text `keyless` did
//! not write: a vendor CLI's stderr and a note somebody typed into their own
//! config are passed through exactly as they arrived, byte for byte. Rewriting
//! those would be editing evidence, and the whole value of quoting a vendor is
//! that it is the vendor's own words.

use std::io::{self, Write};

/// How far a thing was proven, and therefore what a reader should do next.
///
/// One variant per **next action**, which is why there are five rather than the
/// three a tri-state would suggest. [`Mark::NotSetUp`] and [`Mark::Broken`] both
/// mean "this store is not answering" and send the reader to opposite places:
/// one to an install or a login, the other to a store that is installed, logged
/// in, and saying no.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mark {
    /// Something came back through the whole path. The only green there is.
    Proven,
    /// Nothing was asked, so nothing is known. Not a failure.
    Unproven,
    /// The tool, the login or the coordinate is not there yet.
    ///
    /// Amber rather than red on purpose: a store you have not set up is not an
    /// error, it is a step you have not taken.
    NotSetUp,
    /// It was reached, and it said no. Red: this one is a fault.
    Broken,
    /// Switched off in the config, or suppressed by the daemon. Dim.
    Off,
}

impl Mark {
    /// The glyph, in the character set `style` says the terminal can render.
    #[must_use]
    pub const fn glyph(self, style: Style) -> &'static str {
        if style.unicode {
            match self {
                Mark::Proven => "✔",
                Mark::Unproven => "~",
                Mark::NotSetUp => "✗",
                Mark::Broken => "✘",
                Mark::Off => "–",
            }
        } else {
            match self {
                Mark::Proven => "+",
                Mark::Unproven => "~",
                Mark::NotSetUp => "x",
                Mark::Broken => "X",
                Mark::Off => "-",
            }
        }
    }

    /// The ANSI colour, or `""` when colour is off.
    const fn colour(self, style: Style) -> &'static str {
        if !style.colour {
            return "";
        }
        match self {
            Mark::Proven => GREEN,
            Mark::NotSetUp => AMBER,
            Mark::Broken => RED,
            Mark::Unproven | Mark::Off => DIM,
        }
    }

    /// Whether this mark should raise `doctor`'s exit code.
    ///
    /// [`Mark::Unproven`] and [`Mark::Off`] deliberately do not. A health command
    /// that exits non-zero for a store you chose not to enable is a health
    /// command people stop running.
    #[must_use]
    pub const fn is_problem(self) -> bool {
        matches!(self, Mark::NotSetUp | Mark::Broken)
    }
}

const GREEN: &str = "\x1b[32m";
const AMBER: &str = "\x1b[33m";
const RED: &str = "\x1b[31m";
const DIM: &str = "\x1b[2m";
const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";

/// What this terminal can render, and what it has asked not to be sent.
///
/// Two independent axes. Colour is a preference a reader states with `NO_COLOR`;
/// the character set is a capability the locale reports. They are decided
/// separately because a UTF-8 terminal piped into a file still wants the glyphs
/// and must not get the escapes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Style {
    /// Emit ANSI colour.
    pub colour: bool,
    /// Emit the Unicode marks rather than their ASCII fallbacks.
    pub unicode: bool,
}

impl Style {
    /// No colour, ASCII marks. What a pipe, a file and every test gets.
    pub const PLAIN: Style = Style {
        colour: false,
        unicode: false,
    };

    /// Read the environment and decide.
    ///
    /// `out_is_tty` is passed in rather than probed here, for the reason
    /// [`crate::cmd::ls::ls`] takes the same parameter: the caller already knows
    /// which stream it is about to write to, and a function that guesses cannot
    /// be driven down both paths by a test.
    #[must_use]
    pub fn detect(out_is_tty: bool) -> Style {
        Style::decide(out_is_tty, &|key| std::env::var(key).ok())
    }

    /// The whole decision, as a function of five variables.
    ///
    /// Separate from [`Style::detect`] so a test can drive every combination
    /// without touching the process environment — which this crate's suites run
    /// on several threads and therefore cannot safely mutate.
    #[must_use]
    pub fn decide(out_is_tty: bool, env: &dyn Fn(&str) -> Option<String>) -> Style {
        let set = |key: &str| env(key).filter(|value| !value.is_empty());

        // `NO_COLOR`'s own specification: honoured when present and not empty.
        // `TERM=dumb` is the older spelling of the same request. `CLICOLOR_FORCE`
        // is the standard override, and it is here for a working reason rather
        // than for completeness — without it there is no way to SEE the coloured
        // rendering in a captured file, and a display nobody has looked at is a
        // display nobody has designed.
        //
        // 🔴 A REFUSAL BEATS A REQUEST, and the order below is the whole of that
        // rule. Written the other way round — `forced || (tty && !refused)` — a
        // reader with `NO_COLOR` set in their profile got escape sequences the
        // moment anything in their environment also set `CLICOLOR_FORCE`, which
        // is the one outcome `NO_COLOR` exists to make impossible. Measured on
        // the first capture of this display: 17 escape sequences with both set.
        let forced = set("CLICOLOR_FORCE").is_some();
        let refused = set("NO_COLOR").is_some() || env("TERM").as_deref() == Some("dumb");
        let colour = !refused && (forced || out_is_tty);

        let unicode = if set("KEYLESS_ASCII").is_some() {
            false
        } else {
            // The first locale variable that is set decides, in the order the
            // POSIX locale rules use. All three unset is the C locale, which is
            // not UTF-8 — so the conservative answer is ASCII, not a guess.
            ["LC_ALL", "LC_CTYPE", "LANG"]
                .iter()
                .find_map(|key| set(key))
                .is_some_and(|value| {
                    let value = value.to_ascii_lowercase();
                    value.contains("utf-8") || value.contains("utf8")
                })
        };

        Style { colour, unicode }
    }
}

/// The width the state column is padded to.
///
/// Fixed rather than computed, so the same report read twice — once with two
/// stores and once with five — has its detail column in the same place. The
/// number is the longest word in [`the vocabulary`](self#the-state-words).
const STATE_WIDTH: usize = 9;

/// One row: a mark, what it is about, the state in one word, and the detail.
///
/// # The state words
///
/// One word for one meaning, and the list is deliberately short and closed:
///
/// | word | mark | what a reader does next |
/// |---|---|---|
/// | `proven` | [`Mark::Proven`] | nothing |
/// | `unproven` | [`Mark::Unproven`] | ask for it, if the answer matters |
/// | `absent` | [`Mark::NotSetUp`] | install it, log in, or create the item |
/// | `config` | [`Mark::NotSetUp`] | edit one line of the config file |
/// | `ambiguous` | [`Mark::NotSetUp`] | pin a store on the name, or set a default |
/// | `broken` | [`Mark::Broken`] | it is installed and saying no; read the detail |
/// | `stale` | [`Mark::Broken`] | rebuild: this binary is older than the source beside it |
/// | `behind` | [`Mark::Broken`] | pull: that source is older than the branch it tracks |
/// | `off` | [`Mark::Off`] | enable it, if you wanted it |
/// | `blocked` | [`Mark::Unproven`] | fix the store above; this row is a symptom |
///
/// An eleventh word should replace one of these rather than join them.
///
/// The table is the vocabulary, and `tests/state_vocabulary.rs` holds it to
/// that: it derives the same set from every `state` literal the crate renders
/// and reds when the two disagree, in either direction.
pub fn row(
    out: &mut dyn Write,
    style: Style,
    mark: Mark,
    subject: &str,
    subject_width: usize,
    state: &str,
    detail: &str,
) -> io::Result<()> {
    let (on, off) = (mark.colour(style), if style.colour { RESET } else { "" });
    let dim = if style.colour { DIM } else { "" };
    // `2 + 1 + 1 + width + 2 + STATE + 2`, counting the glyph as one column —
    // which is what a terminal gives it, and what `str::len` does not.
    let indent = 8 + subject_width + STATE_WIDTH;
    let mut lines = wrap(detail, LINE_BUDGET.saturating_sub(indent)).into_iter();
    let first = lines.next().unwrap_or_default();
    writeln!(
        out,
        // The state word takes the mark's own colour rather than a flat dim, so
        // a green row reads as green from two feet away — which is the whole
        // request. The wrapped continuation below stays dim: it is the same
        // fact, said at length.
        "  {on}{}{off} {subject:<subject_width$}  {on}{state:<STATE_WIDTH$}{off}  {first}",
        mark.glyph(style)
    )?;
    // A store's own error is a paragraph often enough that this is not a
    // nicety: `stores.proton.session_dir`'s remedy runs to four lines, and
    // unwrapped it reflows against whatever width the reader happens to have,
    // which puts the next row's mark in the middle of the previous row's prose.
    for rest in lines {
        writeln!(out, "{:indent$}{dim}{rest}{off}", "")?;
    }
    Ok(())
}

/// The column budget one rendered line aims to fit in.
///
/// Fixed rather than read from the terminal, and that is a decision rather than
/// an omission: querying the width means an `ioctl` whose answer is absent in a
/// pipe, wrong under `script`, and stale the moment the window is dragged. A
/// report that is stable across all three beats one that is optimal in one.
const LINE_BUDGET: usize = 92;

/// Break `text` into lines of at most `width` columns, on word boundaries.
///
/// A word longer than `width` is left whole and allowed to overflow. That is
/// deliberate: the long words here are paths, URLs and config keys, and a
/// reader who cannot copy one because it was hyphenated is worse off than a
/// reader whose line ran long.
fn wrap(text: &str, width: usize) -> Vec<String> {
    if text.is_empty() {
        return vec![String::new()];
    }
    let width = width.max(24);
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && line.chars().count() + 1 + word.chars().count() > width {
            lines.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

/// The line under a failing row that says what to do about it.
///
/// Indented under the subject and introduced by an arrow, so a reader scanning
/// only the marks can skip it and a reader who stopped at a mark has it in
/// reach. Every failing row is required to have one; a diagnosis with no next
/// action is the shape this report used to have.
pub fn action(out: &mut dyn Write, style: Style, text: &str) -> io::Result<()> {
    let (on, off) = if style.colour {
        (BOLD, RESET)
    } else {
        ("", "")
    };
    let arrow = if style.unicode { "\u{2192}" } else { "->" };
    let mut lines = wrap(text, LINE_BUDGET - 8).into_iter();
    writeln!(
        out,
        "      {on}{arrow}{off} {}",
        lines.next().unwrap_or_default()
    )?;
    for rest in lines {
        writeln!(out, "        {rest}")?;
    }
    Ok(())
}

/// A section heading.
pub fn heading(out: &mut dyn Write, style: Style, text: &str) -> io::Result<()> {
    let (on, off) = if style.colour {
        (BOLD, RESET)
    } else {
        ("", "")
    };
    writeln!(out, "\n{on}{text}{off}")
}

/// A dim continuation line, for prose that belongs to the row above it.
///
/// Wrapped like everything else — except that a line which is already a
/// rendered artefact, such as a line of the JSON `init` just wrote, must reach
/// the reader byte-for-byte. Those go through [`verbatim`].
pub fn note(out: &mut dyn Write, style: Style, text: &str) -> io::Result<()> {
    let (on, off) = if style.colour { (DIM, RESET) } else { ("", "") };
    for line in wrap(text, LINE_BUDGET - 6) {
        writeln!(out, "      {on}{line}{off}")?;
    }
    Ok(())
}

/// A line printed exactly as given: indentation preserved, nothing wrapped.
///
/// For content whose own layout is the information — a JSON body, a fragment of
/// config. Wrapping it would collapse the indentation that makes it readable and
/// make it uncopyable, which is the opposite of why it is being shown.
pub fn verbatim(out: &mut dyn Write, style: Style, text: &str) -> io::Result<()> {
    let (on, off) = if style.colour { (DIM, RESET) } else { ("", "") };
    writeln!(out, "      {on}{text}{off}")
}

/// A command a reader can copy, and one line saying what it does.
///
/// The two are separate arguments rather than one pre-aligned string because
/// wrapping collapses runs of spaces: an aligned column built by hand survives
/// exactly until the first line that needs to wrap, and then silently stops
/// being a column.
pub fn command(out: &mut dyn Write, style: Style, cmd: &str, gloss: &str) -> io::Result<()> {
    let (on, off) = if style.colour {
        (BOLD, RESET)
    } else {
        ("", "")
    };
    let dim = if style.colour { DIM } else { "" };
    let pad = COMMAND_WIDTH.saturating_sub(cmd.chars().count());
    let indent = 6 + COMMAND_WIDTH + 2;
    let mut lines = wrap(gloss, LINE_BUDGET.saturating_sub(indent)).into_iter();
    writeln!(
        out,
        "      {on}{cmd}{off}{:pad$}  {dim}{}{off}",
        "",
        lines.next().unwrap_or_default()
    )?;
    for rest in lines {
        writeln!(out, "{:indent$}{dim}{rest}{off}", "")?;
    }
    Ok(())
}

/// How wide the copyable-command column is.
const COMMAND_WIDTH: usize = 30;

#[cfg(test)]
mod tests {
    use super::{Mark, Style, row};
    use std::collections::BTreeMap;

    /// An environment built from pairs, so no test touches the process's own.
    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
        let map: BTreeMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |key: &str| map.get(key).cloned()
    }

    #[test]
    fn a_pipe_gets_no_colour_however_pretty_the_terminal_is() {
        // The rule the whole module rests on: decoration is for a terminal, and
        // a redirected run gets clean text. Without this assertion every other
        // one here passes on an implementation that colours unconditionally.
        let style = Style::decide(false, &env(&[("TERM", "xterm-256color")]));
        assert!(!style.colour);
        let mut out: Vec<u8> = Vec::new();
        row(&mut out, style, Mark::Proven, "infisical", 9, "proven", "x").expect("write");
        let text = String::from_utf8(out).expect("utf-8");
        assert!(
            !text.contains('\x1b'),
            "a pipe was sent an escape: {text:?}"
        );
    }

    #[test]
    fn no_color_is_honoured_on_a_terminal() {
        assert!(!Style::decide(true, &env(&[("NO_COLOR", "1")])).colour);
        assert!(!Style::decide(true, &env(&[("TERM", "dumb")])).colour);
        // The control: the same terminal with neither set does colour, so the
        // two assertions above are about NO_COLOR rather than about a function
        // that never colours anything.
        assert!(Style::decide(true, &env(&[("TERM", "xterm")])).colour);
    }

    #[test]
    fn a_refusal_beats_a_request() {
        // `NO_COLOR` is the reader saying no. `CLICOLOR_FORCE` is a caller
        // asking. When both are present the reader wins, or `NO_COLOR` is a
        // preference rather than a guarantee — and a guarantee is the only
        // thing it is worth being.
        assert!(!Style::decide(true, &env(&[("NO_COLOR", "1"), ("CLICOLOR_FORCE", "1")])).colour);
        assert!(!Style::decide(false, &env(&[("TERM", "dumb"), ("CLICOLOR_FORCE", "1")])).colour);
        // The control: the request works on its own, which is what makes the
        // coloured rendering observable in a captured file at all.
        assert!(Style::decide(false, &env(&[("CLICOLOR_FORCE", "1")])).colour);
    }

    #[test]
    fn an_empty_no_color_is_not_a_request() {
        // Its own specification: present AND non-empty. `NO_COLOR=` is what a
        // shell leaves behind after unsetting a variable badly, and treating it
        // as a request would silently strip colour from a terminal that asked
        // for none of this.
        assert!(Style::decide(true, &env(&[("NO_COLOR", ""), ("TERM", "xterm")])).colour);
    }

    #[test]
    fn the_marks_degrade_to_ascii_when_the_locale_is_not_utf8() {
        let ascii = Style::decide(true, &env(&[("LANG", "C")]));
        assert!(!ascii.unicode);
        // Unset everywhere is the C locale too, so the conservative answer is
        // ASCII rather than a guess that renders as a box on somebody's screen.
        assert!(!Style::decide(true, &env(&[])).unicode);
        assert!(Style::decide(true, &env(&[("LANG", "en_US.UTF-8")])).unicode);
        // `LC_ALL` outranks `LANG`, as the locale rules say it does.
        assert!(!Style::decide(true, &env(&[("LC_ALL", "C"), ("LANG", "en_US.UTF-8")])).unicode);
        // And the escape hatch works on a terminal that reports UTF-8 and
        // renders it badly anyway.
        assert!(
            !Style::decide(
                true,
                &env(&[("LANG", "en_US.UTF-8"), ("KEYLESS_ASCII", "1")])
            )
            .unicode
        );
    }

    #[test]
    fn every_state_has_its_own_glyph_in_both_character_sets() {
        // Colour must never be the only thing separating two states: a reader
        // with NO_COLOR set, or one reading a transcript, gets the glyph and the
        // word and nothing else. A fallback that collapsed two marks into one
        // character would put the distinction back on colour alone.
        for style in [
            Style::PLAIN,
            Style {
                colour: false,
                unicode: true,
            },
        ] {
            let marks = [
                Mark::Proven,
                Mark::Unproven,
                Mark::NotSetUp,
                Mark::Broken,
                Mark::Off,
            ];
            let glyphs: std::collections::BTreeSet<&str> =
                marks.iter().map(|mark| mark.glyph(style)).collect();
            assert_eq!(
                glyphs.len(),
                marks.len(),
                "two states share a glyph at {style:?}: {glyphs:?}"
            );
        }
    }

    #[test]
    fn a_store_you_never_enabled_is_not_a_problem() {
        // Amber is a step nobody has taken yet; red is a fault. Only a fault
        // raises an exit code, or `doctor` exits 1 on a perfectly good machine
        // and people stop reading it.
        assert!(!Mark::Off.is_problem());
        assert!(!Mark::Unproven.is_problem());
        assert!(Mark::NotSetUp.is_problem());
        assert!(Mark::Broken.is_problem());
        assert!(!Mark::Proven.is_problem());
    }
}
