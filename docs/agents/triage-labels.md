# Triage Role Targets

The five canonical roles belong to the /triage skill, which owns their state machine — when each fires, what it returns to, and the two readings that get inverted. This file answers what each role is called in **this** repo, whether the tracker stores it as a label or as a workflow state, and carries the skill's own one-line gloss so a drafter choosing a role does not have to leave the page.

| Canonical role | Target here | Kind | Meaning |
| --- | --- | --- | --- |
| `needs-triage` | `needs-triage` | label | Maintainer needs to evaluate |
| `needs-info` | `needs-info` | label | Waiting on reporter for more information |
| `ready-for-agent` | `ready-for-agent` | label | Fully specified, ready for an AFK agent |
| `ready-for-human` | `ready-for-human` | label | Needs human implementation |
| `wontfix` | `wontfix` | label | Will not be actioned |

Every target is identity, and all five were checked against the live set rather than assumed: `wontfix` shipped with the repository, and the other four were created on 2026-09-12 because GitHub's default vocabulary carries no workflow roles at all. All are labels — GitHub has no workflow states, so an issue is open or closed and every role is additive.

## Other axes this tracker expresses

**Category** — `bug`, `enhancement`, `documentation`, `question`, plus GitHub's `duplicate` and `invalid`. The defaults, unmodified, and each states its own scope; the tracker resolves them live.

**Area** — none. This repository is one Rust crate plus its hook pack, small enough that the title says where a change lands, and an area vocabulary nobody applies is worse than none.
