//! What a derived index refuses to carry, and where it refuses to go.

use super::fixtures::{advice, field, indexed, item, key_of};
use keyless::store::catalogue::ProtonMint;
use keyless::store::discover::{FieldKind, FieldSummary};
use std::collections::BTreeMap;

#[test]
fn nothing_a_field_summary_carries_but_its_name_reaches_a_route() {
    // C3, at the seam a value could only ever arrive through. `Discover` is
    // shaped so a value cannot be returned at all; what it CAN return besides a
    // field's name is its value type and its structural path, and this asserts
    // the catalogue keeps neither. Each marker is a distinct recognisable
    // string, and each marker's LENGTH is asserted absent too — a length plus a
    // password policy is a materially smaller search space, which is why
    // `src/store/discover.rs` treats one as a value.
    let markers = [
        "MARKERVALUETYPEAAAA",
        "MARKERPATHBBBBBBBBBBBBBBB",
        "MARKERKINDCCCCCCCCCCCCCCCCCCCCC",
    ];
    let leaky = FieldSummary {
        name: "API Token".to_owned(),
        kind: FieldKind::Custom,
        value_type: Some(markers[0].to_owned()),
        path: markers[1].to_owned(),
    };
    let summary = item("decoy-agent");
    let catalogue = indexed(&BTreeMap::new(), std::slice::from_ref(&summary));
    let key = key_of(&summary);
    catalogue.install_view(
        &key,
        &ProtonMint,
        &summary,
        &[leaky.clone(), field("password")],
    );

    let rendered = format!(
        "{:?}|{}|{}|{}|{:?}",
        catalogue.route("DECOY_AGENT__API_TOKEN"),
        catalogue.names().join(","),
        advice(&catalogue, "DECOY_AGENT__NOPE"),
        catalogue.item_names(&key).join(","),
        catalogue.route("DECOY_AGENT"),
    );

    for marker in markers {
        assert!(
            !rendered.contains(marker),
            "{marker} reached a route: {rendered}"
        );
        let length = marker.len().to_string();
        assert!(
            !rendered.contains(&length),
            "the length {length} of {marker} reached a route: {rendered}"
        );
    }
    // The negative control: without this the assertions above would pass on a
    // catalogue that had recorded nothing whatever.
    assert!(
        catalogue
            .names()
            .contains(&"DECOY_AGENT__API_TOKEN".to_owned()),
        "{:?}",
        catalogue.names()
    );
}

#[test]
fn the_derived_index_has_no_way_to_reach_a_disk() {
    // C7, asserted the way this suite asserts every other structural promise:
    // by reading the source. A `Serialize` derive is the one edit that would
    // make the index writable by accident, and it would read as harmless.
    let sources = [
        include_str!("../../src/store/catalogue.rs"),
        include_str!("../../src/store/catalogue/index.rs"),
        include_str!("../../src/store/catalogue/install.rs"),
        include_str!("../../src/store/catalogue/lookup.rs"),
        include_str!("../../src/store/catalogue/mintings.rs"),
        include_str!("../../src/store/catalogue/naming.rs"),
        include_str!("../../src/store/catalogue/rebuild.rs"),
    ];
    let code: String = sources
        .iter()
        .flat_map(|source| source.lines())
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in [
        "Serialize",
        "to_vec",
        "write_all",
        "File::create",
        "fs::write",
    ] {
        assert!(
            !code.contains(forbidden),
            "`{forbidden}` in the catalogue: the derived index lives in the daemon's heap and \
             dies with the daemon, and a durable copy is a `get` verb with extra steps"
        );
    }
}
