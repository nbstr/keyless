mod cache;
mod infisical;
mod onepassword;
mod policy;
mod proton;
mod renewal;
mod routing;

use super::DaemonConfig;

fn parse(json: &str) -> DaemonConfig {
    serde_json::from_str(json).expect("valid daemon config")
}
