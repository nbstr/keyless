use std::path::Path;
use std::path::PathBuf;

use super::backend::Backend;
use super::write_stub;

/// Write a stand-in for the `infisical` binary.
///
/// It records its own argv, one element per line, at `<dir>/infisical.argv`, so
/// a test can assert on the invocation the adapter built rather than on a copy
/// of the adapter's own list of flags.
pub fn stub_infisical(dir: &Path, behaviour: &Backend) -> PathBuf {
    let argv_log = dir.join("infisical.argv");
    let body = format!(
        "#!/bin/sh\n\
         printf '%s\\n' \"$@\" > '{argv}'\n\
         # Everything after `--` is the child command the adapter chose.\n\
         while [ \"$1\" != \"--\" ] && [ $# -gt 0 ]; do shift; done\n\
         shift\n\
         child=\"$1\"\n\
         key=\"$2\"\n\
         {body}",
        argv = argv_log.display(),
        body = behaviour.body(dir)
    );
    write_stub(dir, "infisical-stub", &body)
}
