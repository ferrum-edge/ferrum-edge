# Published reqwest 0.13.4 patch baseline

Ferrum vendors the published
[`reqwest-0.13.4.crate`](https://static.crates.io/crates/reqwest/reqwest-0.13.4.crate),
SHA-256 `219c5811de6525e5416c7d5d53bb656d3afdbc6c5af816e0802bcfa42dbdc1c3`,
VCS revision `11489b34eda6d32b15ad4033e62beba2ee401350`.

Apply [`reqwest-ferrum.patch`](reqwest-ferrum.patch) once from the extracted
crate root to reconstruct all retained local changes. It is a complete diff
from the published archive and includes patches 001–004 and later local
corrections. It changes `Cargo.toml` and six source files; every other shipped
source/license/README file is copied from the archive unchanged. The historical
[`reqwest-3017.patch`](001-per-request-connect-timeout/reqwest-3017.patch) is
upstream filing evidence, not the complete reconstruction patch.

The required per-PR `dependency-audit` job in
`.github/workflows/ci.yml` checks the archive checksum, applies the complete
delta, and compares all shipped source, manifest, licenses and README before
Cargo runs. The same job checks the fixed security floors across every committed
lockfile. The ordinary vendor-integrity gate independently checks the committed
drift manifest. See [dependency policy](../dependency-policy.md#security-floor-pins).

All patch retirement plans and behavioral regression requirements remain in
their individual directories. No patch is retired by this upstream refresh.
