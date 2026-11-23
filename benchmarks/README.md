# Benchmarks

`scores.csv` collects `wickset bench --csv` runs: how long a step takes on
one core, and how fast the same machine seals. Contributions are welcome:

    wickset bench --submit

benches every algorithm on the CPU, and on the GPU where wickset can use
one, then prints a link that proposes the rows as a new file in
`submissions/`, one per machine and day. Each pull request adds its own
file, so submissions never conflict; merging folds them into `scores.csv`.
The [benchmark template](../.github/PULL_REQUEST_TEMPLATE/benchmark.md)
(`?template=benchmark.md` on a pull request's URL) asks what a reviewer
would want to know.

| column | meaning |
|---|---|
| `date`, `version` | when, and `wickset --version`'s release |
| `source` | where it ran, if not someone's own machine: a CI runner, its image, and the run that measured it (filled in by `--csv` in GitHub Actions). Runners are small shared VMs: their rows are reference points, not measurements |
| `os`, `arch`, `cpu`, `cores` | the machine (`cpu` may be empty on Linux on Arm) |
| `gpu` | the machine's GPU, if wickset can seal on it, whether or not this row did |
| `argon2` | the Argon2id implementation: `x/crypto`, or `libsodium VERSION` |
| `alg` | the algorithm's name |
| `step_s` | one step on one core, in seconds, as the fastest known opener runs it |
| `step_timing` | how `step_s` was found, where not as this build runs a step: SHA-256 at the core's full compression rate; Argon2id scaled by libsodium's lead over x/crypto |
| `seal_on`, `at_once`, `seal_steps_per_s` | the fastest sealing measured: on the `cpu` or the `gpu`, how many steps side by side, and its rate |
| `speed_up` | the seal:open ratio, `seal_steps_per_s × step_s` |

A delay is `step_s` times the steps, so `step_s` is what an opener would
need to beat. Rows from the same machine with `x/crypto` and `libsodium`
measure libsodium's lead there: x/crypto's own step time is `step_s` times
the lead its row assumes.
