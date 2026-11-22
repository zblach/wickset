# Benchmarks

`scores.csv` collects `wickset bench --csv` runs: how long a step takes on
one core, and how fast the same machine seals. Contributions are welcome:
run each algorithm, with `--cpu` and, where you have one, on the GPU, and
send the rows.

    for a in 1 2 3 4; do wickset --cpu bench --csv --alg $a; done | awk 'NR==1 || !/^date,/'

| column | meaning |
|---|---|
| `date`, `version` | when, and `wickset --version`'s release |
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
