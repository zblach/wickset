## Benchmark submission

Adds rows to `benchmarks/scores.csv` from `wickset bench --csv`
([benchmarks/README.md](../benchmarks/README.md)).

**Machine**
- CPU:
- GPU (if any):
- OS:
- Power (mains or battery; laptops throttle on battery):

**How I ran it**
- [ ] A release binary (which: ) or a build from a tagged commit, not a dirty tree
- [ ] All four algorithms with `--cpu`:
      `for a in 1 2 3 4; do wickset --cpu bench --csv --alg $a; done | awk 'NR==1 || !/^date,/'`
- [ ] With a GPU wickset can use (Metal on macOS), all four without `--cpu` as well
- [ ] Nothing else heavy running at the time
- [ ] Rows appended to the end of `scores.csv` as printed: no header, no edits

**Notes** (anything unusual: a VM, thermal limits, a custom build):
