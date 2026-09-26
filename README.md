# eBPF for SREs

An introduction to eBPF for site reliability engineers: what BPF is, why it is
useful on call, and how [ior](https://github.com/snonux/ior) (I/O Riot NG) uses
it to trace I/O syscalls. Includes small runnable examples for the audience.

## Contents

- `presentation/`: the 23-slide deck.
  - `slides/*.html`: one file per slide, 1920×1080, in the format of the Claude Slides artifact.
  - `deck.json`: slide order, sections and fonts.
  - `speaker-notes.md`: slide titles and speaker notes in deck order.
- `examples/`: every example from the slides as a script, plus a test runner.
  See [examples/README.md](examples/README.md).

## Running the examples (Rocky Linux 9)

    cd examples
    sudo ./setup-rocky9.sh
    sudo ./run-all.sh

`run-all.sh` runs each example for a few seconds under a small file I/O
workload and prints PASS/FAIL. `examples/results/sandbox-run.log` is a run on a
6.18 kernel with bpftrace 0.20.2. That run passed 7 of 9 examples. The kprobe
variant and the bcc tools could not run there, because that kernel has no
kprobe support and no kernel headers. They have not been verified on Rocky 9
yet.
