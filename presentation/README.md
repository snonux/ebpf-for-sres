# Presentation: eBPF for SREs

45 slides, about 46 minutes including three live demos, built for a 50-minute
slot with SREs and principal engineers. ior appears only at the end, as the
closing demo with an LLM.

* `slides/*.html`: one file per slide, 1920×1080, in the format of the Claude Slides artifact.
* `deck.json`: slide order, sections and fonts.
* `speaker-notes.md`: timing table and speaker notes in deck order. Generated:
  edit the `<aside>` in a slide (or the time budget in `build-notes.py`) and
  run `./build-notes.py`.
* `demo-plan.md`: what to prepare and what to type in each demo.
* `backup-slides/`: slides that were cut for time (the ior case study, the
  earlier libbpf-in-C and safety slides). Add one back by listing its id in
  `deck.json`.
