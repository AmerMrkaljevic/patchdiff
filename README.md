# patchdiff

Points at an old and a new build of the same binary — typically the
vulnerable and the patched version a vendor just shipped — and tells you
**which functions actually changed**, ranked by how likely the change looks
like a security fix. This is the first step of n-day hunting: a vendor's
security advisory tells you *that* something was fixed, patchdiff tells you
*where*, so you're reading one function instead of diffing a multi-megabyte
binary by hand.

Built on [Ghidra](https://ghidra-sre.org/) (free, does the disassembly and
decompilation) plus a thin Python diff/rank layer on top — same philosophy
as this author's other two tools,
[boundgap](https://github.com/AmerMrkaljevic/boundgap) and
[depconf](https://github.com/AmerMrkaljevic/depconf): narrow, sharp, and
built on existing tooling rather than competing with it.

```
$ GHIDRA_HOME=/path/to/ghidra ./patchdiff.sh vulnerable_build patched_build

analyzing vulnerable_build ...
analyzing patched_build ...
12 function(s) matched between builds, 1 changed

  [score  2] validate_mss  (bound-literal)
            insns: 11 -> 11
```

(That's the real, verified output of this repo's own bundled example — see
[Try it](#try-it) below.)

## How it works

1. **`extract_functions.py`** — a Ghidra headless post-script. For every
   defined function in a binary, it records the decompiled pseudo-C plus a
   structural fingerprint (instruction count, distinct call count), as one
   JSON line per function.
2. **`bindiff_lite.py`** — pure Python, no Ghidra needed for this step.
   Matches functions between an old and new extract (by name first, then by
   structural fingerprint for stripped/renamed functions), diffs the
   decompiled text of each matched pair, and scores the *changed lines*
   against a small set of security-relevant patterns: a bounds-check literal
   changed, a `memcpy`/`strcpy`/`sprintf`-family call's arguments changed, a
   new allocation or conditional appeared.
3. **`patchdiff.sh`** — runs both of the above against two binaries and
   prints the ranked result in one command.

## Usage

Requires [Ghidra](https://ghidra-sre.org/) (tested on 11.3.2) and a JDK
(17+). No pip installs, no BinDiff/IDA license needed.

```bash
export GHIDRA_HOME=/path/to/ghidra_11.3.2_PUBLIC
./patchdiff.sh old_binary new_binary                 # workdir in /tmp, auto-cleaned
./patchdiff.sh old_binary new_binary ./work           # keep the Ghidra project + extracts
./patchdiff.sh old_binary new_binary ./work --json    # for CI/tooling
./patchdiff.sh old_binary new_binary ./work --top 50  # show more than the default 20
```

Or run the two stages yourself (useful if you already have Ghidra project
automation, or want to diff an extract you made some other way):

```bash
analyzeHeadless ./proj old -import vulnerable_build -postScript extract_functions.py old.jsonl
analyzeHeadless ./proj new -import patched_build    -postScript extract_functions.py new.jsonl
python3 bindiff_lite.py old.jsonl new.jsonl
```

## Try it

The repo ships a minimal, real before/after pair so you can see it work
without needing a vendor binary first. `examples/vulnerable.c` and
`examples/patched.c` differ by exactly one line — a bounds check that
should require `mss >= 44` but only enforced `mss >= 32`:

```bash
./examples/build.sh
GHIDRA_HOME=/path/to/ghidra ./patchdiff.sh examples/vulnerable examples/patched
```

This is modeled on a real bug shape (the same libsrt-style validator/consumer
mismatch this author's other tool, [boundgap](https://github.com/AmerMrkaljevic/boundgap),
targets at the *source* level) — patchdiff finds the compiled trace of the
same bug class at the *binary* level, with no source required for the
target binary.

## A real finding, and what it taught about decompiled output

Ghidra's decompiler doesn't preserve source-level idioms. The example's
source has `if (mss < 32) return 0;` — Ghidra decompiles that to
`return (0x1f < mss);`: operands flipped, hex instead of decimal. A
pattern written the way you'd write it for real C source (`<\s*\d+`,
literal after the operator, decimal) would silently miss this exact,
central case. That was caught by running this tool against its own test
pair and reading the actual decompiled output, not by reading Ghidra's
docs — `bindiff_lite.py`'s bound-literal pattern matches a comparison
literal on either side, decimal or hex, because of it.

**Optimized builds change what "one patch" looks like.** Compiled at `-O2`,
GCC inlined `validate_mss`'s bound directly into both `process_handshake`
and `main` (constant propagation across the call), so the *same* one-line
source fix showed up as three separate flagged functions instead of one.
That's not a false positive — it's the fix's real compiled footprint, and
for n-day hunting it's useful signal (three independent confirmations of
where the bound changed, from one real source edit) — but it means the
number of flagged functions isn't the same thing as the number of source
lines a vendor changed. Expect more hits on optimized release builds than
on `-O0` debug builds of the same patch.

## Function matching

- **By name**, first — reliable whenever old and new builds keep symbols
  (common for a vendor's own successive releases, even when the final
  shipped binary is stripped, if you can get a debug build or a `.debug`
  companion file).
- **By structural fingerprint**, for the rest — instruction count (bucketed)
  plus call count, matched 1:1 only when a bucket has exactly one candidate
  on each side. Deliberately conservative: an ambiguous bucket is left
  unmatched rather than guessed, because a wrong fuzzy match in a lead
  generator wastes a human's time without any corresponding benefit.
- Fully stripped binaries with heavy structural drift between versions will
  match worse than named ones. This isn't a replacement for
  [BinDiff](https://github.com/google/bindiff) or
  [Diaphora](https://github.com/joxeankoret/diaphora)'s fuzzy-matching
  machinery on genuinely hard stripped-binary cases — it's a fast first pass
  for the common case of diffing a vendor's own successive builds.

## What it is (and isn't)

A lead generator, same as this author's other tools. A high security score
means "this is where the patch's effect is visible, go read it" — not "this
is confirmed exploitable." Every hit still needs a human to read the
decompiled diff and decide what the change actually does.

## License

MIT — see [LICENSE](LICENSE).
