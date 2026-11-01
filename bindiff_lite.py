#!/usr/bin/env python3
"""bindiff_lite — rank which functions changed between two versions of the
same binary, by how likely the change looks like a security fix.

Takes the JSONL function extracts produced by extract_functions.py (run via
Ghidra headless) for an "old" and a "new" build of the same program, matches
functions between them, and flags + ranks the ones whose decompiled pseudo-C
changed in a way that looks security-relevant: a bounds-check constant
changed, a buffer-copy call's arguments changed, a new conditional appeared.

This is the "what did the patch actually touch" step of n-day hunting: point
it at the vulnerable and patched build of something a vendor just shipped a
security fix for, and it tells you which function(s) to go read first,
instead of diffing a multi-megabyte binary by hand.

NOTE ON THE REGEXES BELOW: a decompiler does not preserve source code's
comparison direction or literal base. Ghidra turned `if (mss < 32) return 0;
return 1;` into `return (0x1f < mss);` -- operands flipped, hex instead of
decimal. A pattern written the way boundgap.py's (source-level) patterns are
written -- `<\\s*\\d+`, expecting the literal after the operator in decimal --
would silently miss this exact case. Caught by testing against Ghidra's real
output on a known before/after pair before shipping, not by reading
Ghidra's decompiler docs. BOUND_LITERAL below matches a comparison literal
on either side, decimal or hex.
"""
import json, re, sys, argparse, difflib

BOUND_LITERAL = re.compile(
    r'(?:[<>]=?\s*(?:0x[0-9a-fA-F]+|\d+))|(?:(?:0x[0-9a-fA-F]+|\d+)\s*[<>]=?)'
)
SECURITY_PATTERNS = [
    (re.compile(r'\b(memcpy|strcpy|strcat|sprintf|memmove|alloca|strncpy|snprintf)\s*\('), 'buffer-op'),
    (re.compile(r'\b(malloc|calloc|realloc)\s*\('), 'allocation'),
    (BOUND_LITERAL, 'bound-literal'),
    (re.compile(r'\bif\s*\('), 'conditional'),
]

def load(path):
    out = {}
    for line in open(path):
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        out[rec['name']] = rec
    return out

def structural_key(rec):
    # coarse fingerprint for matching stripped/renamed functions across
    # builds: bucket by instruction count (quantized, since minor codegen
    # churn shifts it by a few) plus exact call count.
    return (rec.get('insn_count', 0) // 5, rec.get('call_count', 0))

def match(old, new):
    """Returns [(old_name, new_name, old_rec, new_rec), ...]."""
    pairs = []
    matched_old, matched_new = set(), set()

    # pass 1: exact name match -- the common case, since an old and new
    # build of the SAME program from the SAME vendor usually keeps symbol
    # names even when stripped-for-release binaries don't (debug builds,
    # or a vendor that ships .debug files, are the realistic target here).
    for name, orec in old.items():
        if name in new:
            pairs.append((name, name, orec, new[name]))
            matched_old.add(name)
            matched_new.add(name)

    # pass 2: fuzzy-match the rest by structural fingerprint, only when a
    # bucket has exactly one candidate on each side -- deliberately
    # conservative. A wrong fuzzy match in a lead generator just wastes a
    # human's five minutes; it is not a correctness bug in a shipped
    # finding, but ambiguous buckets are skipped rather than guessed.
    unmatched_old = {n: r for n, r in old.items() if n not in matched_old}
    unmatched_new = {n: r for n, r in new.items() if n not in matched_new}
    buckets = {}
    for n, r in unmatched_new.items():
        buckets.setdefault(structural_key(r), []).append(n)
    for n, r in unmatched_old.items():
        cands = buckets.get(structural_key(r), [])
        if len(cands) == 1:
            nn = cands[0]
            pairs.append((n, nn, r, unmatched_new[nn]))
            matched_new.add(nn)

    return pairs

def diff_score(old_c, new_c):
    """Returns (score, tags) for the changed lines between two decompiled
    functions. Only lines that actually differ are scanned -- an unchanged
    memcpy() elsewhere in a long function shouldn't inflate the score of an
    unrelated one-line change."""
    if old_c == new_c:
        return 0, []
    sm = difflib.SequenceMatcher(None, old_c.splitlines(), new_c.splitlines())
    changed = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag != 'equal':
            changed.extend(sm.a[i1:i2])
            changed.extend(sm.b[j1:j2])
    score, tags = 0, set()
    for line in changed:
        for rx, tag in SECURITY_PATTERNS:
            if rx.search(line):
                score += 1
                tags.add(tag)
    return score, sorted(tags)

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('old_jsonl', help='extract_functions.py output for the OLD/vulnerable build')
    ap.add_argument('new_jsonl', help='extract_functions.py output for the NEW/patched build')
    ap.add_argument('--top', type=int, default=20, help='show at most N changed functions')
    ap.add_argument('--json', action='store_true', help='emit JSON instead of text (for CI/tooling)')
    a = ap.parse_args()

    old, new = load(a.old_jsonl), load(a.new_jsonl)
    pairs = match(old, new)

    results = []
    for on, nn, orec, nrec in pairs:
        if orec['decompiled'] == nrec['decompiled']:
            continue
        score, tags = diff_score(orec['decompiled'], nrec['decompiled'])
        results.append({
            'old_name': on, 'new_name': nn, 'renamed': on != nn,
            'security_score': score, 'tags': tags,
            'old_insn': orec['insn_count'], 'new_insn': nrec['insn_count'],
        })
    results.sort(key=lambda r: -r['security_score'])

    only_old = sorted(set(old) - {p[0] for p in pairs})
    only_new = sorted(set(new) - {p[1] for p in pairs})

    if a.json:
        print(json.dumps({'matched': len(pairs), 'changed_functions': results[:a.top],
                           'removed_in_new': only_old, 'added_in_new': only_new}, indent=2))
        return

    print(f"{len(pairs)} function(s) matched between builds, {len(results)} changed\n")
    for r in results[:a.top]:
        label = r['new_name'] if not r['renamed'] else f"{r['old_name']} -> {r['new_name']}"
        tagstr = ', '.join(r['tags']) or 'no security pattern matched'
        print(f"  [score {r['security_score']:2d}] {label}  ({tagstr})")
        print(f"            insns: {r['old_insn']} -> {r['new_insn']}")
    if only_old:
        print(f"\n{len(only_old)} function(s) removed in new build: {', '.join(only_old[:10])}")
    if only_new:
        print(f"{len(only_new)} function(s) added in new build: {', '.join(only_new[:10])}")

if __name__ == '__main__':
    main()
