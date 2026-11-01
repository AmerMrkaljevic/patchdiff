# extract_functions.py -- Ghidra headless post-script (Jython).
#
# Walks every defined, non-thunk, non-external function in the currently
# loaded program, decompiles it, and writes one JSON object per line to the
# output path given as the first script argument: name, entry address, a
# structural fingerprint (instruction count, distinct call count -- used to
# match functions across builds when names are unavailable), and the
# decompiled pseudo-C text.
#
# Run via: analyzeHeadless <project_dir> <project_name> -import <binary> \
#              -postScript extract_functions.py <output.jsonl>

import json
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

args = getScriptArgs()
if len(args) < 1:
    print("usage: -postScript extract_functions.py <output.jsonl>")
    exit(1)
out_path = args[0]

monitor = ConsoleTaskMonitor()
ifc = DecompInterface()
ifc.openProgram(currentProgram)

fm = currentProgram.getFunctionManager()
funcs = fm.getFunctions(True)
listing = currentProgram.getListing()

n = 0
with open(out_path, 'w') as f:
    for func in funcs:
        if func.isThunk() or func.isExternal():
            continue

        name = func.getName()
        addr = func.getEntryPoint().toString()

        body = func.getBody()
        insn_count = 0
        for _ in listing.getInstructions(body, True):
            insn_count += 1
        call_count = func.getCalledFunctions(monitor).size()

        decomp_c = ""
        try:
            res = ifc.decompileFunction(func, 30, monitor)
            if res is not None and res.decompileCompleted():
                df = res.getDecompiledFunction()
                if df is not None:
                    decomp_c = df.getC()
        except Exception:
            decomp_c = ""

        rec = {
            "name": name,
            "address": addr,
            "insn_count": insn_count,
            "call_count": call_count,
            "decompiled": decomp_c,
        }
        f.write(json.dumps(rec) + "\n")
        n += 1

ifc.dispose()
print("extract_functions.py: wrote %d function(s) to %s" % (n, out_path))
