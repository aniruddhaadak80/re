// Scripts RevLens hands to Ghidra headless and IDA batch mode. Original code, MIT licensed.
// They are written to a private temp folder at run time; nothing is installed into the tools.

/** Ghidra script class name; the file must be called RevLensExport.java. */
export const GHIDRA_SCRIPT_NAME = 'RevLensExport.java';

/**
 * Ghidra GhidraScript (Java). Arguments:
 *   <outJson> <mode: info|functions|decompile> <limit> <offset> <timeoutSec> [selector ...]
 * Selectors are function names or 0x addresses. The JSON is escaped by hand so the script
 * has no dependency beyond the Ghidra API.
 */
export const GHIDRA_EXPORT_SCRIPT = String.raw`// RevLens headless export script. Original code, MIT licensed, part of @revlens/bridges.
// Arguments: <outJson> <mode: info|functions|decompile> <limit> <offset> <timeoutSec> [selector ...]
//@category RevLens
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Namespace;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class RevLensExport extends GhidraScript {
    private static final int MAX_SELECTORS = 64;

    private static String q(String s) {
        if (s == null) return "null";
        StringBuilder b = new StringBuilder(s.length() + 2);
        b.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20 || c == 0x2028 || c == 0x2029) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        b.append('"');
        return b.toString();
    }

    private String fn(Function f) {
        Namespace ns = f.getParentNamespace();
        StringBuilder b = new StringBuilder();
        b.append("{\"name\":").append(q(f.getName()));
        b.append(",\"namespace\":").append(q(ns == null || ns.isGlobal() ? null : ns.getName(true)));
        b.append(",\"address\":").append(q("0x" + f.getEntryPoint().toString(false)));
        b.append(",\"size\":").append(f.getBody().getNumAddresses());
        b.append(",\"signature\":").append(q(f.getPrototypeString(false, false)));
        b.append(",\"thunk\":").append(f.isThunk());
        b.append(",\"external\":").append(f.isExternal());
        b.append(",\"callingConvention\":").append(q(f.getCallingConventionName()));
        b.append(",\"parameters\":").append(f.getParameterCount());
        b.append("}");
        return b.toString();
    }

    private List<Function> select(String[] args, int from) {
        FunctionManager fm = currentProgram.getFunctionManager();
        Set<Function> out = new LinkedHashSet<>();
        for (int i = from; i < args.length && i - from < MAX_SELECTORS; i++) {
            String sel = args[i];
            if (sel.startsWith("0x") || sel.startsWith("0X")) {
                try {
                    Address a = toAddr(sel.substring(2));
                    Function f = a == null ? null : fm.getFunctionContaining(a);
                    if (f != null) out.add(f);
                } catch (Exception e) {
                    // not an address in this program
                }
                continue;
            }
            FunctionIterator it = fm.getFunctions(true);
            while (it.hasNext()) {
                Function f = it.next();
                if (f.getName().equals(sel) || f.getName(true).equals(sel)) out.add(f);
            }
        }
        return new ArrayList<>(out);
    }

    private void write(String outPath, String json) throws Exception {
        try (Writer w = new OutputStreamWriter(new FileOutputStream(outPath), StandardCharsets.UTF_8)) {
            w.write(json);
        }
    }

    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        if (a.length < 5) throw new IllegalArgumentException("RevLensExport needs 5 arguments");
        String outPath = a[0];
        String mode = a[1];
        int limit = Math.max(0, Math.min(Integer.parseInt(a[2]), 100000));
        int offset = Math.max(0, Integer.parseInt(a[3]));
        int timeout = Math.max(1, Math.min(Integer.parseInt(a[4]), 3600));
        FunctionManager fm = currentProgram.getFunctionManager();
        StringBuilder b = new StringBuilder();
        b.append("{\"schema\":\"revlens/ghidra-export@1\"");
        b.append(",\"program\":").append(q(currentProgram.getName()));
        b.append(",\"language\":").append(q(currentProgram.getLanguageID().getIdAsString()));
        b.append(",\"compiler\":").append(q(currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString()));
        b.append(",\"format\":").append(q(currentProgram.getExecutableFormat()));
        b.append(",\"imageBase\":").append(q("0x" + currentProgram.getImageBase().toString(false)));
        b.append(",\"functionCount\":").append(fm.getFunctionCount());
        b.append(",\"mode\":").append(q(mode));
        if (mode.equals("functions")) {
            b.append(",\"functions\":[");
            FunctionIterator it = fm.getFunctions(true);
            int i = 0, n = 0;
            while (it.hasNext() && n < limit) {
                Function f = it.next();
                if (i++ < offset) continue;
                if (n > 0) b.append(',');
                b.append(fn(f));
                n++;
                if (monitor.isCancelled()) break;
            }
            b.append("]");
        } else if (mode.equals("decompile")) {
            List<Function> fs = select(a, 5);
            b.append(",\"selected\":").append(fs.size());
            DecompInterface ifc = new DecompInterface();
            ifc.toggleCCode(true);
            ifc.toggleSyntaxTree(false);
            if (!ifc.openProgram(currentProgram)) {
                b.append(",\"error\":").append(q("decompiler unavailable: " + ifc.getLastMessage()));
                b.append(",\"decompiled\":[]}");
                ifc.dispose();
                write(outPath, b.toString());
                println("REVLENS_EXPORT_OK " + outPath);
                return;
            }
            b.append(",\"decompiled\":[");
            int n = 0;
            try {
                for (Function f : fs) {
                    if (n >= limit) break;
                    if (n > 0) b.append(',');
                    DecompileResults r = ifc.decompileFunction(f, timeout, monitor);
                    DecompiledFunction d = r == null ? null : r.getDecompiledFunction();
                    b.append("{\"function\":").append(fn(f));
                    b.append(",\"ok\":").append(d != null);
                    b.append(",\"c\":").append(q(d == null ? null : d.getC()));
                    b.append(",\"error\":").append(q(r == null ? "no result" : (d == null ? r.getErrorMessage() : null)));
                    b.append('}');
                    n++;
                }
            } finally {
                ifc.dispose();
            }
            b.append("]");
        }
        b.append('}');
        write(outPath, b.toString());
        println("REVLENS_EXPORT_OK " + outPath);
    }
}
`;

/** IDAPython batch script. Reads its arguments from the REVLENS_IDA_ARGS env var (JSON). */
export const IDA_EXPORT_SCRIPT = String.raw`# RevLens IDA batch export. Original code, MIT licensed, part of @revlens/bridges.
import json
import os

import idaapi
import idautils
import idc
import ida_auto
import ida_funcs
import ida_nalt


def _fn(ea):
    f = ida_funcs.get_func(ea)
    return {
        "name": ida_funcs.get_func_name(ea),
        "address": "0x%x" % ea,
        "size": (f.end_ea - f.start_ea) if f else 0,
        "thunk": bool(f and (f.flags & ida_funcs.FUNC_THUNK)),
        "library": bool(f and (f.flags & ida_funcs.FUNC_LIB)),
    }


def main():
    args = json.loads(os.environ.get("REVLENS_IDA_ARGS", "{}"))
    out_path = args["out"]
    mode = args.get("mode", "functions")
    limit = max(0, min(int(args.get("limit", 200)), 100000))
    offset = max(0, int(args.get("offset", 0)))
    selectors = [str(s) for s in args.get("selectors", [])][:64]
    ida_auto.auto_wait()
    res = {"schema": "revlens/ida-export@1", "mode": mode, "program": ida_nalt.get_root_filename()}
    eas = list(idautils.Functions())
    res["functionCount"] = len(eas)
    if mode == "functions":
        res["functions"] = [_fn(ea) for ea in eas[offset:offset + limit]]
    elif mode == "decompile":
        picked = []
        for s in selectors:
            if s.lower().startswith("0x"):
                f = ida_funcs.get_func(int(s, 16))
                if f:
                    picked.append(f.start_ea)
            else:
                ea = idc.get_name_ea_simple(s)
                if ea != idaapi.BADADDR:
                    picked.append(ea)
        out = []
        try:
            import ida_hexrays
            ok = ida_hexrays.init_hexrays_plugin()
        except Exception:
            ok = False
        for ea in picked[:limit]:
            item = {"function": _fn(ea), "ok": False}
            if not ok:
                item["error"] = "Hex-Rays decompiler not available"
            else:
                try:
                    item["c"] = str(ida_hexrays.decompile(ea))
                    item["ok"] = True
                except Exception as e:
                    item["error"] = str(e)
            out.append(item)
        res["decompiled"] = out
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(res, fh)


try:
    main()
finally:
    idc.qexit(0)
`;
