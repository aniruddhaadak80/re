// Write-back scripts handed to Ghidra headless and IDA batch mode. Original code, MIT licensed,
// part of @revlens/bridges. Written to a private temp folder at run time.

export const GHIDRA_APPLY_SCRIPT_NAME = 'RevLensApplyNames.java';
export const GHIDRA_NAMES_EXPORT_SCRIPT_NAME = 'RevLensExportNames.java';

/**
 * Ghidra GhidraScript. Arguments: <names.json> <report.json> <fileBaseHex>
 * Applies function names and signatures, comments, labels and C types from a RevLens names file.
 * Types go into the /RevLens data type category. Changes are saved with the project.
 */
export const GHIDRA_APPLY_SCRIPT = String.raw`// RevLens names write-back for Ghidra. Original code, MIT licensed, part of @revlens/bridges.
// Arguments: <names.json> <report.json> <fileBaseHex>
//@category RevLens
import com.google.gson.*;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.cparser.C.CParser;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;

public class RevLensApplyNames extends GhidraScript {
    private JsonArray errors = new JsonArray();
    private void err(String where, Throwable t) {
        JsonObject o = new JsonObject();
        o.addProperty("where", where);
        o.addProperty("error", t == null ? "failed" : (t.getClass().getSimpleName() + ": " + String.valueOf(t.getMessage())));
        if (errors.size() < 1000) errors.add(o);
    }
    private static BigInteger hex(String s) { return new BigInteger(s.substring(2), 16); }
    private static String str(JsonObject o, String k) { JsonElement e = o.get(k); return e == null || e.isJsonNull() ? null : e.getAsString(); }

    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        JsonObject names = JsonParser.parseString(new String(Files.readAllBytes(Paths.get(a[0])), StandardCharsets.UTF_8)).getAsJsonObject();
        BigInteger fileBase = hex(a[2]);
        BigInteger progBase = BigInteger.valueOf(currentProgram.getImageBase().getOffset());
        boolean rva = "rva".equals(str(names, "addressing"));
        BigInteger recorded = names.has("imageBase") ? hex(str(names, "imageBase")) : fileBase;
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        int fnRenamed = 0, fnCreated = 0, sigs = 0, comments = 0, labels = 0, types = 0;
        int tx = currentProgram.startTransaction("RevLens names");
        boolean ok = false;
        try {
            CategoryPath cat = new CategoryPath("/RevLens");
            if (names.has("types")) for (JsonElement te : names.getAsJsonArray("types")) {
                String c = str(te.getAsJsonObject(), "c");
                try {
                    CParser p = new CParser(dtm);
                    DataType dt = p.parse(c);
                    if (dt == null) throw new IllegalArgumentException("no type in declaration");
                    DataType copy = dt.clone(dtm);
                    copy.setCategoryPath(cat);
                    dtm.addDataType(copy, DataTypeConflictHandler.REPLACE_HANDLER);
                    types++;
                } catch (Throwable t) { err("type " + c.substring(0, Math.min(c.length(), 80)), t); }
            }
            if (names.has("functions")) for (JsonElement fe : names.getAsJsonArray("functions")) {
                JsonObject f = fe.getAsJsonObject();
                String at = str(f, "address");
                try {
                    BigInteger v = hex(at);
                    BigInteger t = rva ? v.add(progBase) : v.subtract(recorded).add(progBase);
                    Address ad = toAddr(t.longValue());
                    Function fn = getFunctionAt(ad);
                    if (fn == null) {
                        disassemble(ad);
                        fn = createFunction(ad, null);
                        if (fn == null) throw new IllegalStateException("no function and none could be created at " + ad);
                        fnCreated++;
                    }
                    String name = str(f, "name");
                    if (name != null) { fn.setName(name, SourceType.USER_DEFINED); fnRenamed++; }
                    String sig = str(f, "signature");
                    if (sig != null) {
                        CParser p = new CParser(dtm);
                        DataType dt = p.parse(sig + ";");
                        if (!(dt instanceof FunctionDefinition)) throw new IllegalArgumentException("signature did not parse as a function: " + sig);
                        FunctionDefinitionDataType def = new FunctionDefinitionDataType((FunctionDefinition) dt, dtm);
                        if (name != null) def.setName(name);
                        ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(fn.getEntryPoint(), def, SourceType.USER_DEFINED);
                        if (!cmd.applyTo(currentProgram, monitor)) throw new IllegalStateException(cmd.getStatusMsg());
                        sigs++;
                    }
                    String cm = str(f, "comment");
                    if (cm != null) { setPlateComment(fn.getEntryPoint(), cm); comments++; }
                } catch (Throwable t) { err("function " + at, t); }
            }
            if (names.has("comments")) for (JsonElement ce : names.getAsJsonArray("comments")) {
                JsonObject c = ce.getAsJsonObject();
                String at = str(c, "address");
                try {
                    BigInteger v = hex(at);
                    Address ad = toAddr((rva ? v.add(progBase) : v.subtract(recorded).add(progBase)).longValue());
                    String text = str(c, "text");
                    String kind = str(c, "kind");
                    if (kind == null) kind = "eol";
                    switch (kind) {
                        case "pre": setPreComment(ad, text); break;
                        case "plate": setPlateComment(ad, text); break;
                        case "post": setPostComment(ad, text); break;
                        case "repeatable": setRepeatableComment(ad, text); break;
                        default: setEOLComment(ad, text);
                    }
                    comments++;
                } catch (Throwable t) { err("comment " + at, t); }
            }
            if (names.has("labels")) for (JsonElement le : names.getAsJsonArray("labels")) {
                JsonObject l = le.getAsJsonObject();
                String at = str(l, "address");
                try {
                    BigInteger v = hex(at);
                    Address ad = toAddr((rva ? v.add(progBase) : v.subtract(recorded).add(progBase)).longValue());
                    createLabel(ad, str(l, "name"), true, SourceType.USER_DEFINED);
                    labels++;
                } catch (Throwable t) { err("label " + at, t); }
            }
            ok = true;
        } finally {
            currentProgram.endTransaction(tx, ok);
        }
        JsonObject r = new JsonObject();
        r.addProperty("schema", "revlens/ghidra-apply@1");
        r.addProperty("program", currentProgram.getName());
        r.addProperty("imageBase", "0x" + progBase.toString(16));
        r.addProperty("functionsRenamed", fnRenamed);
        r.addProperty("functionsCreated", fnCreated);
        r.addProperty("signatures", sigs);
        r.addProperty("comments", comments);
        r.addProperty("labels", labels);
        r.addProperty("types", types);
        r.add("errors", errors);
        try (Writer w = new OutputStreamWriter(new FileOutputStream(a[1]), StandardCharsets.UTF_8)) { w.write(r.toString()); }
    }
}
`;

/**
 * Ghidra GhidraScript. Arguments: <out.json> <all: true|false>
 * Exports user defined (or with all=true every non default) function names and signatures,
 * comments of every kind, user labels, and the /RevLens types as C.
 */
export const GHIDRA_NAMES_EXPORT_SCRIPT = String.raw`// RevLens names export for Ghidra. Original code, MIT licensed, part of @revlens/bridges.
// Arguments: <out.json> <all: true|false>
//@category RevLens
import com.google.gson.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class RevLensExportNames extends GhidraScript {
    private static final int MAX = 200000;
    private static String hx(Address a) { return "0x" + Long.toHexString(a.getOffset()); }

    /** C for structures, unions, enums and typedefs, written field by field. */
    private static String toC(DataType dt) {
        StringBuilder b = new StringBuilder();
        if (dt instanceof Composite) {
            Composite c = (Composite) dt;
            b.append(dt instanceof Union ? "union " : "struct ").append(dt.getName()).append(" {");
            for (DataTypeComponent m : c.getDefinedComponents()) {
                String field = m.getFieldName() != null ? m.getFieldName() : m.getDefaultFieldName();
                DataType ft = m.getDataType();
                if (ft instanceof Array) {
                    Array arr = (Array) ft;
                    b.append(' ').append(arr.getDataType().getDisplayName()).append(' ').append(field).append('[').append(arr.getNumElements()).append("];");
                } else b.append(' ').append(ft.getDisplayName()).append(' ').append(field).append(';');
            }
            return b.append(" };").toString();
        }
        if (dt instanceof ghidra.program.model.data.Enum) {
            ghidra.program.model.data.Enum e = (ghidra.program.model.data.Enum) dt;
            b.append("enum ").append(dt.getName()).append(" {");
            String[] ns = e.getNames();
            for (int i = 0; i < ns.length; i++) b.append(i == 0 ? " " : ", ").append(ns[i]).append(" = ").append(e.getValue(ns[i]));
            return b.append(" };").toString();
        }
        if (dt instanceof TypeDef) return "typedef " + ((TypeDef) dt).getDataType().getDisplayName() + " " + dt.getName() + ";";
        return null;
    }

    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        boolean all = a.length > 1 && "true".equals(a[1]);
        JsonObject out = new JsonObject();
        out.addProperty("schema", "revlens/names@1");
        out.addProperty("source", "ghidra");
        out.addProperty("imageBase", "0x" + Long.toHexString(currentProgram.getImageBase().getOffset()));
        out.addProperty("addressing", "va");
        JsonArray fns = new JsonArray();
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (fns.size() >= MAX) break;
            if (f.isExternal() || f.isThunk()) continue;
            SourceType src = f.getSymbol().getSource();
            boolean userName = src == SourceType.USER_DEFINED;
            boolean userSig = f.getSignatureSource() == SourceType.USER_DEFINED;
            if (!all && !userName && !userSig) continue;
            if (all && src == SourceType.DEFAULT && !userSig) continue;
            JsonObject o = new JsonObject();
            o.addProperty("address", hx(f.getEntryPoint()));
            o.addProperty("name", f.getName());
            if (userSig) o.addProperty("signature", f.getPrototypeString(false, false));
            fns.add(o);
        }
        out.add("functions", fns);
        JsonArray cms = new JsonArray();
        Listing listing = currentProgram.getListing();
        AddressIterator it = listing.getCommentAddressIterator(currentProgram.getMemory(), true);
        String[] kinds = { "eol", "pre", "plate", "post", "repeatable" };
        while (it.hasNext() && cms.size() < MAX) {
            Address ad = it.next();
            // The loader and analysis also write comments (PT_LOAD, GNU Hash Table ...) outside any
            // function; without all=true only comments inside function bodies are exported.
            Function cf = getFunctionContaining(ad);
            if (!all && (cf == null || cf.isThunk() || cf.isExternal() || !currentProgram.getMemory().getBlock(ad).isExecute())) continue;
            String[] vals = { getEOLComment(ad), getPreComment(ad), getPlateComment(ad), getPostComment(ad), getRepeatableComment(ad) };
            for (int i = 0; i < kinds.length; i++) {
                if (vals[i] == null || vals[i].isEmpty()) continue;
                JsonObject o = new JsonObject();
                o.addProperty("address", hx(ad));
                o.addProperty("text", vals[i].length() > 4096 ? vals[i].substring(0, 4096) : vals[i]);
                o.addProperty("kind", kinds[i]);
                cms.add(o);
            }
        }
        out.add("comments", cms);
        JsonArray lbs = new JsonArray();
        SymbolIterator syms = currentProgram.getSymbolTable().getAllSymbols(true);
        while (syms.hasNext() && lbs.size() < MAX) {
            Symbol s = syms.next();
            if (s.getSymbolType() != SymbolType.LABEL || s.getSource() != SourceType.USER_DEFINED || s.isExternal()) continue;
            if (!all && s.getName().startsWith("prt_")) continue; // Ghidra's own relocation table labels
            JsonObject o = new JsonObject();
            o.addProperty("address", hx(s.getAddress()));
            o.addProperty("name", s.getName());
            lbs.add(o);
        }
        out.add("labels", lbs);
        JsonArray tys = new JsonArray();
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        Category cat = dtm.getCategory(new CategoryPath("/RevLens"));
        if (cat != null) {
            for (DataType dt : cat.getDataTypes()) {
                String c = toC(dt);
                if (c == null) continue;
                JsonObject o = new JsonObject();
                o.addProperty("name", dt.getName());
                o.addProperty("c", c);
                tys.add(o);
            }
        }
        out.add("types", tys);
        try (Writer w = new OutputStreamWriter(new FileOutputStream(a[0]), StandardCharsets.UTF_8)) { w.write(out.toString()); }
    }
}
`;

/**
 * IDAPython for idat batch mode. Reads REVLENS_IDA_ARGS = {"names": path, "report": path, "fileBase": "0x..", "save": path or null}.
 * Applies names, prototypes, comments, labels and C types, then saves the database.
 */
export const IDA_APPLY_SCRIPT = String.raw`# RevLens names write-back for IDA. Original code, MIT licensed, part of @revlens/bridges.
import json, os
import idc, ida_name, ida_funcs, ida_bytes, ida_auto, ida_nalt, ida_loader, ida_pro

def main():
    args = json.loads(os.environ.get("REVLENS_IDA_ARGS", "{}"))
    with open(args["names"], "r", encoding="utf-8") as fh:
        names = json.load(fh)
    ida_auto.auto_wait()
    prog_base = ida_nalt.get_imagebase()
    rva = names.get("addressing") == "rva"
    recorded = int(names["imageBase"], 16) if names.get("imageBase") else int(args.get("fileBase", "0x0"), 16)
    def ea_of(s):
        v = int(s, 16)
        return v + prog_base if rva else v - recorded + prog_base
    rep = {"schema": "revlens/ida-apply@1", "imageBase": hex(prog_base), "functionsRenamed": 0, "functionsCreated": 0,
           "signatures": 0, "comments": 0, "labels": 0, "types": 0, "errors": []}
    def err(where, msg):
        if len(rep["errors"]) < 1000:
            rep["errors"].append({"where": where, "error": str(msg)})
    for t in names.get("types", []):
        n = idc.parse_decls(t["c"], idc.PT_SILENT)
        if n == 0:
            rep["types"] += 1
        else:
            err("type " + t["c"][:80], "%d parse errors" % n)
    for f in names.get("functions", []):
        ea = ea_of(f["address"])
        try:
            if ida_funcs.get_func(ea) is None:
                if not ida_funcs.add_func(ea):
                    err("function " + f["address"], "no function and none could be created")
                    continue
                rep["functionsCreated"] += 1
            if f.get("name"):
                if ida_name.set_name(ea, f["name"], ida_name.SN_NOWARN | ida_name.SN_FORCE):
                    rep["functionsRenamed"] += 1
                else:
                    err("function " + f["address"], "set_name failed")
            if f.get("signature"):
                decl = f["signature"]
                if idc.SetType(ea, decl + ";"):
                    rep["signatures"] += 1
                else:
                    err("function " + f["address"], "SetType failed for " + decl)
            if f.get("comment"):
                fn = ida_funcs.get_func(ea)
                if fn is not None and ida_funcs.set_func_cmt(fn, f["comment"], False):
                    rep["comments"] += 1
        except Exception as e:
            err("function " + f["address"], e)
    for c in names.get("comments", []):
        ea = ea_of(c["address"])
        kind = c.get("kind", "eol")
        try:
            if kind in ("pre", "plate"):
                for i, line in enumerate(c["text"].split("\n")[:100]):
                    idc.update_extra_cmt(ea, idc.E_PREV + i, line)
            elif kind == "post":
                for i, line in enumerate(c["text"].split("\n")[:100]):
                    idc.update_extra_cmt(ea, idc.E_NEXT + i, line)
            else:
                idc.set_cmt(ea, c["text"], 1 if kind == "repeatable" else 0)
            rep["comments"] += 1
        except Exception as e:
            err("comment " + c["address"], e)
    for l in names.get("labels", []):
        ea = ea_of(l["address"])
        if ida_name.set_name(ea, l["name"], ida_name.SN_NOWARN | ida_name.SN_FORCE):
            rep["labels"] += 1
        else:
            err("label " + l["address"], "set_name failed")
    if args.get("save"):
        ida_loader.save_database(args["save"], 0)
    with open(args["report"], "w", encoding="utf-8") as fh:
        json.dump(rep, fh)

try:
    main()
finally:
    ida_pro.qexit(0)
`;

/**
 * IDAPython export. REVLENS_IDA_ARGS = {"out": path, "all": bool}.
 * Exports user named functions (or every non dummy name with all), prototypes the user set,
 * comments in functions, user labels and local types.
 */
export const IDA_NAMES_EXPORT_SCRIPT = String.raw`# RevLens names export for IDA. Original code, MIT licensed, part of @revlens/bridges.
import json, os
import idc, idautils, ida_name, ida_funcs, ida_bytes, ida_auto, ida_nalt, ida_pro

def main():
    args = json.loads(os.environ.get("REVLENS_IDA_ARGS", "{}"))
    ida_auto.auto_wait()
    allnames = bool(args.get("all"))
    out = {"schema": "revlens/names@1", "source": "ida", "imageBase": hex(ida_nalt.get_imagebase()), "addressing": "va",
           "functions": [], "comments": [], "labels": [], "types": []}
    seen_fn = set()
    for ea in idautils.Functions():
        if len(out["functions"]) >= 200000:
            break
        flags = ida_bytes.get_flags(ea)
        user = ida_bytes.has_user_name(flags)
        if not user and not allnames:
            continue
        name = ida_name.get_name(ea)
        if not allnames or user or not name.startswith(("sub_", "nullsub_", "j_")):
            entry = {"address": hex(ea), "name": name}
            tinfo = idc.get_type(ea)
            if user and tinfo:
                entry["signature"] = tinfo
            fc = ida_funcs.get_func_cmt(ida_funcs.get_func(ea), False)
            if fc:
                entry["comment"] = fc[:4096]
            out["functions"].append(entry)
            seen_fn.add(ea)
        f = ida_funcs.get_func(ea)
        for head in idautils.Heads(f.start_ea, f.end_ea):
            if len(out["comments"]) >= 200000:
                break
            for rep, kind in ((0, "eol"), (1, "repeatable")):
                c = idc.get_cmt(head, rep)
                if c:
                    out["comments"].append({"address": hex(head), "text": c[:4096], "kind": kind})
    for ea, name in idautils.Names():
        if len(out["labels"]) >= 200000:
            break
        if ea in seen_fn or ida_funcs.get_func(ea) is not None and ida_funcs.get_func(ea).start_ea == ea:
            continue
        if ida_bytes.has_user_name(ida_bytes.get_flags(ea)):
            out["labels"].append({"address": hex(ea), "name": name})
    try:
        qty = idc.get_ordinal_qty()
        if qty and qty > 0:
            text = idc.print_decls(",".join(str(i) for i in range(1, min(qty, 5000) + 1)), 0) or ""
            for block in [b.strip() for b in text.split("\n\n") if b.strip() and not b.strip().startswith("/*")][:5000]:
                out["types"].append({"c": block[:65536]})
    except Exception:
        pass
    with open(args["out"], "w", encoding="utf-8") as fh:
        json.dump(out, fh)

try:
    main()
finally:
    ida_pro.qexit(0)
`;
