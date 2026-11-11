# Dump real Lua bytecode with the Lua runtimes bundled in lupa (MIT): string.dump of the compiled chunk.
# Dev only. Usage: python gen-lua-fixtures.py <sample.lua> <outdir>
import sys, os, json, importlib
src, outdir = sys.argv[1], sys.argv[2]
code = open(src).read()
ref = {}
for mod, tag in [('lua51', '5.1'), ('lua52', '5.2'), ('lua53', '5.3'), ('lua54', '5.4'), ('luajit21', 'luajit2.1')]:
    L = importlib.import_module('lupa.' + mod).LuaRuntime(encoding=None)
    f = L.eval('function(src, strip) local fn = assert((loadstring or load)(src, "=sample.lua")); return string.dump(fn, strip) end')
    for strip in ((False, True) if tag not in ('5.1', '5.2') else (False,)):
        b = f(code.encode(), strip)
        name = f'sample.{tag}{".stripped" if strip else ""}.luac'
        open(os.path.join(outdir, name), 'wb').write(b)
        ref[name] = {'size': len(b), 'version': L.eval('_VERSION').decode(), 'jit': (L.eval('jit and jit.version or ""') or b'').decode()}
json.dump(ref, open(os.path.join(outdir, 'lua.ref.json'), 'w'), indent=1)
print(ref)

# LuaJIT reference via the built in jit.util module: per prototype info and raw instruction words.
import lupa.luajit21 as lj
L = lj.LuaRuntime(encoding=None)
dumpref = L.eval(r'''function(src)
  local util = require("jit.util")
  local fn = assert(loadstring(src, "=sample.lua"))
  local out = {}
  local function walk(f, path)
    local info = util.funcinfo(f)
    local ins = {}
    for pc = 1, info.bytecodes - 1 do local i = util.funcbc(f, pc); ins[#ins + 1] = string.format("%08x", i % 4294967296) end
    out[#out + 1] = string.format("%s|%d|%d|%d|%d|%d|%s", path, info.params, info.bytecodes, info.gcconsts, info.nconsts, info.upvalues, table.concat(ins, ","))
    for k = 1, info.gcconsts do
      local c = util.funck(f, -k)
      if type(c) == "proto" then walk(c, path .. "/" .. k) end
    end
  end
  walk(fn, "main")
  return table.concat(out, "\n")
end''')
txt = dumpref(code.encode()).decode()
protos = []
for line in txt.split('\n'):
    path, params, nbc, ngc, nk, nuv, ins = line.split('|')
    protos.append({'path': path, 'params': int(params), 'bytecodes': int(nbc), 'gcconsts': int(ngc), 'nconsts': int(nk), 'upvalues': int(nuv), 'ins': ins.split(',') if ins else []})
json.dump({'luajit2.1': protos}, open(os.path.join(outdir, 'luajit.ref.json'), 'w'), indent=1)
print(len(protos), 'luajit protos')
