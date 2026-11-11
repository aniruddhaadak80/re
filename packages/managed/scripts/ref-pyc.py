# Compile a source file with the running CPython and dump dis.get_instructions for every code object as JSON.
# Dev only. Usage: python ref-pyc.py <src.py> <out.pyc> <out.json>
import sys, dis, json, marshal, py_compile, types
src, pyc, out = sys.argv[1:4]
py_compile.compile(src, cfile=pyc, dfile='sample_mod.py', doraise=True, invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)
with open(pyc, 'rb') as f:
    f.read(16)
    co = marshal.load(f)
res = []
def walk(c, path):
    ins = []
    for i in dis.get_instructions(c):
        av = i.argval
        if isinstance(av, (str, int, float, bool)) or av is None:
            pass
        else:
            av = repr(av)
        ins.append([i.offset, i.opname, i.arg, av if not isinstance(av, float) else repr(av), i.argrepr])
    res.append({'path': path, 'name': c.co_name, 'firstlineno': c.co_firstlineno, 'names': list(c.co_names), 'varnames': list(c.co_varnames),
                'freevars': list(c.co_freevars), 'cellvars': list(c.co_cellvars), 'nconsts': len(c.co_consts), 'codeSize': len(c.co_code), 'ins': ins})
    for k in c.co_consts:
        if isinstance(k, types.CodeType):
            walk(k, path + '/' + k.co_name)
walk(co, co.co_name)
json.dump({'version': f'{sys.version_info.major}.{sys.version_info.minor}', 'codes': res}, open(out, 'w'))
print(out, len(res))
