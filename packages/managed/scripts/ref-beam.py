# Reference dump of BEAM files with pybeam (MIT). Dev only. Usage: python ref-beam.py <out.json> <file.beam>...
import sys, json, pybeam
out = {}
for p in sys.argv[2:]:
    b = pybeam.BeamFile(p)
    out[p.split('/')[-1]] = {'module': b.modulename, 'atoms': b.atoms, 'exports': [list(x) for x in b.exports], 'imports': [list(x) for x in b.imports]}
json.dump(out, open(sys.argv[1], 'w'), indent=1)
