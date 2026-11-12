#!/usr/bin/env python3
"""Rewrite the MIT CardExample bundle with LZMA blocks (UnityPy BundleFile.save(packer="lzma"),
block info and data blocks LZMA) and record what UnityPy reads back: node names, sizes, SHA-256
of each node's bytes, and the objects (path id, class) of each serialized file."""
import hashlib, json, UnityPy
src = 'samples/extras/containers/ExternalAssets.unity3d'
dst = 'samples/extras/containers/ExternalAssets-lzma.unity3d'
env = UnityPy.load(src)
open(dst, 'wb').write(env.file.save(packer='lzma'))
env2 = UnityPy.load(dst)
f = env2.file
nodes = []
for name, obj in f.files.items():
    data = obj.save() if hasattr(obj, 'save') else obj.bytes
    nodes.append({'path': name, 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
objs = sorted([{'pathId': str(o.path_id), 'class': o.type.name} for o in env2.objects], key=lambda x: int(x['pathId']))
json.dump({'tool': 'UnityPy ' + UnityPy.__version__, 'dataflags': f.dataflags, 'nodes': nodes, 'objects': objs}, open('samples/extras/containers/ExternalAssets-lzma.reference.json', 'w'), indent=1)
print(f.dataflags, nodes, len(objs))
