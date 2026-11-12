#!/bin/sh
# Builds samples/extras/contracts/asyncapi-go.elf.gz (linux/arm64, stripped) and the JS bundle,
# and records the ruamel.yaml (YAML 1.2, safe loader) load of both documents as the reference.
# PyYAML is not used because YAML 1.1 turns the enum values on/off into booleans.
set -e
cd "$(dirname "$0")"
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w -buildid=" -o /tmp/asyncapi-go.elf .
gzip -9 -n -c /tmp/asyncapi-go.elf > ../../contracts/asyncapi-go.elf.gz
python3 - <<'PY'
import json
from ruamel.yaml import YAML
import ruamel.yaml
y = YAML(typ='safe', pure=True)
v2 = y.load(open('streetlights-mqtt-2.6.yml'))
v3 = y.load(open('streetlights-mqtt-3.0.yml'))
json.dump({'v2': v2, 'v3': v3, 'tool': 'ruamel.yaml ' + ruamel.yaml.__version__ + ' (YAML 1.2)'}, open('../../contracts/asyncapi.reference.json', 'w'), indent=1, sort_keys=True)
# a minified-bundle style file: v3 as an object literal with unquoted keys, v2 as a JSON string
def lit(v):
    if isinstance(v, dict): return '{' + ','.join((k if k.isidentifier() else json.dumps(k)) + ':' + lit(x) for k, x in v.items()) + '}'
    if isinstance(v, list): return '[' + ','.join(lit(x) for x in v) + ']'
    return json.dumps(v)
js = '"use strict";var a=1;const specV3=' + lit(v3) + ';const specV2=JSON.parse(' + json.dumps(json.dumps(v2)) + ');export{specV3,specV2};\n'
open('../../contracts/asyncapi.bundle.min.js', 'w').write(js)
PY
