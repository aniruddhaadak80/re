#!/usr/bin/env python3
"""Write samples/mobile/reference/androguard-graph.json with androguard 4.1.4 (dev only, not run by tests):
components with their raw android:exported attribute and intent filters, and deep links."""
import json, os
from loguru import logger
from androguard.core.apk import APK

logger.remove()
ROOT = os.path.join(os.path.dirname(__file__), '..', '..', '..', 'samples', 'mobile')
NS = '{http://schemas.android.com/apk/res/android}'
out = {}
for f in sorted(os.listdir(os.path.join(ROOT, 'apk'))):
    path = os.path.join(ROOT, 'apk', f)
    if not os.path.exists(path):
        continue
    a = APK(path)
    comps = {}
    for kind, names in [('activity', a.get_activities()), ('service', a.get_services()), ('receiver', a.get_receivers()), ('provider', a.get_providers())]:
        for n in names:
            filt = a.get_intent_filters(kind, n)
            comps[n] = {'kind': kind, 'actions': sorted(filt.get('action', [])), 'categories': sorted(filt.get('category', []))}
    man = a.get_android_manifest_xml()
    for el in man.iter():
        tag = el.tag
        if tag in ('activity', 'activity-alias', 'service', 'receiver', 'provider'):
            n = a._format_value(el.get(NS + 'name'))
            if n in comps:
                comps[n]['exportedAttr'] = el.get(NS + 'exported')
                if tag == 'provider':
                    comps[n]['authorities'] = el.get(NS + 'authorities')
    out[os.path.basename(f)] = {'androguard': __import__('androguard').__version__, 'package': a.get_package(), 'components': comps,
                                'permissions': sorted(a.get_permissions()), 'declaredPermissions': sorted(a.get_declared_permissions())}
json.dump(out, open(os.path.join(ROOT, 'reference', 'androguard-graph.json'), 'w'), indent=1, sort_keys=True)
