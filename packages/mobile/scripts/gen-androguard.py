#!/usr/bin/env python3
"""Write samples/mobile/reference/androguard.json with androguard 4.x (dev only, not run by tests)."""
import hashlib, json, os, sys
from loguru import logger
from androguard.core.apk import APK
from androguard.core.dex import DEX

logger.remove()
ROOT = os.path.join(os.path.dirname(__file__), '..', '..', '..', 'samples', 'mobile')
out = {}
for f in sorted(os.listdir(os.path.join(ROOT, 'apk'))):
    a = APK(os.path.join(ROOT, 'apk', f))
    dexes = []
    for name in a.get_dex_names():
        d = DEX(a.get_file(name))
        dexes.append({'name': name, 'classes': len(d.get_classes()), 'methodIds': len(d.get_methods()), 'strings': len(list(d.get_strings())),
                      'fieldIds': len(d.get_fields())})
    out[f] = {
        'androguard': __import__('androguard').__version__,
        'package': a.get_package(), 'versionCode': a.get_androidversion_code(), 'versionName': a.get_androidversion_name(),
        'minSdk': a.get_min_sdk_version(), 'targetSdk': a.get_target_sdk_version(), 'label': a.get_app_name(), 'mainActivity': a.get_main_activity(),
        'permissions': sorted(a.get_permissions()), 'activities': sorted(a.get_activities()), 'services': sorted(a.get_services()),
        'receivers': sorted(a.get_receivers()), 'providers': sorted(a.get_providers()),
        'signedV1': a.is_signed_v1(), 'signedV2': a.is_signed_v2(), 'signedV3': a.is_signed_v3(),
        'certificates': [{'subject': c.subject.human_friendly, 'issuer': c.issuer.human_friendly, 'serial': str(c.serial_number), 'sha256': c.sha256.hex()} for c in a.get_certificates()],
        'v2CertSha256': [hashlib.sha256(c).hexdigest() for c in a.get_certificates_der_v2()],
        'v3CertSha256': [hashlib.sha256(c).hexdigest() for c in a.get_certificates_der_v3()],
        'dex': dexes,
    }
json.dump(out, open(os.path.join(ROOT, 'reference', 'androguard.json'), 'w'), indent=1, sort_keys=True)
