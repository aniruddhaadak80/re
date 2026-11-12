import json,subprocess
m=json.load(open('manifest.json'))
for x in m:
    if 'flex' not in x or x['format'] in ('wav','sigmf'): continue
    out=subprocess.run(['rtl_433','-R','0','-X',x['flex'],'-r',x['file'],'-F','json'],capture_output=True,text=True,timeout=30).stdout
    rows=[json.loads(l) for l in out.splitlines() if l.startswith('{')]
    codes=[c for r in rows for c in r['codes']]
    print(x['file'],codes)
    x['rtl_433']={'version':'25.02','command':'rtl_433 -R 0 -X "%s" -r %s -F json'%(x['flex'],x['file']),'codes':codes}
json.dump(m,open('manifest.json','w'),indent=2)
