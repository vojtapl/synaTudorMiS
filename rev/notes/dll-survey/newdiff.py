import json,re,os,glob
good=re.compile(r'^[\x20-\x7e]+$')
def interesting(s):
    if len(s)<8 or not good.match(s): return False
    letters=sum(c.isalpha() for c in s)
    if letters < len(s)*0.6: return False
    # require identifier-ish or sentence-ish
    return bool(re.search(r'[a-z]{3}',s,re.I)) and (('_' in s) or (' ' in s) or re.search(r'[a-z][A-Z]',s) or '%' in s)

def load(h): return set(open(glob.glob(f'strs/{h[:10]}*.txt')[0]).read().splitlines())
old=json.load(open('survey_before_downloads.json')); allr=json.load(open('survey.json'))
oldsh={r['sha'] for r in old}
new=[r for r in allr if r['sha'] not in oldsh]
v111=set(); ALL=set()
for r in old:
    s=load(r['sha']); ALL|=s
    if re.search(r'synaWudfBioUsb111\.dll$',r['paths'][0]): v111|=s
new.sort(key=lambda r:('synaFp' in r['paths'][0], r['ver']))
for r in new:
    k=r['kw']; s=load(r['sha'])
    nv=[x for x in s-v111 if interesting(x) and not x.startswith('.?A')]
    na=sorted(x for x in s-ALL if interesting(x) and not x.startswith('.?A'))
    open(f"newall_{r['sha'][:10]}.txt",'w').write('\n'.join(na))
    print(f"{os.path.basename(r['paths'][0]):24} {r['sha'][:8]} {r['arch']:5} {r['ver']:13} {r['size']/1e6:4.2f}MB A{r['nA']:5} U{r['nU']:4} tud{k['tudor']:3} vfm{k['vfm']:3} cmd{k['VCSFW_CMD_']:2} res{k['VCS_RESULT_']:2} ssi{k['ssi']:3} iota{k['iota']:2} prov{k['provision']:2} pair{k['pair']:2} own{k['owner']} | newV111 {len(nv):4} newALL {len(na):4} | {r['pdb'][0].split(chr(92))[-1] if r['pdb'] else '-'} | {r['pdb'][0][:70] if r['pdb'] else ''}")
