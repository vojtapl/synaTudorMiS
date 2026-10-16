import sys, os, re, json, hashlib, subprocess, pefile
files = open('/tmp/claude-1001-dllsurvey/files_new.list0','rb').read().split(b'\0')
files=[f.decode() for f in files if f]
by={}
for f in files:
    h=hashlib.sha256(open(f,'rb').read()).hexdigest()
    by.setdefault(h,[]).append(f)
pat={k:re.compile(k,re.I) for k in ['tudor','vfm','VCSFW_CMD_','VCS_RESULT_','pal','ssi','iota','provision','pair','owner']}
out=json.load(open('/tmp/claude-1001-dllsurvey/survey.json')); seen={r['sha'] for r in out}
for h,paths in by.items():
    if h in seen:
        print('dup',h[:10],paths); continue
    f=paths[0]
    r={'sha':h,'paths':paths,'size':os.path.getsize(f)}
    try:
        pe=pefile.PE(f,fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE'],pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG']])
        m=pe.FILE_HEADER.Machine
        r['arch']={0x8664:'x64',0x14c:'x86',0xaa64:'ARM64',0x1c4:'ARM'}.get(m,hex(m))
        r['ts']=pe.FILE_HEADER.TimeDateStamp
        vi={}
        for fi in getattr(pe,'FileInfo',[]) or []:
            for e in fi:
                if hasattr(e,'StringTable'):
                    for st in e.StringTable:
                        for k,v in st.entries.items(): vi[k.decode(errors='replace')]=v.decode(errors='replace')
        r['ver']=vi.get('FileVersion','?'); r['prodver']=vi.get('ProductVersion','?'); r['desc']=vi.get('FileDescription','?')
        pdb=[]
        for d in getattr(pe,'DIRECTORY_ENTRY_DEBUG',[]):
            e=d.entry
            if e is not None and hasattr(e,'PdbFileName'): pdb.append(e.PdbFileName.rstrip(b'\0').decode(errors='replace'))
        r['pdb']=pdb
    except Exception as ex:
        r['err']=str(ex)
    a=subprocess.run(['strings','-a','-n','6',f],capture_output=True,text=True,errors='replace').stdout.splitlines()
    u=subprocess.run(['strings','-a','-el','-n','6',f],capture_output=True,text=True,errors='replace').stdout.splitlines()
    r['nA']=len(a); r['nU']=len(u)
    allst=set(a)|set(u)
    open(f'/tmp/claude-1001-dllsurvey/strs/{h[:12]}.txt','w').write('\n'.join(sorted(allst)))
    r['kw']={k:sum(1 for s in allst if p.search(s)) for k,p in pat.items()}
    r['nuniq']=len(allst)
    out.append(r)
json.dump(out,open('/tmp/claude-1001-dllsurvey/survey.json','w'),indent=1)
