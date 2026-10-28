"""Inspect exact frozen ZIP bytes without extraction, execution or re-encoding."""
import io
import zipfile
import public_support as S


def inspect(values,records):
    entries={}
    with zipfile.ZipFile(io.BytesIO(values['package_archive'])) as archive:
        listed=archive.infolist()
        S.require(len(listed)==5 and {e.filename for e in listed}=={'README.md','codec.json','index.json','formula.txt','manifest.json'},'exact frozen ZIP entries')
        total=0
        for entry in listed:
            total+=entry.file_size
            S.require(0<=entry.file_size<=S.PUBLIC_CAP and total<=S.CAP,'ZIP expansion budget')
            S.require(not entry.is_dir() and not(entry.flag_bits&1),'ZIP entry form')
            data=archive.read(entry)
            S.require(len(data)==entry.file_size,'ZIP declared size')
            matches=[m.group() for m in S.PRIVATE.finditer(data.decode('utf-8'))]
            S.require(not matches or entry.filename=='manifest.json' and matches==['/usr/lib/libc.so.6'],'unintended ZIP host path')
            entries[entry.filename]=data
    S.require(entries['README.md']==values['package_lexicon'],'exact readable lexicon identity')
    for role in ('package_share','package_lexicon','package_authoring'):
        S.require(not S.PRIVATE.search(values[role].decode()),'private path in exact package artifact')
    index=S.parse(entries['index.json'],S.CAP)
    manifest=S.parse(entries['manifest.json'],S.CAP)
    for source in index['sources']:
        raw=values['source_'+source['id'].lower()]
        S.require(len(raw)==source['bytes'] and S.sha(raw)==source['sha256'],'package source identity')
    return dict(archive=S.public_pin(records['package_archive']),share=dict(**S.public_pin(records['package_share']),codepoints=len(values['package_share'].decode())),
                formula=dict(bytes=len(entries['formula.txt']),codepoints=len(entries['formula.txt'].decode()),sha256=S.sha(entries['formula.txt'])),
                entry_pins={name:dict(bytes=len(data),sha256=S.sha(data)) for name,data in entries.items()},
                coverage=index['coverage'],assurance=index['assurance'],runtime=manifest['body']['runtime'],
                standard_runtime_host_path='/usr/lib/libc.so.6; explicit generic dependency, no user-private paths detected',
                format='Exact frozen ZIP for inspection; use separately supplied matching Transport decoder/runtime for operations. No archive content executed; references remain attached/local, not hosted or fetched.',
                compatibility=manifest['body']['runtime']['formats'],
                scope='Bounded static identity/privacy inspection only; no new native decoder, desktop acceptance, whole-archive net saving or semantic-completeness claim.')


def add(outputs,values):
    for role,name in (('package_archive','meaning.zip'),('package_share','share.txt'),
                      ('package_lexicon','lexicon.md'),('package_authoring','authoring.json')):
        outputs['transported/'+name]=values[role]
