"""Pure signed-adapter controls; native crypto/decoder execution deliberately denied."""
from copy import deepcopy
from pathlib import Path
import subprocess
import errno
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'tools'))
import transport_document as old
import transport_document_archive as za
import transport_signed_document as signed
from manifest_signing import manifest as crypto

KEY = b'K' * crypto.PUBLIC_KEY_BYTES
REGISTRY = 'a' * 64
SOURCE = b'hello'


def manifest_fixture(reading=False):
    sections = [{'id':'ALL','label':'Whole source','start':0,'end':len(SOURCE),'dependencies':[],
                 'sha256':old.digest(SOURCE)}]
    record = old.reading_module.EMPTY
    if reading:
        record = {'schema':'transport/reading-view/1','format':'text','tool_versions':{},
            'source_sha256':old.digest(SOURCE),'text_sha256':old.digest(SOURCE),'text_bytes':len(SOURCE),
            'segments':[{'id':'L1','label':'Line 1','start':0,'end':len(SOURCE),'kind':'line',
                         'source_locator':{'line':1,'source_start':0,'source_end':len(SOURCE)}}],
            'uncertainty':['Declared fixture, fidelity unproved.'],'coverage':{},'text_path':'reading.txt'}
    entries = old.metadata('Fixture',sections,record)
    frame = {'ordinal':0,'offset':0,'source_bytes':len(SOURCE),'source_sha256':old.digest(SOURCE),
             'wire_bytes':4,'wire_sha256':old.digest(b'wire'),'entry':'frames/00000.stb1'}
    index = {'bytes':len(SOURCE),'sha256':old.digest(SOURCE),'frames':[frame],'mode':'source-alias'} if reading else None
    body = old.body_for(Path('fixture.txt'),'Fixture',[frame],len(SOURCE),old.digest(SOURCE),entries,{'fixture':True,'native_sha256':'d'*64},index)
    declaration = {'record_pin':old.pin(entries['reading.json']),'unit_count':1,'claim_status':'DECLARED_UNPROVEN','semantic_record_pin':None} if reading else None
    wrapper = {'body':body,'package_id':old.digest(old.canonical(body))}
    return {'schema':signed.PROFILE,'transport':wrapper,'declared_reading':declaration}, entries


def envelope(value, key=KEY, registry=REGISTRY):
    result = crypto.unsigned_envelope(value,key,registry)
    result['signature'] = ('12' * crypto.SIGNATURE_BYTES)
    return crypto.canonical(result)


def put_archive(path, value, entries, raw=None):
    raw = envelope(value) if raw is None else raw
    with zipfile.ZipFile(path,'x',compression=zipfile.ZIP_STORED,allowZip64=False) as archive:
        za.put(archive,'frames/00000.stb1',b'wire')
        for name,data in entries.items():za.put(archive,name,data)
        za.put(archive,'manifest.json',raw)
    return raw


def maximum_metadata_fixture():
    value,_=manifest_fixture(True);body=value['transport']['body']
    body['frames']=[{'ordinal':i,'offset':i*old.FRAME_SOURCE,'source_bytes':old.FRAME_SOURCE,
        'source_sha256':'c'*64,'wire_bytes':old.FRAME_WIRE,'wire_sha256':'d'*64,
        'entry':'frames/'+format(i,'05d')+'.stb1'} for i in range(old.MAX_FRAMES)]
    body['source']['bytes']=old.MAX_SOURCE;body['source']['sha256']='c'*64
    body['reading']={'bytes':old.reading_module.MAX_READING,'sha256':'e'*64,'mode':'derived',
        'frames':[dict(body['frames'][i],entry='reading/frames/'+format(i,'05d')+'.stb1')
                  for i in range(old.reading_module.MAX_READING_FRAMES)]}
    body['decoder']={'format':'transport/document-decoder/1','native_sha256':'f'*64,
        'modules':{name:'a'*64 for name in old.MODULES},'platform':{
            'system':'linux','machine':'aarch64','python':'3.14.0','implementation':'cpython','libc':['glibc','2.42']}}
    record={'schema':'transport/reading-view/1','format':'pdf','tool_versions':{},
        'source_sha256':body['source']['sha256'],'text_sha256':'e'*64,'text_bytes':old.reading_module.MAX_READING,
        'segments':[{'id':'PAGE1','label':'Synthetic declared page','start':0,'end':old.reading_module.MAX_READING,
                     'kind':'page','source_locator':{'page':1}}],
        'uncertainty':['Synthetic metadata capacity only; no source payload or recovery.'],
        'coverage':{},'text_path':'reading.txt'}
    old.reading_module.record_checked(record,body['source']['sha256'])
    sections=[{'id':'ALL','label':'Declared prefix','start':0,'end':5,'dependencies':[],'sha256':old.digest(SOURCE)}]
    entries=old.metadata(body['title'],sections,record)
    body['entries']={name:old.pin(raw) for name,raw in entries.items()}
    value['declared_reading']['record_pin']=body['entries']['reading.json']
    value['transport']['package_id']=old.digest(old.canonical(body))
    return value


class SignedControls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='signed-pure-')
        self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.addCleanup(patch.stopall)
        patch.object(subprocess,'Popen',side_effect=AssertionError('no real process/native/provider')).start()
        patch.object(old,'runtime',return_value={'fixture':True,'native_sha256':'d'*64}).start()
        self.provider=object.__new__(crypto.NativeProvider)
        self.verified=False;self.reads=[]

    def gate(self, value=None, mutate=None, raw=None, key=KEY, status='NOT_REVOKED', held=None, reading=False, authorize_changed=False):
        original,entries=manifest_fixture(reading)
        value=original if value is None else value
        expected=crypto.signing_preimage(crypto.parse(envelope(value if authorize_changed else original)))
        def verify(public,signature,preimage):
            crypto.need(public==KEY and signature==bytes.fromhex('12'*crypto.SIGNATURE_BYTES)
                        and preimage==expected,'mock native signature refusal')
            self.verified=True
        patch.object(self.provider,'verify',side_effect=verify).start()
        if mutate:mutate(value)
        raw=envelope(value) if raw is None else raw
        path=self.root/('case'+str(len(list(self.root.iterdir())))+'.zip')
        put_archive(path,value,entries,raw)
        share=signed.signed_share_for(envelope(value if authorize_changed else original),entries['formula.txt'].decode(),'meaning.zip')
        work=self.root/('work'+str(len(list(self.root.iterdir()))));work.mkdir()
        with za.opened(path) as (archive,names):
            original_open=archive.open
            def spy(info,*args,**kwargs):
                name=info.filename if hasattr(info,'filename') else info
                self.reads.append(name)
                if name!='manifest.json':self.assertTrue(self.verified,'payload before signature')
                return original_open(info,*args,**kwargs)
            with patch.object(archive,'open',side_effect=spy):
                return signed.verified_metadata(archive,names,share,held or old.digest(share),self.provider,
                    key,REGISTRY,status,Path('mock-native'),work)

    def test_positive_verifies_before_dictionaries_and_no_frame_read(self):
        with patch.object(old,'share_for',side_effect=AssertionError('encoder constructor forbidden in decoder')):
            body,identifier,sections,record,declaration=self.gate()
        self.assertTrue(self.verified);self.assertEqual(self.reads[0],'manifest.json')
        self.assertNotIn('frames/00000.stb1',self.reads)
        self.assertNotEqual(identifier,old.digest(old.canonical(body)))
        self.assertEqual(sections[0]['id'],'ALL');self.assertIsNone(declaration)

    def test_bad_signature_and_changed_frame_list_refuse_before_payload(self):
        for mode in ('signature','frames'):
            with self.subTest(mode=mode):
                self.verified=False;self.reads=[]
                value,_=manifest_fixture();env=crypto.parse(envelope(value))
                if mode=='signature':env['signature']='00'*crypto.SIGNATURE_BYTES
                else:
                    value['transport']['body']['frames'][0]['wire_sha256']='0'*64
                    value['transport']['package_id']=old.digest(old.canonical(value['transport']['body']))
                    env=crypto.parse(envelope(value))
                with self.assertRaises(ValueError):self.gate(raw=crypto.canonical(env))
                self.assertEqual(self.reads,['manifest.json'])

    def test_wrong_external_key_revocation_and_nonprovider_refuse(self):
        for key,status in ((b'X'*len(KEY),'NOT_REVOKED'),(KEY,'REVOKED'),(KEY,'UNKNOWN')):
            with self.subTest(status=status),self.assertRaises(ValueError):self.gate(key=key,status=status)
            self.assertFalse(self.verified);self.assertEqual(self.reads[-1],'manifest.json')
        value,_=manifest_fixture()
        with self.assertRaises(ValueError):signed.authenticated(envelope(value),object(),KEY,REGISTRY,'NOT_REVOKED')

    def test_algorithm_schema_unsigned_legacy_noncanonical_and_trailing_refuse(self):
        value,_=manifest_fixture();raw=envelope(value)
        cases=[]
        for name,change in (('algorithm','other'),('schema','other'),('signature',None)):
            env=crypto.parse(raw);env[name]=change;cases.append(crypto.canonical(env))
        cases += [old.canonical(value['transport']),raw+b' ',raw.replace(b'"algorithm":',b'"algorithm" :',1)]
        for invalid in cases:
            self.reads=[];self.verified=False
            with self.subTest(raw=invalid[:25]),self.assertRaises(ValueError):self.gate(raw=invalid)
            self.assertEqual(self.reads,['manifest.json'])

    def test_fullshare_tampering_refuses_before_dictionary_reads(self):
        with self.assertRaises(ValueError):self.gate(held='0'*64)
        self.assertTrue(self.verified);self.assertEqual(self.reads,['manifest.json'])
        value,entries=manifest_fixture();raw=envelope(value)
        share=signed.signed_share_for(raw,entries['formula.txt'].decode(),'meaning.zip')
        for changed in (share+b'comment',share.replace(b'meaning.zip',b'evil.zip'),share.replace(b'STSD1:',b'STS1:')):
            with self.assertRaises(ValueError):signed.share_checked(changed,old.digest(share),old.digest(crypto.signing_preimage(crypto.parse(raw))))

    def test_preimage_identity_binds_key_revocation_and_declared_reading(self):
        value,entries=manifest_fixture();formula=entries['formula.txt'].decode()
        baseline=signed.signed_share_for(envelope(value),formula,'meaning.zip')
        self.assertNotEqual(baseline,signed.signed_share_for(envelope(value,b'X'*len(KEY)),formula,'meaning.zip'))
        self.assertNotEqual(baseline,signed.signed_share_for(envelope(value,registry='b'*64),formula,'meaning.zip'))
        value,_=manifest_fixture(True)
        a=signed.signed_share_for(envelope(value),formula,'meaning.zip')
        value['declared_reading']['semantic_record_pin']={'bytes':1,'sha256':'1'*64}
        with self.assertRaisesRegex(ValueError,'semantic artifact delivery unsupported'):
            signed.signed_share_for(envelope(value),formula,'meaning.zip')

    def test_reading_typed_count_source_binding_and_exact_record(self):
        _,_,_,record,declaration=self.gate(reading=True)
        self.assertEqual(declaration['record_pin'],old.pin(old.canonical(record)));self.assertEqual(declaration['unit_count'],1)
        for kind in ('count','bool','source','claim','missing'):
            value,_=manifest_fixture(True)
            if kind=='count':value['declared_reading']['unit_count']=4744
            elif kind=='bool':value['declared_reading']['unit_count']=True
            elif kind=='source':value['declared_reading']['record_pin']['sha256']='0'*64
            elif kind=='claim':value['declared_reading']['claim_status']='PROVED'
            else:value['declared_reading']=None
            with self.subTest(kind=kind),self.assertRaises(ValueError):
                if kind=='count':self.gate(value=value,reading=True,authorize_changed=True)
                else:signed.signed_manifest_checked(value)

    def test_closed_manifest_and_oversize_envelope_refuse(self):
        for kind in ('missing','extra','schema','package'):
            value,_=manifest_fixture()
            if kind=='missing':del value['declared_reading']
            elif kind=='extra':value['extra']=True
            elif kind=='schema':value['schema']='transport/document-zip/1'
            else:value['transport']['package_id']='0'*64
            with self.subTest(kind=kind),self.assertRaises(ValueError):
                if kind=='count':self.gate(value=value,reading=True,authorize_changed=True)
                else:signed.signed_manifest_checked(value)
        with self.assertRaises(ValueError):signed.authenticated(b'x'*(signed.MAX_SIGNED_METADATA+1),self.provider,KEY,REGISTRY,'NOT_REVOKED')

    def test_signed_reading_count_checked_after_validated_dictionary(self):
        value,_=manifest_fixture(True)
        value['declared_reading']['unit_count']=2
        with self.assertRaisesRegex(ValueError,'reading unit count mismatch'):
            self.gate(value=value,reading=True,authorize_changed=True)
        self.assertTrue(self.verified);self.assertIn('reading.json',self.reads)
        self.assertNotIn('frames/00000.stb1',self.reads)

    def test_frame_orchestration_uses_existing_decoder_and_checks_recovery(self):
        value,entries=manifest_fixture(True);raw=envelope(value)
        path=self.root/'signed.zip';put_archive(path,value,entries,raw)
        share=signed.signed_share_for(raw,entries['formula.txt'].decode(),'meaning.zip')
        share_path=self.root/'share.txt';share_path.write_bytes(share)
        calls=[]
        def decode(native,wire,recovered,expected,size):
            self.assertTrue(self.verified);self.assertTrue(wire.read_bytes().startswith(b'FT01'))
            calls.append((expected,size));recovered.write_bytes(SOURCE)
        def verify(*unused):self.verified=True
        with patch.object(self.provider,'verify',side_effect=verify),patch.object(old,'native_path',return_value=Path('native')), \
             patch.object(old,'scratch_root',return_value=self.root),patch.object(old,'reserve'), \
             patch.object(old,'run_native',side_effect=decode):
            target=self.root/'recovered'
            result=signed.decode_document(path,share_path,old.digest(share),target,self.provider,KEY,REGISTRY,'NOT_REVOKED')
        self.assertEqual(target.read_bytes(),SOURCE);self.assertEqual(len(calls),1)
        self.assertEqual(result['execution_authority'],'NONE')
        self.assertEqual(result['semantic_completeness'],'UNPROVEN')
        self.assertFalse(any(p.name.startswith('signed-document-') for p in self.root.iterdir()))

    def test_external_seal_copies_new_manifest_without_key_generation(self):
        value,entries=manifest_fixture();raw=envelope(value)
        old_path=self.root/'old.zip'
        put_archive(old_path,value,entries,old.canonical(value['transport']))
        old_share=self.root/'old-share.txt'
        old_share.write_bytes(old.share_for(entries['formula.txt'].decode(),value['transport']['package_id'],'old.zip',None))
        out=self.root/'sealed'
        with patch.object(self.provider,'verify'),patch.object(old,'native_path',return_value=Path('native')),patch.object(old,'reserve'):
            result=signed.seal_existing_envelope(old_path,old_share,raw,out,'new.zip',self.provider,KEY,REGISTRY,'NOT_REVOKED')
        self.assertEqual(result['exact_recovery'],'NOT_PERFORMED')
        self.assertEqual(result['checked_scope'],'ENDORSEMENT_AND_LEGACY_METADATA_ONLY')
        with za.opened(out/'meaning.zip') as (archive,names):
            self.assertEqual(za.read_entry(archive,'manifest.json',signed.MAX_SIGNED_METADATA),raw)
            self.assertEqual(za.read_entry(archive,'frames/00000.stb1',100),b'wire')
        self.assertIn(b'STSD1:',(out/'share.txt').read_bytes())
        self.assertNotEqual(result['package_id'],value['transport']['package_id'])

    def test_changed_metadata_still_refuses_after_valid_signature(self):
        value,entries=manifest_fixture();entries['operators.json']=b'{}'
        raw=envelope(value);path=self.root/'wrong-dictionary.zip';put_archive(path,value,entries,raw)
        share=signed.signed_share_for(raw,old.formula_for('Fixture',[{'id':'ALL'}]),'meaning.zip')
        with za.opened(path) as (archive,names),patch.object(self.provider,'verify'):
            with self.assertRaisesRegex(ValueError,'metadata integrity'):
                signed.verified_metadata(archive,names,share,old.digest(share),self.provider,
                    KEY,REGISTRY,'NOT_REVOKED',Path('native'),self.root)

    def test_total_metadata_budget_refuses_without_payload_open(self):
        class Archive:
            def getinfo(self,name):
                info=zipfile.ZipInfo(name);info.file_size=signed.MAX_SIGNED_METADATA;return info
            def open(self,*unused):raise AssertionError('payload read before admission')
        with self.assertRaisesRegex(ValueError,'complete metadata bound'):signed.metadata_bound(Archive())

    def test_operator_signing_interface_forwards_explicit_capability_only(self):
        value,_=manifest_fixture();raw=envelope(value)
        with patch.object(self.provider,'sign_manifest',return_value=raw) as signer, \
             patch.object(signed,'seal_existing_envelope',return_value={'status':'FIXTURE'}) as sealer:
            result=signed.sign_and_seal('a','s',value,'out','meaning.zip',self.provider,KEY,17,REGISTRY,'NOT_REVOKED')
        self.assertEqual(result,{'status':'FIXTURE'})
        self.assertEqual(signer.call_args.args,(value,KEY,17,REGISTRY,'NOT_REVOKED','ACTIVE'))
        self.assertEqual(sealer.call_args.args[2],raw)
        with self.assertRaises(ValueError):signed.sign_and_seal('a','s',value,'out','x',object(),KEY,17,REGISTRY,'NOT_REVOKED')

    def test_full_share_formula_must_match_signed_metadata_even_with_held_pin(self):
        value,entries=manifest_fixture();raw=envelope(value)
        path=self.root/'wrong-formula.zip';put_archive(path,value,entries,raw)
        share=signed.signed_share_for(raw,'Wrong formula','meaning.zip')
        with za.opened(path) as (archive,names),patch.object(self.provider,'verify'):
            with self.assertRaisesRegex(ValueError,'formula and package identity mismatch'):
                signed.verified_metadata(archive,names,share,old.digest(share),self.provider,
                    KEY,REGISTRY,'NOT_REVOKED',Path('native'),self.root)

    def test_metadata_total_exact_cap_and_one_over(self):
        names=sorted(za.META_NAMES)
        class Archive:
            def __init__(self,excess):self.excess=excess
            def getinfo(self,name):
                info=zipfile.ZipInfo(name)
                info.file_size=signed.MAX_SIGNED_METADATA-len(names)+1+self.excess if name==names[0] else 1
                return info
            def open(self,*unused):raise AssertionError('payload opened before bounds')
        signed.metadata_bound(Archive(0))
        with self.assertRaises(ValueError):signed.metadata_bound(Archive(1))
        self.assertEqual(signed.MAX_SIGNED_METADATA,old.MAX_META)

    def test_maximum_source_and_derived_frame_lists_fit_full_signed_preimage(self):
        value=maximum_metadata_fixture();signed.signed_manifest_checked(value)
        raw=envelope(value);preimage=crypto.signing_preimage(crypto.parse(raw))
        self.assertLessEqual(len(raw),old.MAX_META)
        self.assertLessEqual(len(preimage),old.MAX_META)
        parsed=crypto.parse(raw)['manifest']['transport']['body']
        self.assertEqual(len(parsed['frames']),old.MAX_FRAMES)
        self.assertEqual(len(parsed['reading']['frames']),old.reading_module.MAX_READING_FRAMES)
        self.assertEqual(parsed['source']['bytes'],old.MAX_SOURCE)
        self.assertLessEqual(sum(parsed['entries'][n]['bytes'] for n in parsed['entries'])+len(raw),old.MAX_META)

    def seal_inputs(self):
        value,entries=manifest_fixture();raw=envelope(value)
        path=self.root/'old.zip';put_archive(path,value,entries,old.canonical(value['transport']))
        share=self.root/'old-share.txt'
        share.write_bytes(old.share_for(entries['formula.txt'].decode(),value['transport']['package_id'],'old.zip',None))
        return path,share,raw

    def seal_call(self,inputs,out):
        with patch.object(self.provider,'verify'),patch.object(old,'native_path',return_value=Path('native')),patch.object(old,'reserve'):
            return signed.seal_existing_envelope(*inputs,out,'new.zip',self.provider,KEY,REGISTRY,'NOT_REVOKED')

    def test_each_publication_stage_failure_leaves_no_visible_directory(self):
        inputs=self.seal_inputs();original_write=signed.write_new;original_copy=signed.copy_authenticated_archive
        def failed_copy(*args):
            original_copy(*args);raise OSError(errno.ENOSPC,'injected archive failure')
        for stage in ('archive','share.txt','receipt.json','rename'):
            out=self.root/('output-'+stage)
            def write(path,data):
                if path.name==stage:raise OSError(errno.ENOSPC,'injected write failure')
                return original_write(path,data)
            with self.subTest(stage=stage),patch.object(signed,'write_new',side_effect=write), \
                 patch.object(signed,'copy_authenticated_archive',side_effect=failed_copy if stage=='archive' else original_copy), \
                 patch.object(signed.publication,'rename_new',side_effect=OSError(errno.ENOSPC,'injected rename') if stage=='rename' else signed.publication.rename_new):
                with self.assertRaises(OSError):self.seal_call(inputs,out)
            self.assertFalse(out.exists());self.assertFalse(out.is_symlink())
            self.assertFalse(any(p.name.startswith('.signed-seal-') for p in self.root.iterdir()))

    def test_concurrent_directory_and_symlink_destinations_are_preserved(self):
        inputs=self.seal_inputs();original=signed.publication.rename_new
        for kind in ('directory','symlink'):
            out=self.root/('race-'+kind);outside=self.root/('outside-'+kind)
            outside.mkdir();(outside/'keep').write_bytes(b'original')
            def race(source,destination):
                if kind=='directory':destination.mkdir();(destination/'keep').write_bytes(b'concurrent')
                else:destination.symlink_to(outside,target_is_directory=True)
                return original(source,destination)
            with self.subTest(kind=kind),patch.object(signed.publication,'rename_new',side_effect=race):
                with self.assertRaises(FileExistsError):self.seal_call(inputs,out)
            self.assertEqual((outside/'keep').read_bytes(),b'original')
            self.assertEqual((out/'keep').read_bytes(),b'concurrent' if kind=='directory' else b'original')
            self.assertEqual(out.is_symlink(),kind=='symlink')

    def test_success_publishes_complete_bundle_without_perfile_links(self):
        inputs=self.seal_inputs();out=self.root/'complete'
        with patch.object(signed.os,'link',side_effect=OSError(errno.ENOSPC,'old partial-publication trigger')):
            self.seal_call(inputs,out)
        self.assertEqual({p.name for p in out.iterdir()},{'meaning.zip','share.txt','receipt.json'})
        self.assertFalse(any(p.name.startswith('.signed-seal-') for p in self.root.iterdir()))

    def test_nonnull_semantic_pin_refuses_before_dictionary_payload(self):
        value,entries=manifest_fixture(True)
        value['declared_reading']['semantic_record_pin']={'bytes':1,'sha256':'a'*64}
        raw=envelope(value);path=self.root/'unresolved.zip';put_archive(path,value,entries,raw)
        reads=[]
        with za.opened(path) as (archive,names),patch.object(self.provider,'verify') as verifier:
            original=archive.open
            def spy(info):
                reads.append(info.filename);return original(info)
            with patch.object(archive,'open',side_effect=spy):
                with self.assertRaisesRegex(ValueError,'semantic artifact delivery unsupported'):
                    signed.verified_metadata(archive,names,b'not reached','0'*64,self.provider,
                        KEY,REGISTRY,'NOT_REVOKED',Path('native'),self.root)
            verifier.assert_called_once()
        self.assertEqual(reads,['manifest.json'])

    def test_existing_output_is_createonly_before_decode(self):
        target=self.root/'exists';target.write_bytes(b'keep')
        with patch.object(signed,'validated',side_effect=AssertionError('decode must not start')):
            with self.assertRaises(ValueError):signed.decode_document('a','s','0'*64,target,self.provider,KEY,REGISTRY,'NOT_REVOKED')
        self.assertEqual(target.read_bytes(),b'keep')


if __name__=='__main__':unittest.main()
