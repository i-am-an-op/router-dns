#!/usr/bin/env python3
"""Synthetic archive rejection tests; never starts Docker or imports an image."""
import hashlib,io,json,tarfile,tempfile,unittest
from pathlib import Path
from verify_image_archive import verify

class ArchiveTests(unittest.TestCase):
    def check_archive(self, entries, valid, expected=None):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'image.tar'
            with tarfile.open(p,'w') as t:
                for name,data in entries:
                    info=tarfile.TarInfo(name);info.size=len(data);t.addfile(info,io.BytesIO(data))
            digest=expected or hashlib.sha256(p.read_bytes()).hexdigest()
            if valid:self.assertFalse(verify(p,digest)['daemon_invoked'])
            else:
                with self.assertRaises(ValueError):verify(p,digest)
    def test_verified_descriptor(self):
        blob=b'{}';digest=hashlib.sha256(blob).hexdigest()
        self.check_archive([('blobs/sha256/'+digest,blob),('index.json',json.dumps({'manifests':[{'digest':'sha256:'+digest,'size':2}]}).encode())],True)
    def test_corrupt_expected_archive(self):self.check_archive([('manifest.json',b'[]')],False,'0'*64)
    def test_malformed_child_digest(self):self.check_archive([('index.json',b'{"digest":"sha256:bad","size":2}')],False)
    def test_subject_annotation(self):self.check_archive([('index.json',b'{"annotations":{"io.containerd.manifest.subject":"x"}}')],False)
    def test_missing_descriptor_target(self):self.check_archive([('index.json',json.dumps({'digest':'sha256:'+'a'*64,'size':2}).encode())],False)
    def test_changed_blob(self):self.check_archive([('blobs/sha256/'+'a'*64,b'{}')],False)
    def test_path_traversal(self):self.check_archive([('../index.json',b'{}')],False)
    def test_duplicate(self):self.check_archive([('manifest.json',b'[]'),('manifest.json',b'[]')],False)
    def test_empty_manifest(self):self.check_archive([('manifest.json',b'[]')],False)
    def docker(self, changed=False, missing=False):
        layer=b'known uncompressed layer';layer_sha=hashlib.sha256(layer).hexdigest()
        config=json.dumps({'rootfs':{'diff_ids':['sha256:'+layer_sha]}}).encode()
        name=hashlib.sha256(config).hexdigest()+'.json'
        entries=[(name,config),('manifest.json',json.dumps([{'Config':name,'Layers':['layer.tar']}]).encode())]
        if not missing:entries.append(('layer.tar',b'changed' if changed else layer))
        return entries
    def test_docker_config_and_layers(self):self.check_archive(self.docker(),True)
    def test_changed_docker_layer(self):self.check_archive(self.docker(changed=True),False)
    def test_missing_docker_layer(self):self.check_archive(self.docker(missing=True),False)
    def test_oversized_metadata(self):self.check_archive([('index.json',b'{'+b' '*(8*1024*1024))],False)
    def test_outer_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'image.tar'
            with tarfile.open(p,'w') as t:
                info=tarfile.TarInfo('index.json');info.type=tarfile.SYMTYPE;info.linkname='/tmp/index';t.addfile(info)
            with self.assertRaises(ValueError):verify(p,hashlib.sha256(p.read_bytes()).hexdigest())

if __name__=='__main__':unittest.main()
