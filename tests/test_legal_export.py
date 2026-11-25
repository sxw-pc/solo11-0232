import tempfile
import unittest
from pathlib import Path
from cloudlab.store import connect
from cloudlab import claim, recovery
from cloudlab.legal_export import provisional_manifest


class LegalExportTest(unittest.TestCase):
    def test_snapshot_invalidation_changes_provisional_manifest(self):
        with tempfile.TemporaryDirectory() as folder:
            db=connect(str(Path(folder)/'state.sqlite'))
            claim.run(db,dict(op='declare',id='v',size=4,mode='single_writer',region='east'))
            recovery.run(db,dict(op='snapshot',id='s1',claim='v',generation=1))
            recovery.run(db,dict(op='snapshot',id='s2',claim='v',parent='s1',generation=2))
            self.assertEqual(provisional_manifest(db,'m1','v')['snapshot'],'s2')
            recovery.run(db,dict(op='invalidate_snapshot',id='s2'))
            self.assertEqual(provisional_manifest(db,'m2','v')['snapshot'],'s1')
            db.close()
