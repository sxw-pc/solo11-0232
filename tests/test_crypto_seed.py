import tempfile,unittest
from pathlib import Path
from cloudlab.store import connect
from cloudlab import key_wrap,key_service,decrypt_probe

class CryptoSeed(unittest.TestCase):
    def test_key_receipt_and_snapshot_access_are_distinct(self):
        with tempfile.TemporaryDirectory() as d:
            db=connect(str(Path(d)/'x.sqlite'))
            try:
                self.assertEqual(key_wrap.record(db,'w','k','c','s',2,'site-a','active')['decision'],'recorded')
                self.assertEqual(key_service.receipt(db,'r','k','rotate',20,'site-a','done')['decision'],'recorded')
                self.assertEqual(decrypt_probe.result(db,'p','c','s','k','site-b',21,'failed')['decision'],'recorded')
            finally:db.close()
