import tempfile
import unittest
from pathlib import Path
from cloudlab.store import connect
from cloudlab import claim
from cloudlab.usage_capture import capture_page, provisional_invoice


class UsageCaptureTest(unittest.TestCase):
    def test_page_changes_provisional_charge_once(self):
        with tempfile.TemporaryDirectory() as folder:
            db=connect(str(Path(folder)/'state.sqlite'))
            claim.run(db,dict(op='declare',id='v',size=4,mode='single_writer',region='east'))
            page=[{'claim':'v','period':1,'reads':2,'writes':3}]
            self.assertEqual(capture_page(db,'p',page)['decision'],'captured')
            self.assertEqual(capture_page(db,'p',page)['decision'],'reused')
            self.assertEqual(provisional_invoice(db,'i','v',2,5)['amount'],19)
            db.close()
