import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from build_regional_tls_packages import (REGIONS, OLD_CRO, OLD_CRR, OLD_GOOGLE,
    OLD_UA, NEW_CRO, NEW_CRR, NEW_UA, patch_code)


class RegionalGooglePatchTests(unittest.TestCase):
    def test_google_fields_and_mobile_agent_fit_without_shifting_code(self):
        source = b'\x01'.join((OLD_CRO, OLD_CRR, OLD_GOOGLE, OLD_UA))
        for region, info in REGIONS.items():
            with self.subTest(region=region):
                url = info['google']
                self.assertTrue(url.startswith(b'https://'))
                self.assertEqual(url.count(b'%s'), 1)
                self.assertLessEqual(len(url), len(OLD_GOOGLE))
                # JPN's additional binary hooks require an actual browser image.
                result = patch_code(source, url)
                self.assertEqual(len(result), len(source))
                for expected in (NEW_CRO, NEW_CRR, NEW_UA, url):
                    self.assertIn(expected, result)
                self.assertNotIn(OLD_GOOGLE, result)


if __name__ == '__main__':
    unittest.main()
