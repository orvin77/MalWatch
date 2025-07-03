import unittest
from scan import get_analysis_stats, get_pwned

class TestScan(unittest.TestCase):

    def test_get_analysis_stats(self):
    # Using this URL to test: http://www.lebensmittel-ueberwachung.de/index.php/aktuelles.1
        res = {
            "malicious": 0,
            "suspicious": 0,
            "undetected": 32,
            "harmless": 65,
            "timeout": 0
        }

        self.assertEqual(get_analysis_stats("https://www.virustotal.com/api/v3/analyses/u-7a45bfbf23a186c8c167a416a92c3c0802b9b244f69be29457925cd759d2412f-1751513126"), res)

    def test_get_Pwned(self):
    # Using this email to test: arianawoocay@gmail.com
        status, breaches = get_pwned("arianawoocay@gmail.com")
        assert status == 200
