import unittest
from cbvg_paired import PairedResult, assess_paired

def rows(wins, losses, ties=0):
    return tuple(PairedResult(str(i), False, True) for i in range(wins)) + tuple(
        PairedResult(str(i + wins), True, False) for i in range(losses)) + tuple(
        PairedResult(str(i + wins + losses), True, True) for i in range(ties))

class PairedTests(unittest.TestCase):
    def test_small_gain_not_supported(self):
        v = assess_paired(rows(2, 0, 28))
        self.assertFalse(v.admitted)
        self.assertEqual(v.reason, 'insufficient_statistical_evidence')
    def test_clear_gain(self):
        v = assess_paired(rows(12, 0, 28))
        self.assertTrue(v.admitted)
        self.assertLess(v.one_sided_p, .05)
    def test_equal_baseline(self):
        self.assertFalse(assess_paired(rows(0, 0, 40)).admitted)
    def test_losses(self):
        self.assertFalse(assess_paired(rows(2, 10, 30)).admitted)
    def test_duplicate_tasks(self):
        x = list(rows(1,0,29)); x[-1] = PairedResult(x[0].task_id,True,True)
        self.assertEqual(assess_paired(tuple(x)).reason, 'duplicate_task')
    def test_bad_inputs(self):
        self.assertEqual(assess_paired((PairedResult('a',1,True),)*30).reason,'malformed_task')
    def test_insufficient_samples(self):
        self.assertEqual(assess_paired(rows(3,0,0)).reason,'insufficient_samples')
    def test_zero_discordance(self):
        self.assertEqual(assess_paired(rows(0,0,40)).one_sided_p,1.0)
    def test_invalid_config(self):
        with self.assertRaises(ValueError): assess_paired(rows(20,0,20),alpha=0)
if __name__ == '__main__': unittest.main()
