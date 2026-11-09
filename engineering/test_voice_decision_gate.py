import unittest
from voice_decision_gate import VoiceSignal, assess_voice_signal

class VoiceDecisionTests(unittest.TestCase):
    def test_consent(self):
        d=assess_voice_signal(VoiceSignal("agent",1.0,"open tool",False))
        self.assertEqual(d.disposition,"ignore")
    def test_not_addressed(self):
        self.assertEqual(assess_voice_signal(VoiceSignal("other",1.0,"open tool",True)).disposition,"ignore")
    def test_ambiguous(self):
        self.assertEqual(assess_voice_signal(VoiceSignal("unknown",0.95,"open tool",True)).disposition,"clarify")
    def test_low_confidence(self):
        self.assertEqual(assess_voice_signal(VoiceSignal("agent",0.5,"open tool",True)).disposition,"clarify")
    def test_no_autonomous_permission(self):
        d=assess_voice_signal(VoiceSignal("agent",1.0,"transfer funds",True))
        self.assertEqual(d.disposition,"consider")
        self.assertFalse(d.tool_execution_authorized)
    def test_invalid_score(self):
        d=assess_voice_signal(VoiceSignal("agent",float("nan"),"open tool",True))
        self.assertEqual(d.disposition,"clarify")
    def test_empty(self):
        d=assess_voice_signal(VoiceSignal("agent",1.0," ",True))
        self.assertEqual(d.disposition,"clarify")
if __name__ == "__main__":
    unittest.main()
