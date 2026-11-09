# Real-time voice decision signal pilot

Read-only structured decision module for separating voice perception from authority. Inspired by real-time voice decision models and modular conversational context standards; **does not claim compliance with the Real-time Context Standard (RCS)**.

This helper takes externally supplied speaker-directedness, confidence, transcript and processing consent, and outputs `ignore`, `clarify`, or `consider`. All paths explicitly deny tool-action authorization. Only the existing independently verified AAK action gate may authorize a tool call.

Run from `engineering/`: `python -m unittest -v test_voice_decision_gate.py`.

Limits: confidence is not calibrated; speaker identity is not authenticated; emotion/sarcasm inference is excluded; consent flag is illustrative, not proof of lawful consent. A real pilot requires secure device consent, source provenance, bounded retention, anti-spoofing and independent authorization, plus latency and interruption tests. Do not store private audio or voiceprints by default.
