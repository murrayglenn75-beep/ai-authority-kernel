"""Pure policy decision helper for real-time voice signals (no microphone access)."""
from dataclasses import dataclass
from typing import Literal

@dataclass(frozen=True)
class VoiceSignal:
    speaker_target: Literal["agent", "other", "unknown"]
    confidence: float
    transcript: str
    has_user_consent: bool

@dataclass(frozen=True)
class VoiceDecision:
    disposition: Literal["ignore", "clarify", "consider"]
    tool_execution_authorized: bool
    explanation: str

def assess_voice_signal(signal: VoiceSignal) -> VoiceDecision:
    """Signal is untrusted. This function NEVER grants tool execution authority."""
    if not signal.has_user_consent:
        return VoiceDecision("ignore", False, "No recording/processing consent")
    if not isinstance(signal.confidence, (int, float)) or isinstance(signal.confidence, bool) or not 0 <= signal.confidence <= 1:
        return VoiceDecision("clarify", False, "Invalid confidence")
    if signal.speaker_target == "other":
        return VoiceDecision("ignore", False, "Speech not directed at agent")
    if signal.speaker_target != "agent" or signal.confidence < 0.9:
        return VoiceDecision("clarify", False, "Ambiguous addressed speech")
    if not signal.transcript.strip():
        return VoiceDecision("clarify", False, "Empty transcript")
    return VoiceDecision("consider", False, "Requires independently authenticated AAK action authorization")
