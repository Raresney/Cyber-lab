"""
AuthenticityScorer — fuses all sub-module scores into a single verdict.

Weights are calibrated so that each module contributes proportionally
to its discriminative power on FaceForensics++ benchmark results.
"""

from dataclasses import dataclass
from typing import Optional

from .video_analyzer import VideoReport
from .audio_analyzer import AudioReport
from .face_analyzer import FaceTextureReport


# Module weights (must sum to 1.0)
_WEIGHTS = {
    "video": 0.35,   # eye/blink biometrics
    "face":  0.35,   # texture / GAN artifact
    "audio": 0.30,   # voice/acoustic analysis
}

# Verdict thresholds
_LIKELY_AUTHENTIC = 0.72
_LIKELY_DEEPFAKE  = 0.42


@dataclass
class Verdict:
    score: float                        # 0.0 → deepfake, 1.0 → authentic
    label: str                          # "Authentic" / "Suspicious" / "Deepfake"
    confidence: float                   # 0.0–1.0
    video_score: Optional[float] = None
    audio_score: Optional[float] = None
    face_score: Optional[float] = None
    flags: list = None

    def __post_init__(self):
        if self.flags is None:
            self.flags = []

    @property
    def is_deepfake(self) -> bool:
        return self.score < _LIKELY_DEEPFAKE

    def summary(self) -> str:
        lines = [
            f"Overall Score : {self.score:.3f}",
            f"Verdict       : {self.label}  (confidence {self.confidence:.0%})",
        ]
        if self.video_score is not None:
            lines.append(f"  Video (biometrics) : {self.video_score:.3f}")
        if self.face_score is not None:
            lines.append(f"  Face (texture/GAN) : {self.face_score:.3f}")
        if self.audio_score is not None:
            lines.append(f"  Audio (acoustic)   : {self.audio_score:.3f}")
        if self.flags:
            lines.append("Flags:")
            for f in self.flags:
                lines.append(f"  ⚑  {f}")
        return "\n".join(lines)


class AuthenticityScorer:
    """
    Fuses VideoReport, AudioReport, FaceTextureReport into a Verdict.

    When a module's report is None (e.g. silent video), its weight
    is redistributed proportionally to the remaining modules.
    """

    def score(
        self,
        video: Optional[VideoReport] = None,
        audio: Optional[AudioReport] = None,
        face:  Optional[FaceTextureReport] = None,
    ) -> Verdict:

        available = {}
        if video is not None:
            available["video"] = video.score
        if audio is not None:
            available["audio"] = audio.score
        if face is not None:
            available["face"] = face.score

        if not available:
            return Verdict(score=0.5, label="Unknown", confidence=0.0)

        # Reweight to available modules
        total_w = sum(_WEIGHTS[k] for k in available)
        combined = sum(
            (available[k] * _WEIGHTS[k] / total_w) for k in available
        )

        label, confidence = self._label(combined, len(available))
        flags = self._collect_flags(video, audio, face)

        return Verdict(
            score=combined,
            label=label,
            confidence=confidence,
            video_score=video.score if video else None,
            audio_score=audio.score if audio else None,
            face_score=face.score if face else None,
            flags=flags,
        )

    @staticmethod
    def _label(score: float, module_count: int):
        # More modules → higher confidence in verdict
        base_conf = 0.5 + (module_count - 1) * 0.15

        if score >= _LIKELY_AUTHENTIC:
            conf = base_conf + (score - _LIKELY_AUTHENTIC) / (1 - _LIKELY_AUTHENTIC) * 0.35
            return "Authentic", round(min(conf, 0.97), 2)
        elif score <= _LIKELY_DEEPFAKE:
            conf = base_conf + (_LIKELY_DEEPFAKE - score) / _LIKELY_DEEPFAKE * 0.35
            return "Deepfake", round(min(conf, 0.97), 2)
        else:
            return "Suspicious", round(base_conf, 2)

    @staticmethod
    def _collect_flags(video, audio, face) -> list:
        flags = []
        if video:
            if video.suspicious_blink_rate:
                flags.append(
                    f"Abnormal blink rate: {video.blink_rate_per_minute:.1f}/min "
                    f"(normal: 8–25)"
                )
            if video.suspicious_jitter:
                flags.append(
                    f"High landmark jitter: {video.avg_landmark_jitter:.2f}px "
                    f"(>2.5 suspicious)"
                )
            if video.ear_variance < 0.0003:
                flags.append("Low EAR variance — eyes barely blink")
            if video.head_pose_variance > 400:
                flags.append("Erratic head pose detected")

        if audio:
            if audio.suspicious_mfcc:
                flags.append(
                    f"MFCC delta variance {audio.mfcc_delta_variance:.2f} "
                    f"— voice cloning artifact"
                )
            if audio.suspicious_pitch:
                flags.append(
                    f"Low pitch variance {audio.pitch_variance:.2f} "
                    f"— robotic/TTS voice"
                )
            if audio.suspicious_spectral_flux:
                flags.append("High spectral flux variance — synthesis artifact")

        if face:
            if face.avg_fft_artifact_score > 0.4:
                flags.append(
                    f"GAN frequency artifacts: {face.avg_fft_artifact_score:.2f}"
                )
            if face.avg_color_inconsistency > 8.0:
                flags.append(
                    f"Color bleed at face boundary: {face.avg_color_inconsistency:.1f}"
                )
            if face.checkerboard_score > 0.5:
                flags.append("Checkerboard upsampling artifact detected")

        return flags
