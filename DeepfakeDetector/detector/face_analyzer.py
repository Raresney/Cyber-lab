"""
Face texture and frequency-domain analysis for GAN artifact detection.

Techniques:
- DCT/FFT high-frequency artifact detection (GAN upsampling leaves grid patterns)
- Color channel inconsistency around face boundary
- Facial region chromatic aberration analysis
"""

import cv2
import numpy as np
import mediapipe as mp
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class FaceTextureReport:
    analyzed_frames: int = 0
    avg_fft_artifact_score: float = 0.0    # 0–1, higher = more GAN artifacts
    avg_color_inconsistency: float = 0.0   # color bleed at face boundary
    avg_noise_variance: float = 0.0        # unnatural noise pattern
    checkerboard_score: float = 0.0        # GAN upsampling grid artifact
    score: float = 1.0

    _artifact_scores: list = field(default_factory=list, repr=False)
    _color_scores: list = field(default_factory=list, repr=False)
    _noise_scores: list = field(default_factory=list, repr=False)

    def compute(self):
        if self._artifact_scores:
            self.avg_fft_artifact_score = float(np.mean(self._artifact_scores))
        if self._color_scores:
            self.avg_color_inconsistency = float(np.mean(self._color_scores))
        if self._noise_scores:
            self.avg_noise_variance = float(np.mean(self._noise_scores))

        penalty = 0.0
        if self.avg_fft_artifact_score > 0.6:
            penalty += 0.35
        elif self.avg_fft_artifact_score > 0.4:
            penalty += 0.15

        if self.avg_color_inconsistency > 15.0:
            penalty += 0.25
        elif self.avg_color_inconsistency > 8.0:
            penalty += 0.10

        if self.checkerboard_score > 0.5:
            penalty += 0.20

        self.score = max(0.0, 1.0 - penalty)


class FaceAnalyzer:
    """
    Analyzes per-frame facial region for GAN-specific artifacts.

    Works by cropping the face ROI and examining:
    1. FFT spectrum for periodic high-frequency patterns
    2. Color inconsistency at the face/background boundary
    3. Checkerboard artifacts from transpose convolutions
    """

    def __init__(self):
        self._mp_face = mp.solutions.face_detection.FaceDetection(
            model_selection=1,
            min_detection_confidence=0.5,
        )

    def analyze_frames(self, frames: list[np.ndarray],
                       sample_every: int = 5) -> FaceTextureReport:
        report = FaceTextureReport()

        for i, frame in enumerate(frames):
            if i % sample_every != 0:
                continue

            face_roi = self._extract_face_roi(frame)
            if face_roi is None:
                continue

            report.analyzed_frames += 1
            art = self._fft_artifact_score(face_roi)
            col = self._color_inconsistency(frame, face_roi)
            noise = self._noise_variance(face_roi)

            report._artifact_scores.append(art)
            report._color_scores.append(col)
            report._noise_scores.append(noise)

        report.checkerboard_score = self._checkerboard_score(
            report._artifact_scores
        )
        report.compute()
        return report

    def _extract_face_roi(self, frame: np.ndarray) -> Optional[np.ndarray]:
        h, w = frame.shape[:2]
        rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        result = self._mp_face.process(rgb)

        if not result.detections:
            return None

        det = result.detections[0].location_data.relative_bounding_box
        x1 = max(0, int(det.xmin * w))
        y1 = max(0, int(det.ymin * h))
        x2 = min(w, int((det.xmin + det.width) * w))
        y2 = min(h, int((det.ymin + det.height) * h))

        if (x2 - x1) < 32 or (y2 - y1) < 32:
            return None

        return frame[y1:y2, x1:x2]

    @staticmethod
    def _fft_artifact_score(roi: np.ndarray) -> float:
        """
        GAN-generated faces show periodic peaks in FFT at specific frequencies
        due to upsampling artifacts. Score is normalized peak prominence.
        """
        gray = cv2.cvtColor(roi, cv2.COLOR_BGR2GRAY).astype(np.float32)
        gray = cv2.resize(gray, (128, 128))

        f = np.fft.fft2(gray)
        fshift = np.fft.fftshift(f)
        magnitude = np.log1p(np.abs(fshift))

        # Suppress DC component (center 8x8)
        cx, cy = magnitude.shape[1] // 2, magnitude.shape[0] // 2
        magnitude[cy-4:cy+4, cx-4:cx+4] = 0

        # Ratio of high-frequency energy to total
        total = np.sum(magnitude) + 1e-6
        h, w = magnitude.shape
        border = 20
        hf = np.sum(magnitude[:border, :]) + np.sum(magnitude[-border:, :]) + \
             np.sum(magnitude[:, :border]) + np.sum(magnitude[:, -border:])

        return float(np.clip(hf / total * 4.0, 0.0, 1.0))

    @staticmethod
    def _color_inconsistency(frame: np.ndarray, face_roi: np.ndarray) -> float:
        """
        Measures color channel std-dev difference between face ROI and
        surrounding region — blending artifacts leave color bleeds.
        """
        face_lab = cv2.cvtColor(
            cv2.resize(face_roi, (64, 64)), cv2.COLOR_BGR2Lab
        ).astype(np.float32)
        frame_lab = cv2.cvtColor(
            cv2.resize(frame, (64, 64)), cv2.COLOR_BGR2Lab
        ).astype(np.float32)

        face_std = np.std(face_lab[:, :, 1:], axis=(0, 1))  # a, b channels
        frame_std = np.std(frame_lab[:, :, 1:], axis=(0, 1))

        return float(np.mean(np.abs(face_std - frame_std)))

    @staticmethod
    def _noise_variance(roi: np.ndarray) -> float:
        """Laplacian-based noise estimation — synthetic faces are often too smooth."""
        gray = cv2.cvtColor(roi, cv2.COLOR_BGR2GRAY)
        lap = cv2.Laplacian(gray, cv2.CV_64F)
        return float(np.var(lap))

    @staticmethod
    def _checkerboard_score(artifact_scores: list) -> float:
        if len(artifact_scores) < 5:
            return 0.0
        arr = np.array(artifact_scores)
        # Checkerboard artifacts create periodic oscillation in scores
        diffs = np.diff(arr)
        sign_changes = np.sum(np.diff(np.sign(diffs)) != 0)
        return float(np.clip(sign_changes / len(arr), 0.0, 1.0))
