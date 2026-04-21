"""
Audio deepfake analysis: spectral artifacts, MFCC consistency,
formant stability, and GAN codec fingerprints.
"""

import numpy as np
import librosa
import soundfile as sf
from dataclasses import dataclass, field
from typing import Optional
import subprocess
import os
import tempfile


@dataclass
class AudioReport:
    duration_sec: float = 0.0
    sample_rate: int = 0

    # Feature statistics
    mfcc_delta_variance: float = 0.0      # high → unnatural transitions
    spectral_flux_mean: float = 0.0       # rate of spectral change
    spectral_flux_variance: float = 0.0
    zcr_mean: float = 0.0                 # zero-crossing rate
    pitch_variance: float = 0.0
    formant_consistency: float = 1.0      # 0–1, 1 = stable
    silence_ratio: float = 0.0

    # Artifact flags
    suspicious_spectral_flux: bool = False
    suspicious_pitch: bool = False
    suspicious_mfcc: bool = False

    score: float = 1.0   # 1.0 = authentic

    def compute(self):
        penalty = 0.0

        # Unnatural MFCC delta variance (TTS / voice-cloning artifacts)
        if self.mfcc_delta_variance > 15.0:
            self.suspicious_mfcc = True
            penalty += 0.30
        elif self.mfcc_delta_variance > 8.0:
            self.suspicious_mfcc = True
            penalty += 0.15

        # High spectral flux variance → unstable synthesis
        if self.spectral_flux_variance > 0.05:
            self.suspicious_spectral_flux = True
            penalty += 0.25

        # Very low pitch variance → monotone robot voice
        if 0 < self.pitch_variance < 10.0:
            self.suspicious_pitch = True
            penalty += 0.20

        # Formant consistency below 0.6 → vocal tract synthesis issues
        if self.formant_consistency < 0.6:
            penalty += 0.15

        self.score = max(0.0, 1.0 - penalty)


class AudioAnalyzer:
    """
    Analyzes audio track extracted from video for deepfake artifacts.

    Detects:
    - Unnatural MFCC delta patterns (voice cloning fingerprint)
    - Spectral flux anomalies (GAN codec artifacts)
    - Pitch monotonicity (TTS tells)
    - Formant instability
    """

    HOP_LENGTH = 512
    N_MFCC = 40
    SILENCE_DB = -40

    def analyze_file(self, path: str) -> AudioReport:
        """Accepts audio files (.wav, .mp3) or video files (extracts audio)."""
        audio_path = self._ensure_audio(path)
        try:
            return self._run_analysis(audio_path)
        finally:
            if audio_path != path and os.path.exists(audio_path):
                os.remove(audio_path)

    def _ensure_audio(self, path: str) -> str:
        ext = os.path.splitext(path)[1].lower()
        if ext in (".wav", ".flac", ".ogg", ".mp3"):
            return path

        # Extract audio from video using ffmpeg
        tmp = tempfile.NamedTemporaryFile(suffix=".wav", delete=False)
        tmp.close()
        try:
            subprocess.run(
                ["ffmpeg", "-y", "-i", path, "-vn",
                 "-acodec", "pcm_s16le", "-ar", "16000", "-ac", "1", tmp.name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True,
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            # ffmpeg not available — return original path, librosa will try
            return path
        return tmp.name

    def _run_analysis(self, path: str) -> AudioReport:
        y, sr = librosa.load(path, sr=None, mono=True)
        report = AudioReport(duration_sec=len(y) / sr, sample_rate=sr)

        # --- MFCC delta variance ---
        mfcc = librosa.feature.mfcc(y=y, sr=sr, n_mfcc=self.N_MFCC,
                                     hop_length=self.HOP_LENGTH)
        mfcc_delta = librosa.feature.delta(mfcc)
        report.mfcc_delta_variance = float(np.var(mfcc_delta))

        # --- Spectral flux ---
        stft = np.abs(librosa.stft(y, hop_length=self.HOP_LENGTH))
        flux = np.sqrt(np.sum(np.diff(stft, axis=1) ** 2, axis=0))
        report.spectral_flux_mean = float(np.mean(flux))
        report.spectral_flux_variance = float(np.var(flux))

        # --- Zero-crossing rate ---
        zcr = librosa.feature.zero_crossing_rate(y, hop_length=self.HOP_LENGTH)
        report.zcr_mean = float(np.mean(zcr))

        # --- Pitch (F0) via YIN ---
        f0 = librosa.yin(y, fmin=50, fmax=500, hop_length=self.HOP_LENGTH)
        voiced = f0[f0 > 0]
        report.pitch_variance = float(np.var(voiced)) if len(voiced) > 10 else 0.0

        # --- Silence ratio ---
        rms = librosa.feature.rms(y=y, hop_length=self.HOP_LENGTH)[0]
        db = librosa.amplitude_to_db(rms)
        report.silence_ratio = float(np.mean(db < self.SILENCE_DB))

        # --- Formant consistency (approximated via LPC spectral envelope) ---
        report.formant_consistency = self._formant_consistency(y, sr)

        report.compute()
        return report

    def _formant_consistency(self, y: np.ndarray, sr: int) -> float:
        """
        Estimates formant stability by comparing LPC envelope centroids
        across 0.5-second windows. High variance → low consistency.
        """
        window = int(sr * 0.5)
        if len(y) < window * 2:
            return 1.0

        centroids = []
        for start in range(0, len(y) - window, window // 2):
            chunk = y[start: start + window]
            # LPC order 12 (standard for speech formant analysis)
            try:
                a = librosa.lpc(chunk, order=12)
                roots = np.roots(a)
                roots = roots[np.imag(roots) >= 0]
                angles = np.angle(roots)
                freqs = angles * (sr / (2 * np.pi))
                freqs = sorted(freqs[(freqs > 90) & (freqs < 4000)])
                if freqs:
                    centroids.append(freqs[0])   # F1 centroid
            except Exception:
                continue

        if len(centroids) < 3:
            return 1.0

        cv = np.std(centroids) / (np.mean(centroids) + 1e-6)
        # CV > 0.30 → high instability
        return float(max(0.0, 1.0 - cv / 0.30))
