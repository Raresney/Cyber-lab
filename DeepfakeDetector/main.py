#!/usr/bin/env python3
"""
DeepfakeDetector — CLI entry point

Usage:
    python main.py <video_file> [--no-audio] [--no-face] [--weights PATH]
"""

import argparse
import sys
import time
from pathlib import Path

from detector.video_analyzer import VideoAnalyzer
from detector.audio_analyzer import AudioAnalyzer
from detector.face_analyzer import FaceAnalyzer
from detector.scorer import AuthenticityScorer
from detector.neural_models import DeepfakeClassifier, build_handcrafted_vector
from utils.video_utils import collect_frames, video_metadata, is_supported


BANNER = """
╔══════════════════════════════════════════════════════╗
║          DeepfakeDetector  v1.0                      ║
║          Biometric + Neural Analysis Pipeline        ║
╚══════════════════════════════════════════════════════╝
"""


def parse_args():
    p = argparse.ArgumentParser(
        description="Detect deepfake videos using biometric and neural analysis."
    )
    p.add_argument("input", help="Path to video file")
    p.add_argument("--no-audio", action="store_true", help="Skip audio analysis")
    p.add_argument("--no-face",  action="store_true", help="Skip face texture analysis")
    p.add_argument("--weights",  default=None,
                   help="Path to trained DeepfakeClassifier weights (.pt)")
    p.add_argument("--device",   default="cpu", choices=["cpu", "cuda"],
                   help="Inference device for neural model")
    return p.parse_args()


def bar(label: str, score: float, width: int = 30) -> str:
    filled = int(score * width)
    bar_str = "█" * filled + "░" * (width - filled)
    color = "\033[92m" if score > 0.7 else ("\033[93m" if score > 0.4 else "\033[91m")
    reset = "\033[0m"
    return f"{color}[{bar_str}]{reset} {score:.3f}"


def main():
    args = parse_args()
    print(BANNER)

    path = args.input
    if not Path(path).exists():
        print(f"[ERROR] File not found: {path}")
        sys.exit(1)
    if not is_supported(path):
        print(f"[ERROR] Unsupported format: {Path(path).suffix}")
        sys.exit(1)

    meta = video_metadata(path)
    print(f"File       : {path}")
    print(f"Resolution : {meta.get('width')}x{meta.get('height')}")
    print(f"Duration   : {meta.get('duration_sec', 0):.1f}s  "
          f"({meta.get('frame_count')} frames @ {meta.get('fps'):.1f} fps)\n")

    # ── Video biometric analysis ──────────────────────────────────────────
    print("▶ Analyzing video biometrics (eye blink, landmarks, head pose)…")
    t0 = time.time()

    def progress(cur, total):
        pct = cur / max(total, 1) * 100
        print(f"\r  Frame {cur}/{total}  ({pct:.0f}%)", end="", flush=True)

    video_analyzer = VideoAnalyzer()
    video_report = video_analyzer.analyze_video(path, progress_cb=progress)
    print(f"\r  Done in {time.time()-t0:.1f}s")
    print(f"  Blink rate : {video_report.blink_rate_per_minute:.1f}/min  "
          f"| Avg EAR : {video_report.avg_ear:.4f}  "
          f"| Jitter : {video_report.avg_landmark_jitter:.2f}px")

    # ── Audio analysis ────────────────────────────────────────────────────
    audio_report = None
    if not args.no_audio:
        print("\n▶ Analyzing audio (MFCC, spectral flux, pitch, formants)…")
        t0 = time.time()
        try:
            audio_report = AudioAnalyzer().analyze_file(path)
            print(f"  Done in {time.time()-t0:.1f}s")
            print(f"  Pitch var : {audio_report.pitch_variance:.2f}  "
                  f"| MFCC Δvar : {audio_report.mfcc_delta_variance:.2f}  "
                  f"| Formant consistency : {audio_report.formant_consistency:.3f}")
        except Exception as e:
            print(f"  [WARN] Audio analysis failed: {e}")

    # ── Face texture analysis ─────────────────────────────────────────────
    face_report = None
    if not args.no_face:
        print("\n▶ Analyzing face texture (FFT artifacts, GAN fingerprints)…")
        t0 = time.time()
        try:
            frames = collect_frames(path, max_frames=200, step=3)
            face_report = FaceAnalyzer().analyze_frames(frames, sample_every=5)
            print(f"  Done in {time.time()-t0:.1f}s")
            print(f"  FFT artifact score : {face_report.avg_fft_artifact_score:.3f}  "
                  f"| Color inconsistency : {face_report.avg_color_inconsistency:.2f}  "
                  f"| Checkerboard : {face_report.checkerboard_score:.3f}")
        except Exception as e:
            print(f"  [WARN] Face analysis failed: {e}")

    # ── Neural model inference (if weights provided) ───────────────────────
    neural_score = None
    if args.weights and Path(args.weights).exists():
        print("\n▶ Running neural classifier…")
        try:
            model = DeepfakeClassifier.load(args.weights, device=args.device)
            hc_vec = build_handcrafted_vector(video_report, audio_report, face_report)
            frames = collect_frames(path, max_frames=16, step=max(meta.get("frame_count", 100) // 16, 1))
            neural_score = model.predict_frames(frames, hc_vec, device=args.device)
            print(f"  Neural score : {neural_score:.4f}")
        except Exception as e:
            print(f"  [WARN] Neural inference failed: {e}")

    # ── Score fusion ──────────────────────────────────────────────────────
    verdict = AuthenticityScorer().score(
        video=video_report,
        audio=audio_report,
        face=face_report,
    )

    # Blend with neural score if available
    if neural_score is not None:
        verdict.score = round(0.5 * verdict.score + 0.5 * neural_score, 4)
        label_map = {
            "Authentic": verdict.score >= 0.72,
            "Deepfake":  verdict.score <= 0.42,
        }
        if verdict.score >= 0.72:
            verdict.label = "Authentic"
        elif verdict.score <= 0.42:
            verdict.label = "Deepfake"
        else:
            verdict.label = "Suspicious"

    # ── Output ────────────────────────────────────────────────────────────
    print("\n" + "─" * 56)
    print("  ANALYSIS RESULTS")
    print("─" * 56)

    if video_report:
        print(f"  Video biometrics : {bar('video', video_report.score)}")
    if face_report:
        print(f"  Face texture     : {bar('face', face_report.score)}")
    if audio_report:
        print(f"  Audio acoustic   : {bar('audio', audio_report.score)}")
    if neural_score is not None:
        print(f"  Neural model     : {bar('neural', neural_score)}")

    print(f"\n  OVERALL SCORE    : {bar('total', verdict.score)}")
    print(f"  VERDICT          : {verdict.label}  (confidence {verdict.confidence:.0%})")

    if verdict.flags:
        print("\n  Flags detected:")
        for flag in verdict.flags:
            print(f"    ⚑  {flag}")

    print("─" * 56)
    sys.exit(0 if not verdict.is_deepfake else 1)


if __name__ == "__main__":
    main()
