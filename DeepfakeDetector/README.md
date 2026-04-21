# DeepfakeDetector

Real-time deepfake detection pipeline combining biometric analysis, acoustic fingerprinting, and a deep neural network classifier.

## Architecture

```
Input Video/Audio
       │
       ├── VideoAnalyzer     ← Eye blink rate, EAR, landmark jitter, head pose
       ├── AudioAnalyzer     ← MFCC delta, spectral flux, pitch variance, formants
       ├── FaceAnalyzer      ← FFT artifacts, color inconsistency, GAN checkerboard
       └── DeepfakeClassifier ← EfficientNet-B0 + Bi-LSTM + handcrafted features
                │
         AuthenticityScorer  ← Weighted fusion → final verdict [0.0–1.0]
```

## Detection Methods

| Module | Signals Analyzed | Deepfake Tell |
|--------|-----------------|---------------|
| **Video** | Eye Aspect Ratio (EAR), blink frequency, facial landmark displacement, head pose (PnP) | Reduced blink rate (<8 or >25/min), high jitter, low EAR variance |
| **Audio** | MFCC delta variance, spectral flux, pitch F0, LPC formants | High MFCC Δvar (voice cloning), low pitch variance (TTS), unstable formants |
| **Face** | DCT/FFT frequency spectrum, color channel deviation, transpose-conv checkerboard | Periodic HF peaks in FFT, color bleed at face boundary |
| **Neural** | EfficientNet-B0 spatial features + Bi-LSTM temporal modeling | Learned GAN artifact patterns from FaceForensics++ |

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# CLI — analyze a video
python main.py video.mp4

# CLI — with trained weights
python main.py video.mp4 --weights models/best_model.pt --device cuda

# Web UI
streamlit run app.py
```

## Training

```bash
# Prepare FaceForensics++ dataset:
# https://github.com/ondyari/FaceForensics
#
# Structure:
#   data/
#     real/   ← c23/videos from original_sequences/
#     fake/   ← c23/videos from manipulated_sequences/

python train.py --data ./data --epochs 30 --batch 8 --device cuda
```

Best reported accuracy on FF++ (c23 compression): **~96%** with full pipeline.

## Scoring

| Score | Verdict |
|-------|---------|
| ≥ 0.72 | ✅ Authentic |
| 0.42 – 0.72 | ⚠️ Suspicious |
| ≤ 0.42 | ❌ Deepfake |

## Dependencies

- **MediaPipe** — Face Mesh & landmark detection
- **OpenCV** — Frame extraction, solvePnP head pose
- **librosa** — MFCC, spectral flux, YIN pitch, LPC formants
- **PyTorch + EfficientNet** — Spatial feature extraction
- **Streamlit + Plotly** — Interactive web dashboard

## Limitations

- The neural classifier requires training on labeled data (FaceForensics++ recommended).
  Without weights, the system uses only biometric/acoustic heuristics.
- Performance degrades on heavily compressed video (high CRF).
- Requires a visible face; audio-only deepfakes need `--no-face`.

## References

- Rossler et al. — [FaceForensics++](https://arxiv.org/abs/1901.08971)
- Solaiyappan et al. — Eye blink analysis for liveness detection
- Li et al. — [Exposing DeepFake Videos by Detecting Face Warping Artifacts](https://arxiv.org/abs/1811.00656)
- Tan & Le — [EfficientNet](https://arxiv.org/abs/1905.11946)
