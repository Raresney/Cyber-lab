"""
Neural network architecture for deepfake classification.

Architecture:
- EfficientNet-B0 backbone (pretrained on ImageNet) for spatial features
- Bi-LSTM for temporal sequence modeling across frames
- Fusion head combining spatial + temporal + handcrafted features
- Output: authenticity probability [0, 1]

Training dataset recommendation: FaceForensics++ (FF++)
  https://github.com/ondyari/FaceForensics
"""

import torch
import torch.nn as nn
import torchvision.models as models
import torchvision.transforms as T
import numpy as np
import cv2
from pathlib import Path
from typing import Optional


# ─── Transforms ──────────────────────────────────────────────────────────────

FACE_TRANSFORM = T.Compose([
    T.ToPILImage(),
    T.Resize((224, 224)),
    T.ToTensor(),
    T.Normalize(mean=[0.485, 0.456, 0.406],
                std=[0.229, 0.224, 0.225]),
])


# ─── Models ──────────────────────────────────────────────────────────────────

class SpatialEncoder(nn.Module):
    """EfficientNet-B0 backbone stripped of classification head."""

    FEATURE_DIM = 1280

    def __init__(self, pretrained: bool = True):
        super().__init__()
        weights = models.EfficientNet_B0_Weights.DEFAULT if pretrained else None
        backbone = models.efficientnet_b0(weights=weights)
        # Remove classifier, keep feature extractor + avgpool
        self.features = backbone.features
        self.pool = backbone.avgpool

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: (B, 3, 224, 224)
        x = self.features(x)
        x = self.pool(x)
        return x.flatten(1)           # (B, 1280)


class TemporalEncoder(nn.Module):
    """Bi-LSTM that captures temporal inconsistencies across a sequence of frames."""

    def __init__(self, input_dim: int = 1280, hidden_dim: int = 256, num_layers: int = 2):
        super().__init__()
        self.lstm = nn.LSTM(
            input_size=input_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            bidirectional=True,
            dropout=0.3,
        )
        self.out_dim = hidden_dim * 2   # bidirectional

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: (B, T, 1280)
        out, _ = self.lstm(x)
        # Mean-pool over time
        return out.mean(dim=1)          # (B, hidden*2)


class FusionHead(nn.Module):
    """Combines spatial, temporal, and handcrafted feature vectors."""

    def __init__(self, spatial_dim: int, temporal_dim: int, handcrafted_dim: int):
        super().__init__()
        total = spatial_dim + temporal_dim + handcrafted_dim
        self.net = nn.Sequential(
            nn.Linear(total, 256),
            nn.BatchNorm1d(256),
            nn.GELU(),
            nn.Dropout(0.4),
            nn.Linear(256, 64),
            nn.GELU(),
            nn.Dropout(0.3),
            nn.Linear(64, 1),
            nn.Sigmoid(),
        )

    def forward(self, spatial: torch.Tensor,
                temporal: torch.Tensor,
                handcrafted: torch.Tensor) -> torch.Tensor:
        x = torch.cat([spatial, temporal, handcrafted], dim=1)
        return self.net(x).squeeze(1)   # (B,)  → authenticity score


class DeepfakeClassifier(nn.Module):
    """
    Full deepfake detection model.

    Input:
        frames        : (B, T, 3, 224, 224) — sequence of face crops
        handcrafted   : (B, D) — biometric features (EAR, jitter, audio MFCCs …)

    Output:
        score         : (B,) float in [0, 1]  — 1 = authentic, 0 = deepfake
    """

    HANDCRAFTED_DIM = 16

    def __init__(self, pretrained_backbone: bool = True):
        super().__init__()
        self.spatial = SpatialEncoder(pretrained=pretrained_backbone)
        self.temporal = TemporalEncoder(
            input_dim=self.spatial.FEATURE_DIM,
            hidden_dim=256,
        )
        self.fusion = FusionHead(
            spatial_dim=self.spatial.FEATURE_DIM,
            temporal_dim=self.temporal.out_dim,
            handcrafted_dim=self.HANDCRAFTED_DIM,
        )

    def forward(self, frames: torch.Tensor,
                handcrafted: torch.Tensor) -> torch.Tensor:
        B, T, C, H, W = frames.shape
        # Encode each frame spatially
        frames_flat = frames.view(B * T, C, H, W)
        spatial_flat = self.spatial(frames_flat)        # (B*T, 1280)
        spatial_seq = spatial_flat.view(B, T, -1)       # (B, T, 1280)

        # Temporal encoding
        temporal_feat = self.temporal(spatial_seq)      # (B, 512)

        # Global spatial (mean over time)
        spatial_feat = spatial_seq.mean(dim=1)          # (B, 1280)

        return self.fusion(spatial_feat, temporal_feat, handcrafted)

    # ── Inference helpers ──────────────────────────────────────────────────

    @classmethod
    def load(cls, weights_path: str, device: str = "cpu") -> "DeepfakeClassifier":
        model = cls(pretrained_backbone=False)
        state = torch.load(weights_path, map_location=device)
        model.load_state_dict(state)
        model.eval()
        return model

    def predict_frames(self,
                       face_frames: list[np.ndarray],
                       handcrafted_vec: np.ndarray,
                       device: str = "cpu") -> float:
        """
        Convenience method for inference on a list of BGR face crops.
        Returns float in [0, 1] (1 = authentic).
        """
        if not face_frames:
            return 0.5

        tensors = torch.stack([FACE_TRANSFORM(f) for f in face_frames])  # (T,3,224,224)
        tensors = tensors.unsqueeze(0).to(device)                          # (1,T,…)
        hc = torch.tensor(handcrafted_vec, dtype=torch.float32).unsqueeze(0).to(device)

        with torch.no_grad():
            score = self(tensors, hc)
        return float(score.item())

    def save(self, path: str):
        torch.save(self.state_dict(), path)


# ─── Handcrafted feature builder ─────────────────────────────────────────────

def build_handcrafted_vector(video_report, audio_report, face_report) -> np.ndarray:
    """
    Packs all biometric/acoustic metrics into a fixed-length vector
    for the fusion head.  Dimension must equal DeepfakeClassifier.HANDCRAFTED_DIM.
    """
    def safe(val, default=0.0):
        try:
            return float(val) if val is not None else default
        except Exception:
            return default

    vec = np.array([
        # Video biometrics (6)
        safe(getattr(video_report, "avg_ear", None)),
        safe(getattr(video_report, "ear_variance", None)),
        safe(getattr(video_report, "blink_rate_per_minute", None)) / 30.0,
        safe(getattr(video_report, "avg_landmark_jitter", None)) / 10.0,
        safe(getattr(video_report, "head_pose_variance", None)) / 500.0,
        float(getattr(video_report, "suspicious_blink_rate", False)),

        # Audio acoustics (5)
        safe(getattr(audio_report, "mfcc_delta_variance", None)) / 20.0,
        safe(getattr(audio_report, "spectral_flux_mean", None)),
        safe(getattr(audio_report, "pitch_variance", None)) / 200.0,
        safe(getattr(audio_report, "formant_consistency", None)),
        safe(getattr(audio_report, "silence_ratio", None)),

        # Face texture (5)
        safe(getattr(face_report, "avg_fft_artifact_score", None)),
        safe(getattr(face_report, "avg_color_inconsistency", None)) / 20.0,
        safe(getattr(face_report, "avg_noise_variance", None)) / 1000.0,
        safe(getattr(face_report, "checkerboard_score", None)),
        safe(getattr(face_report, "score", None)),
    ], dtype=np.float32)

    assert len(vec) == DeepfakeClassifier.HANDCRAFTED_DIM, \
        f"Expected {DeepfakeClassifier.HANDCRAFTED_DIM} features, got {len(vec)}"

    return np.clip(vec, 0.0, 2.0)   # clamp outliers
