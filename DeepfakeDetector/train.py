"""
Training script for DeepfakeClassifier.

Dataset: FaceForensics++ (FF++)
    https://github.com/ondyari/FaceForensics

Expected directory layout:
    data/
      real/        ← original video clips
      fake/        ← manipulated video clips (DeepFakes, Face2Face, FaceSwap, NeuralTextures)

Usage:
    python train.py --data ./data --epochs 30 --batch 16 --device cuda
"""

import argparse
import os
import random
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader, random_split
import torchvision.transforms as T
from tqdm import tqdm

from detector.neural_models import DeepfakeClassifier, FACE_TRANSFORM
from detector.video_analyzer import VideoAnalyzer, VideoReport
from detector.audio_analyzer import AudioAnalyzer, AudioReport
from detector.face_analyzer import FaceAnalyzer, FaceTextureReport
from detector.neural_models import build_handcrafted_vector
from utils.video_utils import collect_frames


SEED = 42
random.seed(SEED); np.random.seed(SEED); torch.manual_seed(SEED)


# ── Dataset ──────────────────────────────────────────────────────────────────

class DeepfakeDataset(Dataset):
    """
    Loads (frames_tensor, handcrafted_vector, label) triplets.
    label=1.0 → authentic, label=0.0 → deepfake
    """

    FRAMES_PER_CLIP = 16
    CACHE_DIR = Path(".cache/features")

    def __init__(self, data_dir: str, augment: bool = False):
        self.samples = []   # list of (path, label)
        self.augment = augment

        for label_str, label_val in [("real", 1.0), ("fake", 0.0)]:
            folder = Path(data_dir) / label_str
            if not folder.exists():
                continue
            for ext in ("*.mp4", "*.avi", "*.mov"):
                for p in folder.glob(ext):
                    self.samples.append((str(p), label_val))

        random.shuffle(self.samples)
        self.CACHE_DIR.mkdir(parents=True, exist_ok=True)

        self._v_analyzer = VideoAnalyzer()
        self._a_analyzer = AudioAnalyzer()
        self._f_analyzer = FaceAnalyzer()

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        path, label = self.samples[idx]
        cache_key = self.CACHE_DIR / (Path(path).stem + ".pt")

        if cache_key.exists():
            data = torch.load(cache_key, weights_only=True)
            return data["frames"], data["hc"], torch.tensor(label)

        # Extract features
        frames_bgr = collect_frames(path, max_frames=self.FRAMES_PER_CLIP * 3,
                                    step=3)[:self.FRAMES_PER_CLIP]

        frame_tensors = torch.stack(
            [FACE_TRANSFORM(f) for f in frames_bgr] +
            # Pad if fewer frames
            [FACE_TRANSFORM(frames_bgr[-1])] * max(0, self.FRAMES_PER_CLIP - len(frames_bgr))
        )  # (T, 3, 224, 224)

        try:
            vr = self._v_analyzer.analyze_video(path)
        except Exception:
            vr = VideoReport()

        try:
            ar = self._a_analyzer.analyze_file(path)
        except Exception:
            ar = AudioReport()

        try:
            fr = self._f_analyzer.analyze_frames(frames_bgr, sample_every=2)
        except Exception:
            fr = FaceTextureReport()

        hc = torch.tensor(build_handcrafted_vector(vr, ar, fr), dtype=torch.float32)

        torch.save({"frames": frame_tensors, "hc": hc}, cache_key)
        return frame_tensors, hc, torch.tensor(label)


# ── Training loop ─────────────────────────────────────────────────────────────

def train(args):
    device = torch.device(args.device)
    dataset = DeepfakeDataset(args.data, augment=True)

    n_val = max(1, int(len(dataset) * 0.15))
    n_train = len(dataset) - n_val
    train_ds, val_ds = random_split(dataset, [n_train, n_val])

    train_dl = DataLoader(train_ds, batch_size=args.batch, shuffle=True,
                          num_workers=args.workers, pin_memory=True)
    val_dl   = DataLoader(val_ds,   batch_size=args.batch, shuffle=False,
                          num_workers=args.workers)

    model = DeepfakeClassifier(pretrained_backbone=True).to(device)
    optimizer = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(
        optimizer, T_max=args.epochs
    )
    criterion = nn.BCELoss()

    best_val_acc = 0.0
    os.makedirs(args.out, exist_ok=True)

    for epoch in range(1, args.epochs + 1):
        # ── Train ────────────────────────────────────────────────────────
        model.train()
        train_loss = train_correct = train_total = 0

        for frames, hc, labels in tqdm(train_dl, desc=f"Epoch {epoch}/{args.epochs}"):
            frames = frames.to(device)
            hc     = hc.to(device)
            labels = labels.float().to(device)

            optimizer.zero_grad()
            preds = model(frames, hc)
            loss = criterion(preds, labels)
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()

            train_loss    += loss.item() * len(labels)
            train_correct += ((preds >= 0.5).float() == labels).sum().item()
            train_total   += len(labels)

        scheduler.step()

        # ── Validate ─────────────────────────────────────────────────────
        model.eval()
        val_correct = val_total = 0
        with torch.no_grad():
            for frames, hc, labels in val_dl:
                frames = frames.to(device)
                hc     = hc.to(device)
                labels = labels.float().to(device)
                preds  = model(frames, hc)
                val_correct += ((preds >= 0.5).float() == labels).sum().item()
                val_total   += len(labels)

        val_acc   = val_correct / max(val_total, 1)
        train_acc = train_correct / max(train_total, 1)
        print(f"  Loss: {train_loss/train_total:.4f}  "
              f"Train acc: {train_acc:.3f}  Val acc: {val_acc:.3f}")

        if val_acc > best_val_acc:
            best_val_acc = val_acc
            ckpt = os.path.join(args.out, "best_model.pt")
            model.save(ckpt)
            print(f"  ✔ Saved best model → {ckpt}  (val acc {val_acc:.3f})")

    print(f"\nTraining complete. Best val accuracy: {best_val_acc:.3f}")


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--data",    required=True,  help="Dataset root (real/ fake/ subdirs)")
    p.add_argument("--epochs",  type=int,   default=30)
    p.add_argument("--batch",   type=int,   default=8)
    p.add_argument("--lr",      type=float, default=1e-4)
    p.add_argument("--workers", type=int,   default=2)
    p.add_argument("--device",  default="cuda" if torch.cuda.is_available() else "cpu")
    p.add_argument("--out",     default="models/",  help="Checkpoint output directory")
    return p.parse_args()


if __name__ == "__main__":
    train(parse_args())
