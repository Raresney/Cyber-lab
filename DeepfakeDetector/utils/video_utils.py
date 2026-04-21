"""Utility helpers for video frame extraction and preprocessing."""

import cv2
import numpy as np
from pathlib import Path
from typing import Generator


def iter_frames(path: str, step: int = 1) -> Generator[np.ndarray, None, None]:
    """Yield BGR frames from a video file every `step` frames."""
    cap = cv2.VideoCapture(path)
    if not cap.isOpened():
        raise FileNotFoundError(f"Cannot open: {path}")
    idx = 0
    while True:
        ok, frame = cap.read()
        if not ok:
            break
        if idx % step == 0:
            yield frame
        idx += 1
    cap.release()


def collect_frames(path: str, max_frames: int = 300, step: int = 1) -> list[np.ndarray]:
    frames = []
    for frame in iter_frames(path, step=step):
        frames.append(frame)
        if len(frames) >= max_frames:
            break
    return frames


def video_metadata(path: str) -> dict:
    cap = cv2.VideoCapture(path)
    if not cap.isOpened():
        return {}
    meta = {
        "fps": cap.get(cv2.CAP_PROP_FPS),
        "width": int(cap.get(cv2.CAP_PROP_FRAME_WIDTH)),
        "height": int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT)),
        "frame_count": int(cap.get(cv2.CAP_PROP_FRAME_COUNT)),
    }
    meta["duration_sec"] = meta["frame_count"] / max(meta["fps"], 1)
    cap.release()
    return meta


def is_supported(path: str) -> bool:
    return Path(path).suffix.lower() in {
        ".mp4", ".avi", ".mov", ".mkv", ".webm", ".flv", ".wmv"
    }
