"""
Video biometric analyzer: eye blink rate, Eye Aspect Ratio (EAR),
facial landmark jitter, and head pose consistency.
"""

import cv2
import numpy as np
import mediapipe as mp
from dataclasses import dataclass, field
from typing import Optional


# MediaPipe landmark indices for left/right eye
_LEFT_EYE  = [362, 385, 387, 263, 373, 380]
_RIGHT_EYE = [33,  160, 158, 133, 153, 144]

# Indices used for head-pose estimation (nose tip, chin, eye corners, mouth corners)
_POSE_POINTS = [1, 152, 33, 263, 61, 291]


@dataclass
class FrameMetrics:
    ear: float = 0.0
    blink_detected: bool = False
    landmark_jitter: float = 0.0
    head_yaw: float = 0.0
    head_pitch: float = 0.0
    head_roll: float = 0.0
    face_detected: bool = False


@dataclass
class VideoReport:
    total_frames: int = 0
    analyzed_frames: int = 0
    blink_count: int = 0
    avg_ear: float = 0.0
    blink_rate_per_minute: float = 0.0
    avg_landmark_jitter: float = 0.0
    ear_variance: float = 0.0
    head_pose_variance: float = 0.0
    suspicious_blink_rate: bool = False
    suspicious_jitter: bool = False
    score: float = 1.0          # 1.0 = authentic, 0.0 = deepfake
    frame_metrics: list = field(default_factory=list)

    # Normal human blink rate: 12–20 blinks/min
    BLINK_RATE_MIN = 8
    BLINK_RATE_MAX = 25

    def compute(self):
        """Derive flags and authenticity score from accumulated metrics."""
        if not self.frame_metrics:
            return

        ears = [m.ear for m in self.frame_metrics if m.face_detected]
        jitters = [m.landmark_jitter for m in self.frame_metrics if m.face_detected]
        yaws = [m.head_yaw for m in self.frame_metrics if m.face_detected]
        pitches = [m.head_pitch for m in self.frame_metrics if m.face_detected]

        if ears:
            self.avg_ear = float(np.mean(ears))
            self.ear_variance = float(np.var(ears))
        if jitters:
            self.avg_landmark_jitter = float(np.mean(jitters))
        if yaws and pitches:
            self.head_pose_variance = float(np.var(yaws) + np.var(pitches))

        self.suspicious_blink_rate = not (
            self.BLINK_RATE_MIN <= self.blink_rate_per_minute <= self.BLINK_RATE_MAX
        )
        # Deepfakes often show high jitter (>2.5 px average deviation)
        self.suspicious_jitter = self.avg_landmark_jitter > 2.5

        # Score penalties
        penalty = 0.0
        if self.suspicious_blink_rate:
            penalty += 0.30
        if self.suspicious_jitter:
            penalty += 0.25
        # Low EAR variance → eyes barely close → deepfake tell
        if self.ear_variance < 0.0003:
            penalty += 0.20
        # Very high head pose variance → unnatural movement
        if self.head_pose_variance > 400:
            penalty += 0.15

        self.score = max(0.0, 1.0 - penalty)


def _ear(landmarks, indices, w, h) -> float:
    """Eye Aspect Ratio — scalar measure of eye openness."""
    pts = np.array(
        [[landmarks[i].x * w, landmarks[i].y * h] for i in indices],
        dtype=np.float32,
    )
    # Vertical distances
    v1 = np.linalg.norm(pts[1] - pts[5])
    v2 = np.linalg.norm(pts[2] - pts[4])
    # Horizontal distance
    h1 = np.linalg.norm(pts[0] - pts[3])
    return (v1 + v2) / (2.0 * h1 + 1e-6)


def _landmark_array(landmarks, w, h) -> np.ndarray:
    return np.array([[lm.x * w, lm.y * h] for lm in landmarks], dtype=np.float32)


class VideoAnalyzer:
    """
    Frame-by-frame biometric analysis using MediaPipe Face Mesh.

    Usage:
        analyzer = VideoAnalyzer()
        report   = analyzer.analyze_video("input.mp4", progress_cb=print)
    """

    EAR_BLINK_THRESHOLD = 0.20   # EAR below this → eye is closed
    BLINK_CONSEC_FRAMES = 2      # consecutive closed frames = blink

    def __init__(self):
        self._face_mesh = mp.solutions.face_mesh.FaceMesh(
            static_image_mode=False,
            max_num_faces=1,
            refine_landmarks=True,
            min_detection_confidence=0.5,
            min_tracking_confidence=0.5,
        )
        self._blink_counter = 0   # consecutive frames below threshold
        self._prev_landmarks: Optional[np.ndarray] = None

    def analyze_video(self, path: str, progress_cb=None) -> VideoReport:
        cap = cv2.VideoCapture(path)
        if not cap.isOpened():
            raise FileNotFoundError(f"Cannot open video: {path}")

        fps = cap.get(cv2.CAP_PROP_FPS) or 25.0
        total = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        report = VideoReport(total_frames=total)

        frame_idx = 0
        while True:
            ok, frame = cap.read()
            if not ok:
                break

            metrics = self._analyze_frame(frame)
            report.frame_metrics.append(metrics)
            report.analyzed_frames += 1

            if metrics.blink_detected:
                report.blink_count += 1

            if progress_cb and frame_idx % 30 == 0:
                progress_cb(frame_idx, total)
            frame_idx += 1

        cap.release()

        duration_min = (report.analyzed_frames / fps) / 60.0
        report.blink_rate_per_minute = (
            report.blink_count / duration_min if duration_min > 0 else 0.0
        )
        report.compute()
        return report

    def _analyze_frame(self, frame: np.ndarray) -> FrameMetrics:
        h, w = frame.shape[:2]
        rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        result = self._face_mesh.process(rgb)
        metrics = FrameMetrics()

        if not result.multi_face_landmarks:
            self._prev_landmarks = None
            self._blink_counter = 0
            return metrics

        metrics.face_detected = True
        lms = result.multi_face_landmarks[0].landmark

        # EAR
        ear_l = _ear(lms, _LEFT_EYE,  w, h)
        ear_r = _ear(lms, _RIGHT_EYE, w, h)
        metrics.ear = (ear_l + ear_r) / 2.0

        # Blink detection using consecutive-frame counter
        if metrics.ear < self.EAR_BLINK_THRESHOLD:
            self._blink_counter += 1
        else:
            if self._blink_counter >= self.BLINK_CONSEC_FRAMES:
                metrics.blink_detected = True
            self._blink_counter = 0

        # Landmark jitter (mean displacement from previous frame)
        current_lms = _landmark_array(lms, w, h)
        if self._prev_landmarks is not None and len(self._prev_landmarks) == len(current_lms):
            metrics.landmark_jitter = float(
                np.mean(np.linalg.norm(current_lms - self._prev_landmarks, axis=1))
            )
        self._prev_landmarks = current_lms

        # Head pose (simplified Euler angles via solvePnP)
        metrics.head_yaw, metrics.head_pitch, metrics.head_roll = (
            self._estimate_head_pose(lms, w, h)
        )

        return metrics

    @staticmethod
    def _estimate_head_pose(landmarks, w: int, h: int):
        model_points = np.array([
            [0.0,    0.0,    0.0],    # nose tip
            [0.0,   -330.0, -65.0],   # chin
            [-225.0, 170.0, -135.0],  # left eye corner
            [225.0,  170.0, -135.0],  # right eye corner
            [-150.0, -150.0, -125.0], # left mouth corner
            [150.0,  -150.0, -125.0], # right mouth corner
        ], dtype=np.float64)

        image_points = np.array(
            [[landmarks[i].x * w, landmarks[i].y * h] for i in _POSE_POINTS],
            dtype=np.float64,
        )
        focal = w
        cam = np.array([[focal, 0, w / 2], [0, focal, h / 2], [0, 0, 1]], dtype=np.float64)
        dist = np.zeros((4, 1))

        ok, rvec, _ = cv2.solvePnP(model_points, image_points, cam, dist,
                                    flags=cv2.SOLVEPNP_ITERATIVE)
        if not ok:
            return 0.0, 0.0, 0.0

        rmat, _ = cv2.Rodrigues(rvec)
        sy = np.sqrt(rmat[0, 0] ** 2 + rmat[1, 0] ** 2)
        yaw   = float(np.degrees(np.arctan2(-rmat[2, 0], sy)))
        pitch = float(np.degrees(np.arctan2(rmat[2, 1], rmat[2, 2])))
        roll  = float(np.degrees(np.arctan2(rmat[1, 0], rmat[0, 0])))
        return yaw, pitch, roll
