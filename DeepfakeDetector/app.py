"""
Streamlit web UI for DeepfakeDetector.
Run with: streamlit run app.py
"""

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import numpy as np
import tempfile
import os
import time
from pathlib import Path

from detector.video_analyzer import VideoAnalyzer
from detector.audio_analyzer import AudioAnalyzer
from detector.face_analyzer import FaceAnalyzer
from detector.scorer import AuthenticityScorer, Verdict
from utils.video_utils import collect_frames, video_metadata

st.set_page_config(
    page_title="DeepfakeDetector",
    page_icon="🔍",
    layout="wide",
)

# ── Styling ──────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    .metric-card {
        background: #1e1e2e;
        border-radius: 12px;
        padding: 16px;
        border-left: 4px solid #7c3aed;
    }
    .verdict-authentic { color: #22c55e; font-size: 2rem; font-weight: 700; }
    .verdict-deepfake  { color: #ef4444; font-size: 2rem; font-weight: 700; }
    .verdict-suspicious{ color: #f59e0b; font-size: 2rem; font-weight: 700; }
    .flag-item { background: #2d1b1b; border-left: 3px solid #ef4444;
                 padding: 6px 12px; border-radius: 4px; margin: 4px 0; }
</style>
""", unsafe_allow_html=True)


def score_gauge(score: float, title: str) -> go.Figure:
    color = "#22c55e" if score > 0.7 else ("#f59e0b" if score > 0.4 else "#ef4444")
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score * 100,
        title={"text": title, "font": {"size": 14}},
        number={"suffix": "%", "font": {"size": 20}},
        gauge={
            "axis": {"range": [0, 100], "tickwidth": 1},
            "bar": {"color": color, "thickness": 0.3},
            "bgcolor": "#1e1e2e",
            "steps": [
                {"range": [0, 42],  "color": "#3b1b1b"},
                {"range": [42, 72], "color": "#3b3b1b"},
                {"range": [72, 100],"color": "#1b3b1b"},
            ],
            "threshold": {
                "line": {"color": color, "width": 3},
                "thickness": 0.8,
                "value": score * 100,
            },
        },
    ))
    fig.update_layout(
        height=200,
        margin=dict(l=20, r=20, t=40, b=10),
        paper_bgcolor="#0f0f1a",
        font_color="white",
    )
    return fig


def ear_timeline(frame_metrics) -> go.Figure:
    if not frame_metrics:
        return go.Figure()
    ears = [m.ear for m in frame_metrics]
    blink_frames = [i for i, m in enumerate(frame_metrics) if m.blink_detected]

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        y=ears, mode="lines", name="EAR",
        line=dict(color="#7c3aed", width=1.5),
    ))
    fig.add_hline(y=0.20, line_dash="dash", line_color="#ef4444",
                  annotation_text="Blink threshold (0.20)")
    for bf in blink_frames:
        fig.add_vline(x=bf, line_color="#22c55e", opacity=0.4, line_width=1)

    fig.update_layout(
        title="Eye Aspect Ratio (EAR) Over Time",
        xaxis_title="Frame",
        yaxis_title="EAR",
        height=280,
        paper_bgcolor="#0f0f1a",
        plot_bgcolor="#1e1e2e",
        font_color="white",
        legend=dict(bgcolor="#0f0f1a"),
    )
    return fig


def jitter_timeline(frame_metrics) -> go.Figure:
    if not frame_metrics:
        return go.Figure()
    jitters = [m.landmark_jitter for m in frame_metrics if m.landmark_jitter > 0]
    fig = go.Figure(go.Scatter(
        y=jitters, mode="lines", name="Jitter",
        line=dict(color="#f59e0b", width=1.2),
        fill="tozeroy", fillcolor="rgba(245,158,11,0.1)",
    ))
    fig.add_hline(y=2.5, line_dash="dash", line_color="#ef4444",
                  annotation_text="Suspicious threshold")
    fig.update_layout(
        title="Facial Landmark Jitter (px)",
        xaxis_title="Frame", yaxis_title="Displacement (px)",
        height=260,
        paper_bgcolor="#0f0f1a", plot_bgcolor="#1e1e2e", font_color="white",
    )
    return fig


def radar_chart(video_score, audio_score, face_score) -> go.Figure:
    scores = [
        video_score if video_score is not None else 0.5,
        audio_score if audio_score is not None else 0.5,
        face_score  if face_score  is not None else 0.5,
    ]
    categories = ["Video Biometrics", "Audio Acoustic", "Face Texture"]
    fig = go.Figure(go.Scatterpolar(
        r=scores + [scores[0]],
        theta=categories + [categories[0]],
        fill="toself",
        fillcolor="rgba(124,58,237,0.25)",
        line=dict(color="#7c3aed", width=2),
    ))
    fig.update_layout(
        polar=dict(
            bgcolor="#1e1e2e",
            radialaxis=dict(visible=True, range=[0, 1], color="white"),
            angularaxis=dict(color="white"),
        ),
        showlegend=False,
        height=300,
        paper_bgcolor="#0f0f1a",
        font_color="white",
        title="Module Score Radar",
    )
    return fig


# ── Main UI ──────────────────────────────────────────────────────────────────

st.title("🔍 DeepfakeDetector")
st.caption("Biometric + Acoustic + Neural analysis pipeline")

uploaded = st.file_uploader(
    "Upload a video file",
    type=["mp4", "avi", "mov", "mkv", "webm"],
    help="Supports MP4, AVI, MOV, MKV, WebM",
)

col_opt1, col_opt2 = st.columns(2)
with col_opt1:
    run_audio = st.checkbox("Audio analysis", value=True)
    run_face  = st.checkbox("Face texture analysis", value=True)
with col_opt2:
    max_frames = st.slider("Max frames to analyze", 60, 600, 300, step=30)

if uploaded and st.button("▶ Analyze", type="primary", use_container_width=True):
    with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as tmp:
        tmp.write(uploaded.read())
        tmp_path = tmp.name

    try:
        meta = video_metadata(tmp_path)
        st.info(
            f"**{uploaded.name}** — "
            f"{meta.get('width')}×{meta.get('height')} "
            f"@ {meta.get('fps', 0):.1f} fps — "
            f"{meta.get('duration_sec', 0):.1f}s"
        )

        video_report = audio_report = face_report = None

        # ── Video ────────────────────────────────────────────────────────
        with st.spinner("Analyzing video biometrics…"):
            video_report = VideoAnalyzer().analyze_video(tmp_path)

        # ── Audio ────────────────────────────────────────────────────────
        if run_audio:
            with st.spinner("Analyzing audio…"):
                try:
                    audio_report = AudioAnalyzer().analyze_file(tmp_path)
                except Exception as e:
                    st.warning(f"Audio analysis skipped: {e}")

        # ── Face texture ─────────────────────────────────────────────────
        if run_face:
            with st.spinner("Analyzing face texture / GAN artifacts…"):
                try:
                    frames = collect_frames(tmp_path, max_frames=max_frames, step=3)
                    face_report = FaceAnalyzer().analyze_frames(frames, sample_every=5)
                except Exception as e:
                    st.warning(f"Face texture analysis skipped: {e}")

        # ── Verdict ───────────────────────────────────────────────────────
        verdict = AuthenticityScorer().score(
            video=video_report,
            audio=audio_report,
            face=face_report,
        )

        # ── VERDICT HEADER ────────────────────────────────────────────────
        st.divider()
        vcls = verdict.label.lower()
        st.markdown(
            f"<div class='verdict-{vcls}'>{'✅' if vcls=='authentic' else ('❌' if vcls=='deepfake' else '⚠️')} "
            f"{verdict.label}</div>",
            unsafe_allow_html=True,
        )
        st.markdown(f"**Overall Authenticity Score:** `{verdict.score:.3f}` "
                    f"— Confidence: `{verdict.confidence:.0%}`")

        # ── GAUGE CHARTS ─────────────────────────────────────────────────
        cols = st.columns(3)
        with cols[0]:
            st.plotly_chart(
                score_gauge(video_report.score if video_report else 0.5, "Video"),
                use_container_width=True,
            )
        with cols[1]:
            st.plotly_chart(
                score_gauge(audio_report.score if audio_report else 0.5, "Audio"),
                use_container_width=True,
            )
        with cols[2]:
            st.plotly_chart(
                score_gauge(face_report.score if face_report else 0.5, "Face Texture"),
                use_container_width=True,
            )

        # ── FLAGS ─────────────────────────────────────────────────────────
        if verdict.flags:
            st.subheader("⚑ Suspicious Signals")
            for flag in verdict.flags:
                st.markdown(
                    f"<div class='flag-item'>⚑ {flag}</div>",
                    unsafe_allow_html=True,
                )

        # ── CHARTS ────────────────────────────────────────────────────────
        st.divider()
        st.subheader("Biometric Timeline")

        tab_ear, tab_jitter, tab_radar = st.tabs(
            ["EAR / Blink", "Landmark Jitter", "Score Radar"]
        )
        with tab_ear:
            if video_report:
                st.plotly_chart(
                    ear_timeline(video_report.frame_metrics),
                    use_container_width=True,
                )
                c1, c2, c3 = st.columns(3)
                c1.metric("Blink count", video_report.blink_count)
                c2.metric("Blink rate /min",
                          f"{video_report.blink_rate_per_minute:.1f}",
                          delta="Normal: 8–25",
                          delta_color="off")
                c3.metric("Avg EAR", f"{video_report.avg_ear:.4f}")

        with tab_jitter:
            if video_report:
                st.plotly_chart(
                    jitter_timeline(video_report.frame_metrics),
                    use_container_width=True,
                )
                st.metric("Avg landmark jitter (px)",
                          f"{video_report.avg_landmark_jitter:.2f}",
                          delta=">2.5 suspicious", delta_color="off")

        with tab_radar:
            st.plotly_chart(
                radar_chart(
                    verdict.video_score,
                    verdict.audio_score,
                    verdict.face_score,
                ),
                use_container_width=True,
            )

        # ── AUDIO DETAILS ─────────────────────────────────────────────────
        if audio_report:
            st.subheader("Audio Details")
            a1, a2, a3, a4 = st.columns(4)
            a1.metric("Pitch variance",     f"{audio_report.pitch_variance:.2f}")
            a2.metric("MFCC Δ variance",    f"{audio_report.mfcc_delta_variance:.2f}")
            a3.metric("Formant consistency",f"{audio_report.formant_consistency:.3f}")
            a4.metric("Silence ratio",      f"{audio_report.silence_ratio:.2%}")

    finally:
        os.unlink(tmp_path)
