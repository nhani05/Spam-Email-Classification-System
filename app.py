
"""
Spam Email Classifier — Streamlit Application
==============================================

Access rules
------------
* **Guest** (not logged in): Single Email tab only.
* **Authenticated user**: Single Email + Batch MBOX Processing + History.
"""

import os
import tempfile
import time

import streamlit as st

# ── Pipeline ──────────────────────────────────────────────────────────────
from src.pipeline.prediction_pipeline import PredictionPipeline

# ── Auth / DB ─────────────────────────────────────────────────────────────
from src.auth.auth import (
    AuthError,
    login_user,
    register_user,
    save_single_prediction,
    save_batch_prediction,
    get_single_history,
    get_batch_history,
)
from src.database.db import ping as db_ping
from src.components.dashboard import show_dashboard
from src.security import EmailThreatAnalyzer, QRImageAnalyzer

# ══════════════════════════════════════════════════════════════════════════
# Page configuration
# ══════════════════════════════════════════════════════════════════════════
st.set_page_config(
    page_title="Spam Email Classifier",
    page_icon="📧",
    layout="centered",
)

# ══════════════════════════════════════════════════════════════════════════
# Session-state initialisation
# ══════════════════════════════════════════════════════════════════════════
_SESSION_DEFAULTS = {
    "logged_in":  False,
    "user_id":    None,
    "username":   None,
    "auth_page":  "login",   # "login" | "register"
    "db_ok":      None,      # None = unchecked
}
for key, default in _SESSION_DEFAULTS.items():
    if key not in st.session_state:
        st.session_state[key] = default

# ══════════════════════════════════════════════════════════════════════════
# ML Pipeline (cached)
# ══════════════════════════════════════════════════════════════════════════
@st.cache_resource
def get_pipeline() -> PredictionPipeline:
    return PredictionPipeline(load_models=True)


@st.cache_resource
def get_qr_analyzer() -> QRImageAnalyzer:
    return QRImageAnalyzer()


@st.cache_resource
def get_email_threat_analyzer() -> EmailThreatAnalyzer:
    return EmailThreatAnalyzer()


try:
    pipeline = get_pipeline()
except Exception as exc:
    st.error(f"❌ Không thể tải mô hình ML: {exc}")
    st.stop()


# ══════════════════════════════════════════════════════════════════════════
# Database connectivity check (lazy, once per session)
# ══════════════════════════════════════════════════════════════════════════
def check_db() -> bool:
    if st.session_state["db_ok"] is None:
        st.session_state["db_ok"] = db_ping()
    return st.session_state["db_ok"]


# ══════════════════════════════════════════════════════════════════════════
# Sidebar — auth controls
# ══════════════════════════════════════════════════════════════════════════
def _sidebar_auth() -> None:
    st.sidebar.title("👤 Tài khoản")

    if st.session_state["logged_in"]:
        st.sidebar.success(f"Xin chào, **{st.session_state['username']}**!")
        if st.sidebar.button("🚪 Đăng xuất", use_container_width=True):
            for key in ("logged_in", "user_id", "username"):
                st.session_state[key] = _SESSION_DEFAULTS[key]
            st.rerun()
        return

    # ── DB not reachable ──────────────────────────────────────────────────
    if not check_db():
        st.sidebar.warning(
            "⚠️ Không thể kết nối đến cơ sở dữ liệu.\n\n"
            "Kiểm tra biến môi trường `DB_HOST`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`."
        )
        st.sidebar.info("Bạn vẫn có thể kiểm tra email đơn mà không cần đăng nhập.")
        return

    # ── Toggle login / register ───────────────────────────────────────────
    col_l, col_r = st.sidebar.columns(2)
    if col_l.button("Đăng nhập", use_container_width=True,
                    type="primary" if st.session_state["auth_page"] == "login" else "secondary"):
        st.session_state["auth_page"] = "login"
    if col_r.button("Đăng ký", use_container_width=True,
                    type="primary" if st.session_state["auth_page"] == "register" else "secondary"):
        st.session_state["auth_page"] = "register"

    st.sidebar.divider()

    if st.session_state["auth_page"] == "login":
        _sidebar_login_form()
    else:
        _sidebar_register_form()


def _sidebar_login_form() -> None:
    st.sidebar.subheader("🔑 Đăng nhập")
    with st.sidebar.form("login_form", clear_on_submit=False):
        username = st.text_input("Tên đăng nhập", max_chars=12)
        password = st.text_input("Mật khẩu", type="password")
        submitted = st.form_submit_button("Đăng nhập", use_container_width=True)

    if submitted:
        if not username or not password:
            st.sidebar.error("Vui lòng điền đầy đủ thông tin.")
            return
        try:
            user = login_user(username, password)
            st.session_state.update({
                "logged_in": True,
                "user_id":   user["id"],
                "username":  user["username"],
            })
            st.sidebar.success("Đăng nhập thành công!")
            st.rerun()
        except AuthError as exc:
            st.sidebar.error(str(exc))
        except Exception as exc:
            st.sidebar.error(f"Lỗi kết nối: {exc}")


def _sidebar_register_form() -> None:
    st.sidebar.subheader("📝 Đăng ký")
    with st.sidebar.form("register_form", clear_on_submit=True):
        username = st.text_input("Tên đăng nhập (tối đa 12 ký tự)", max_chars=12)
        password = st.text_input("Mật khẩu", type="password")
        confirm  = st.text_input("Xác nhận mật khẩu", type="password", max_chars=12)
        submitted = st.form_submit_button("Tạo tài khoản", use_container_width=True)

    if submitted:
        if not username or not password:
            st.sidebar.error("Vui lòng điền đầy đủ thông tin.")
            return
        if password != confirm:
            st.sidebar.error("Mật khẩu xác nhận không khớp.")
            return
        try:
            user = register_user(username, password)
            st.sidebar.success(
                f"✅ Tạo tài khoản **{user['username']}** thành công! "
                "Vui lòng đăng nhập."
            )
            st.session_state["auth_page"] = "login"
            st.rerun()
        except AuthError as exc:
            st.sidebar.error(str(exc))
        except Exception as exc:
            st.sidebar.error(f"Lỗi kết nối: {exc}")


# ══════════════════════════════════════════════════════════════════════════
# Main tabs
# ══════════════════════════════════════════════════════════════════════════
def _tab_single_email() -> None:
    """Single email classification — available to all users."""
    st.header("📨 Kiểm tra Email Đơn")

    if not st.session_state["logged_in"]:
        st.info(
            "💡 Bạn đang dùng chế độ **khách**. "
            "Kết quả sẽ **không được lưu**. "
            "Đăng nhập để lưu lịch sử kiểm tra."
        )

    email_text = st.text_area(
        "Dán nội dung email vào đây:",
        height=200,
        placeholder="Dear friend, I have a business proposal...",
    )

    if st.button("🔍 Phân loại Email", type="primary"):
        if not email_text.strip():
            st.warning("Vui lòng nhập nội dung email.")
            return

        with st.spinner("Đang phân tích..."):
            try:
                result = pipeline.predict_single_email(email_text)
                threat_result = get_email_threat_analyzer().analyze(email_text)
                prediction = result["prediction"]
                confidence = result.get("confidence")

                # ── Result card ─────────────────────────────────────────
                if prediction == "Spam":
                    st.error("🚨 Email này là **SPAM**")
                else:
                    st.success("✅ Email này là **HAM** (An toàn)")

                if confidence:
                    st.metric("Độ tin cậy", f"{confidence:.1f}%")

                st.subheader("Threat Detection")
                threat_cols = st.columns(4)
                threat_cols[0].metric("Overall risk", threat_result.risk_score)
                threat_cols[1].metric("Phishing", threat_result.phishing_score)
                threat_cols[2].metric("Fake link", threat_result.fake_link_score)
                threat_cols[3].metric("Malware", threat_result.malware_score)

                if threat_result.risk_score >= 80:
                    st.error(f"Threat verdict: {threat_result.verdict} ({threat_result.risk_level})")
                elif threat_result.risk_score >= 35:
                    st.warning(f"Threat verdict: {threat_result.verdict} ({threat_result.risk_level})")
                else:
                    st.success(f"Threat verdict: {threat_result.verdict} ({threat_result.risk_level})")

                with st.expander("Why this result?", expanded=threat_result.risk_score >= 35):
                    for reason in threat_result.reasons:
                        st.write(f"- {reason}")

                    if threat_result.risky_files:
                        st.write("Risky file indicators:")
                        for filename in threat_result.risky_files:
                            st.code(filename, language="text")

                    if threat_result.urls:
                        st.write("Detected links:")
                        for url_info in threat_result.urls:
                            st.write(
                                f"- `{url_info['verdict']}` | score `{url_info['risk_score']}` | "
                                f"domain `{url_info['domain'] or 'N/A'}`"
                            )
                            st.code(url_info["url"], language="text")

                # ── Save if logged in ───────────────────────────────────
                if st.session_state["logged_in"] and check_db():
                    try:
                        save_single_prediction(
                            user_id=st.session_state["user_id"],
                            email_content=email_text,
                            prediction=prediction,
                            confidence=confidence,
                        )
                        st.caption("✔ Đã lưu vào lịch sử.")
                    except Exception as exc:
                        st.caption(f"⚠ Không thể lưu lịch sử: {exc}")

            except Exception as exc:
                st.error(f"Lỗi phân tích: {exc}")


def _tab_batch() -> None:
    """Batch MBOX processing — authenticated users only."""
    st.header("📦 Xử lý File MBOX")

    # ── Gate: must be logged in ───────────────────────────────────────────
    if not st.session_state["logged_in"]:
        st.warning(
            "🔒 **Chức năng này yêu cầu đăng nhập.**\n\n"
            "Vui lòng đăng nhập hoặc đăng ký tài khoản ở thanh bên trái."
        )
        return

    uploaded_file = st.file_uploader(
        "Tải lên file MBOX", type=["mbox", "txt"]
    )

    if uploaded_file is not None and st.button("⚙️ Xử lý File", type="primary"):
        with st.spinner("Đang xử lý file... vui lòng chờ"):
            try:
                with tempfile.NamedTemporaryFile(
                    delete=False, suffix=".mbox"
                ) as tmp:
                    tmp.write(uploaded_file.getvalue())
                    tmp_path = tmp.name

                try:
                    df = pipeline.predict_mbox_file(tmp_path)
                    st.write("Columns:", df.columns.tolist())  # thêm tạm để kiểm tra

                    spam_count = len(df[df['Prediction'] == 'Spam'])
                    ham_count = len(df[df['Prediction'] == 'Ham'])

                    # ── Metrics ─────────────────────────────────────────
                    col1, col2, col3 = st.columns(3)
                    col1.metric("📧 Tổng email",  len(df))
                    col2.metric("🚨 Spam",         spam_count)
                    col3.metric("✅ Ham",           ham_count)

                    st.subheader("Kết quả mẫu (10 email đầu)")
                    st.dataframe(
                        df[["Time", "Subject", "Prediction"]].head(10),
                        use_container_width=True,
                    )

                    # ── Download ─────────────────────────────────────────
                    csv = df.to_csv(index=False).encode("utf-8")
                    st.download_button(
                        "⬇️ Tải xuống kết quả (CSV)",
                        data=csv,
                        file_name=f"predictions_{int(time.time())}.csv",
                        mime="text/csv",
                    )

                    # ── Save summary ──────────────────────────────────────
                    if check_db():
                        try:
                            save_batch_prediction(
                                user_id=st.session_state["user_id"],
                                file_name=uploaded_file.name,
                                total_emails=len(df),
                                spam_count=spam_count,
                                ham_count=ham_count,
                            )
                            st.caption("✔ Đã lưu thống kê vào lịch sử.")
                        except Exception as exc:
                            st.caption(f"⚠ Không thể lưu lịch sử: {exc}")

                finally:
                    if os.path.exists(tmp_path):
                        try:
                            os.unlink(tmp_path)
                        except OSError:
                            pass

            except Exception as exc:
                st.error(f"Lỗi xử lý file: {exc}")


def _tab_qr_image_security() -> None:
    """Analyze QR codes embedded in suspicious email images."""
    st.header("QR Image Threat Detection")
    st.caption(
        "Upload an email image, receipt screenshot, or QR payment image. "
        "The system extracts QR URLs and scores phishing risk without opening the link."
    )

    uploaded_image = st.file_uploader(
        "Upload image",
        type=["png", "jpg", "jpeg", "webp", "bmp"],
        key="qr_image_upload",
    )

    if uploaded_image is None:
        return

    image_bytes = uploaded_image.getvalue()
    st.image(image_bytes, caption=uploaded_image.name, use_container_width=True)

    if not st.button("Analyze QR image", type="primary"):
        return

    analyzer = get_qr_analyzer()
    with st.spinner("Analyzing QR image..."):
        try:
            result = analyzer.analyze_image_bytes(image_bytes)
        except Exception as exc:
            st.error(f"Could not analyze image: {exc}")
            return

    if result.warnings:
        for warning in result.warnings:
            st.warning(warning)

    col1, col2, col3 = st.columns(3)
    col1.metric("QR found", result.qr_count)
    col2.metric("Risk score", result.max_risk_score)
    col3.metric("Risk level", result.risk_level)

    if not result.qr_found:
        st.info("No QR code was detected in this image.")
        return

    if result.max_risk_score >= 80:
        st.error(f"Final verdict: {result.final_verdict}")
    elif result.max_risk_score >= 35:
        st.warning(f"Final verdict: {result.final_verdict}")
    else:
        st.success(f"Final verdict: {result.final_verdict}")

    st.subheader("Detected QR links")
    for index, qr_result in enumerate(result.qr_results, start=1):
        title = f"QR #{index}: {qr_result['verdict']} - {qr_result['risk_score']}/100"
        with st.expander(title, expanded=True):
            st.write("Decoded value:")
            st.code(qr_result["url"], language="text")
            st.write("Final destination:")
            st.code(qr_result["final_url"], language="text")
            st.write(f"Domain: `{qr_result['domain']}`")

            st.write("Reasons:")
            for reason in qr_result["reasons"]:
                st.write(f"- {reason}")

            st.write("Extracted URL features:")
            st.json(qr_result["features"])


def _tab_history() -> None:
    """Prediction history — authenticated users only."""
    st.header("📋 Lịch sử Phân loại")

    if not st.session_state["logged_in"]:
        st.warning(
            "🔒 **Chức năng này yêu cầu đăng nhập.**\n\n"
            "Vui lòng đăng nhập hoặc đăng ký tài khoản ở thanh bên trái."
        )
        return

    if not check_db():
        st.error("Không thể kết nối đến cơ sở dữ liệu.")
        return

    h_single, h_batch = st.tabs(["Email Đơn", "File MBOX"])

    # ── Single history ────────────────────────────────────────────────────
    with h_single:
        try:
            rows = get_single_history(st.session_state["user_id"])
            if not rows:
                st.info("Chưa có lịch sử kiểm tra email đơn.")
            else:
                import pandas as pd
                df = pd.DataFrame(rows)
                df = df.rename(columns={
                    "id":         "ID",
                    "prediction": "Kết quả",
                    "confidence": "Độ tin cậy (%)",
                    "created_at": "Thời gian",
                    "preview":    "Nội dung (120 ký tự đầu)",
                })
                st.dataframe(df, use_container_width=True)
        except Exception as exc:
            st.error(f"Lỗi tải lịch sử: {exc}")

    # ── Batch history ─────────────────────────────────────────────────────
    with h_batch:
        try:
            rows = get_batch_history(st.session_state["user_id"])
            if not rows:
                st.info("Chưa có lịch sử xử lý file MBOX.")
            else:
                import pandas as pd
                df = pd.DataFrame(rows)
                df = df.rename(columns={
                    "id":           "ID",
                    "file_name":    "Tên file",
                    "total_emails": "Tổng",
                    "spam_count":   "Spam",
                    "ham_count":    "Ham",
                    "created_at":   "Thời gian",
                })
                st.dataframe(df, use_container_width=True)
        except Exception as exc:
            st.error(f"Lỗi tải lịch sử: {exc}")


# ══════════════════════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════════════════════
def main() -> None:
    # ── Sidebar ───────────────────────────────────────────────────────────
    _sidebar_auth()

    # ── Header ────────────────────────────────────────────────────────────
    st.title("📧 Spam Email Classifier")
    st.markdown(
        "Phân loại email là **Spam** hay **Ham** bằng Machine Learning."
    )

    # ── Tabs (vary by auth state) ─────────────────────────────────────────
    if st.session_state["logged_in"]:
        tab_dashboard, tab_single, tab_batch, tab_history = st.tabs(
            ["📊 Dashboard", "📨 Email Đơn", "📦 File MBOX", "📋 Lịch sử"]
        )

        with tab_dashboard:
            show_dashboard(st.session_state["user_id"])

        with tab_single:
            _tab_single_email()
            st.divider()
            _tab_qr_image_security()

        with tab_batch:
            _tab_batch()

        with tab_history:
            _tab_history()
    else:
        tab_single, tab_batch = st.tabs(
            ["📨 Email Đơn", "📦 File MBOX 🔒"]
        )
        with tab_single:
            _tab_single_email()
            st.divider()
            _tab_qr_image_security()
        with tab_batch:
            _tab_batch()   # shows the "please log in" message internally


if __name__ == "__main__":
    main()
