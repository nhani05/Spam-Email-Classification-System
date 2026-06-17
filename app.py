"""
MailGuard AI - ung dung Streamlit.

Quyen truy cap:
- Khach: kiem tra email don, phan tich URL va phan tich QR.
- Nguoi dung da dang nhap: them dashboard, xu ly MBOX, lich su va feedback.
"""

import os
import re
import tempfile
import time

import pandas as pd
import streamlit as st

from src.auth.auth import (
    AuthError,
    get_batch_history,
    get_single_history,
    login_user,
    register_user,
    save_batch_prediction,
    save_prediction_feedback,
    save_single_prediction,
)
from src.components.dashboard import show_dashboard
from src.components.email_summarizer import show_email_summarizer_tab
from src.database.db import ping as db_ping
from src.pipeline.prediction_pipeline import PredictionPipeline
from src.security import CampaignIntelligenceEngine, EmailThreatAnalyzer, QRImageAnalyzer, URLRiskModel
from src.security.campaign_intelligence import CampaignSummary


st.set_page_config(
    page_title="MailGuard AI",
    page_icon="MG",
    layout="centered",
)


_SESSION_DEFAULTS = {
    "logged_in": False,
    "user_id": None,
    "username": None,
    "auth_page": "login",
    "db_ok": None,
    "last_prediction_id": None,
}
for key, default in _SESSION_DEFAULTS.items():
    if key not in st.session_state:
        st.session_state[key] = default


@st.cache_resource
def get_pipeline() -> PredictionPipeline:
    return PredictionPipeline(load_models=True)


@st.cache_resource
def get_qr_analyzer() -> QRImageAnalyzer:
    return QRImageAnalyzer()


@st.cache_resource
def get_email_threat_analyzer() -> EmailThreatAnalyzer:
    return EmailThreatAnalyzer()


@st.cache_resource
def get_url_risk_model() -> URLRiskModel:
    return URLRiskModel()


@st.cache_resource
def get_campaign_engine() -> CampaignIntelligenceEngine:
    return CampaignIntelligenceEngine()


try:
    pipeline = get_pipeline()
except Exception as exc:
    st.error(f"Không thể tải mô hình ML: {exc}")
    st.stop()


def check_db() -> bool:
    if st.session_state["db_ok"] is None:
        st.session_state["db_ok"] = db_ping()
    return st.session_state["db_ok"]


def _risk_level_vi(value: str) -> str:
    if value is None:
        return "Không rõ"
    try:
        if pd.isna(value):
            return "Không rõ"
    except (TypeError, ValueError):
        pass
    mapping = {
        "Low": "Thấp",
        "Medium": "Trung bình",
        "High": "Cao",
        "Critical": "Nghiêm trọng",
    }
    return mapping.get(str(value), str(value))


def _verdict_vi(value: str) -> str:
    mapping = {
        "LOW_RISK_EMAIL": "Email rủi ro thấp",
        "SPAM_LOW_THREAT": "Spam nhưng tín hiệu đe dọa thấp",
        "SUSPICIOUS_EMAIL": "Email đáng nghi",
        "HIGH_RISK_EMAIL": "Email rủi ro cao",
        "CRITICAL_EMAIL_THREAT": "Email nguy hiểm nghiêm trọng",
        "MALWARE_RISK_EMAIL": "Email có nguy cơ mã độc",
        "FAKE_LINK_PHISHING": "Email có liên kết giả mạo",
        "QUISHING_EMAIL": "Email có dấu hiệu quishing",
        "PAYMENT_SCAM_EMAIL": "Email có dấu hiệu lừa đảo thanh toán",
        "CREDENTIAL_THEFT_EMAIL": "Email có dấu hiệu đánh cắp thông tin đăng nhập",
        "LOW_RISK_URL": "URL rủi ro thấp",
        "UNKNOWN_SHORT_LINK": "Liên kết rút gọn cần kiểm tra",
        "SUSPICIOUS_URL": "URL đáng nghi",
        "HIGH_RISK_URL": "URL rủi ro cao",
        "PHISHING_URL": "URL phishing",
        "PAYMENT_QR_REVIEW": "QR thanh toán cần kiểm tra",
        "NON_URL_QR": "QR không chứa URL",
        "NO_QR_FOUND": "Không tìm thấy QR",
        "LOW_RISK_QR_IMAGE": "Ảnh QR rủi ro thấp",
        "SUSPICIOUS_QR_IMAGE": "Ảnh QR đáng nghi",
        "HIGH_RISK_QR_IMAGE": "Ảnh QR rủi ro cao",
        "PHISHING_QR_IMAGE": "Ảnh QR phishing",
    }
    return mapping.get(str(value), str(value))


def _threat_label_vi(value: str) -> str:
    if value is None:
        return "Không rõ"
    try:
        if pd.isna(value):
            return "Không rõ"
    except (TypeError, ValueError):
        pass
    mapping = {
        "Safe": "An toàn",
        "Spam": "Spam",
        "Phishing": "Phishing",
        "Malware Risk": "Nguy cơ mã độc",
        "Business Email Compromise": "Giả mạo email doanh nghiệp",
        "Quishing": "Quishing",
        "Credential Theft": "Đánh cắp thông tin đăng nhập",
        "Payment Scam": "Lừa đảo thanh toán",
    }
    return mapping.get(str(value), str(value))


def _message_vi(message: object) -> str:
    text = str(message)
    exact = {
        "No strong spam, phishing, fake-link, or malware indicator found.": (
            "Không phát hiện chỉ báo mạnh về spam, phishing, liên kết giả hoặc mã độc."
        ),
        "ML classifier predicts Spam.": "Mô hình ML dự đoán email là Spam.",
        "ML classifier predicts Ham, but confidence was unavailable.": (
            "Mô hình ML dự đoán email là Ham, nhưng không có độ tin cậy."
        ),
        "Rule-based threat analysis found high-risk signals even though the ML label is Ham.": (
            "Bộ phân tích theo luật phát hiện tín hiệu rủi ro cao dù nhãn ML là Ham."
        ),
        "ML spam signal is the main risk indicator; rule-based threat signals are low.": (
            "Tín hiệu spam từ ML là chỉ báo rủi ro chính; tín hiệu theo luật đang thấp."
        ),
        "No strong phishing signal found.": "Không phát hiện tín hiệu phishing mạnh.",
        "URL does not use HTTPS.": "URL không sử dụng HTTPS.",
        "URL uses a raw IP address instead of a domain.": "URL dùng địa chỉ IP trực tiếp thay vì tên miền.",
        "URL points to a shortened URL.": "URL trỏ tới dịch vụ rút gọn liên kết.",
        "URL contains a nested redirect parameter.": "URL chứa tham số chuyển hướng lồng nhau.",
        "URL contains '@', which can hide the real destination.": "URL chứa ký tự '@', có thể che giấu đích thật.",
        "URL contains encoded characters such as '%', which can hide text.": (
            "URL chứa ký tự mã hóa như '%', có thể che giấu nội dung."
        ),
        "Domain has an unusual number of subdomains.": "Tên miền có số lượng subdomain bất thường.",
        "URL is unusually long.": "URL dài bất thường.",
        "Domain name is unusually long.": "Tên miền dài bất thường.",
        "Domain contains many digits.": "Tên miền chứa nhiều chữ số.",
        "Domain contains many hyphens.": "Tên miền chứa nhiều dấu gạch nối.",
        "Domain uses a high-risk top-level domain.": "Tên miền dùng TLD có rủi ro cao.",
        "URL appears to point to a risky executable file.": "URL có vẻ trỏ tới file thực thi rủi ro.",
        "QR code contains a payment payload, not a web URL.": "QR chứa nội dung thanh toán, không phải URL web.",
        "Verify recipient name, bank, and account number before transferring money.": (
            "Hãy xác minh tên người nhận, ngân hàng và số tài khoản trước khi chuyển tiền."
        ),
        "Payment QR codes in unexpected emails can be used for invoice or receipt scams.": (
            "QR thanh toán trong email bất ngờ có thể bị dùng cho lừa đảo hóa đơn hoặc biên lai."
        ),
        "QR code was decoded, but it does not contain a web URL.": "QR đã được giải mã nhưng không chứa URL web.",
        "No QR code was detected in this image.": "Không phát hiện QR code trong ảnh này.",
        "OpenCV is not installed. Install opencv-python to enable QR detection.": (
            "Chưa cài OpenCV. Hãy cài `opencv-python` để bật nhận diện QR."
        ),
        "Do not click links, scan QR codes, download files, or reply to this email.": (
            "Không nhấp liên kết, quét QR, tải file hoặc trả lời email này."
        ),
        "Report or delete the message after preserving evidence if needed.": (
            "Báo cáo hoặc xóa thư sau khi lưu bằng chứng nếu cần."
        ),
        "Treat this email as dangerous until verified through a trusted channel.": (
            "Xem email này là nguy hiểm cho tới khi xác minh qua kênh tin cậy."
        ),
        "Do not provide passwords, OTP codes, payment details, or personal information.": (
            "Không cung cấp mật khẩu, mã OTP, thông tin thanh toán hoặc thông tin cá nhân."
        ),
        "Review the sender, links, and attachments carefully before taking action.": (
            "Kiểm tra kỹ người gửi, liên kết và tệp đính kèm trước khi thao tác."
        ),
        "Open the official website directly instead of using links in the email.": (
            "Mở website chính thức trực tiếp thay vì dùng liên kết trong email."
        ),
        "No urgent action is required, but keep normal email safety checks in mind.": (
            "Không cần hành động khẩn cấp, nhưng vẫn nên kiểm tra an toàn email như bình thường."
        ),
        "Verify detected domains before opening any link.": "Xác minh các tên miền phát hiện được trước khi mở liên kết.",
        "Do not open mentioned attachments or downloads unless you trust the sender.": (
            "Không mở tệp đính kèm hoặc nội dung tải xuống nếu chưa tin cậy người gửi."
        ),
    }
    if text in exact:
        return exact[text]

    match = re.fullmatch(r"ML classifier predicts Spam with ([0-9.]+)% confidence\.", text)
    if match:
        return f"Mô hình ML dự đoán email là Spam với độ tin cậy {match.group(1)}%."

    match = re.fullmatch(r"ML classifier predicts Ham, but confidence is low \(([0-9.]+)%\)\.", text)
    if match:
        return f"Mô hình ML dự đoán email là Ham nhưng độ tin cậy thấp ({match.group(1)}%)."

    match = re.fullmatch(r"ML classifier predicts Ham with ([0-9.]+)% confidence\.", text)
    if match:
        return f"Mô hình ML dự đoán email là Ham với độ tin cậy {match.group(1)}%."

    match = re.fullmatch(r"URL contains sensitive phishing keywords: (.+)\.", text)
    if match:
        return f"URL chứa từ khóa nhạy cảm thường gặp trong phishing: {match.group(1)}."

    match = re.fullmatch(r"Domain resembles (.+) but is not the official domain (.+)\.", text)
    if match:
        return f"Tên miền giống {match.group(1)} nhưng không phải tên miền chính thức {match.group(2)}."

    match = re.fullmatch(r"Email is linked to campaign (.+) \((.+) risk\)\.", text)
    if match:
        return f"Email liên quan tới chiến dịch {match.group(1)} với mức rủi ro {_risk_level_vi(match.group(2))}."

    match = re.fullmatch(r"QR #([0-9]+): (.+)", text)
    if match:
        return f"QR #{match.group(1)}: {_message_vi(match.group(2))}"

    return text


def _features_vi(features: dict) -> dict:
    labels = {
        "uses_https": "Dùng HTTPS",
        "uses_ip_address": "Dùng địa chỉ IP",
        "is_shortened": "Liên kết rút gọn",
        "has_nested_redirect": "Có chuyển hướng lồng nhau",
        "has_at_symbol": "Có ký tự @",
        "has_encoded_chars": "Có ký tự mã hóa",
        "has_many_subdomains": "Nhiều subdomain",
        "url_length": "Độ dài URL",
        "domain_length": "Độ dài tên miền",
        "digit_count": "Số chữ số trong tên miền",
        "hyphen_count": "Số dấu gạch nối",
        "encoded_char_count": "Số ký tự mã hóa",
        "suspicious_tld": "TLD rủi ro cao",
        "keyword_hits": "Từ khóa nhạy cảm",
        "brand_impersonation": "Dấu hiệu giả mạo thương hiệu",
        "is_url": "Là URL",
        "is_payment_payload": "Nội dung thanh toán",
        "payload_length": "Độ dài nội dung",
    }
    result = {}
    for key, value in features.items():
        if isinstance(value, bool):
            value = "Có" if value else "Không"
        result[labels.get(key, key)] = value
    return result


def _safe_columns(df: pd.DataFrame, columns: list[str]) -> list[str]:
    return [column for column in columns if column in df.columns]


def _sidebar_auth() -> None:
    st.sidebar.title("Tài khoản")

    if st.session_state["logged_in"]:
        st.sidebar.success(f"Xin chào, **{st.session_state['username']}**!")
        if st.sidebar.button("Đăng xuất", use_container_width=True):
            for key in ("logged_in", "user_id", "username", "last_prediction_id"):
                st.session_state[key] = _SESSION_DEFAULTS[key]
            st.rerun()
        return

    if not check_db():
        st.sidebar.warning(
            "Không thể kết nối cơ sở dữ liệu.\n\n"
            "Hãy kiểm tra các biến môi trường `DB_HOST`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`."
        )
        st.sidebar.info("Bạn vẫn có thể dùng chế độ khách để kiểm tra email đơn, URL và QR.")
        return

    col_login, col_register = st.sidebar.columns(2)
    if col_login.button(
        "Đăng nhập",
        use_container_width=True,
        type="primary" if st.session_state["auth_page"] == "login" else "secondary",
    ):
        st.session_state["auth_page"] = "login"
    if col_register.button(
        "Đăng ký",
        use_container_width=True,
        type="primary" if st.session_state["auth_page"] == "register" else "secondary",
    ):
        st.session_state["auth_page"] = "register"

    st.sidebar.divider()

    if st.session_state["auth_page"] == "login":
        _sidebar_login_form()
    else:
        _sidebar_register_form()


def _sidebar_login_form() -> None:
    st.sidebar.subheader("Đăng nhập")
    with st.sidebar.form("login_form", clear_on_submit=False):
        username = st.text_input("Tên đăng nhập", max_chars=12)
        password = st.text_input("Mật khẩu", type="password")
        submitted = st.form_submit_button("Đăng nhập", use_container_width=True)

    if not submitted:
        return

    if not username or not password:
        st.sidebar.error("Vui lòng nhập đầy đủ thông tin.")
        return

    try:
        user = login_user(username, password)
        st.session_state.update(
            {
                "logged_in": True,
                "user_id": user["id"],
                "username": user["username"],
            }
        )
        st.sidebar.success("Đăng nhập thành công.")
        st.rerun()
    except AuthError as exc:
        st.sidebar.error(str(exc))
    except Exception as exc:
        st.sidebar.error(f"Lỗi kết nối: {exc}")


def _sidebar_register_form() -> None:
    st.sidebar.subheader("Đăng ký")
    with st.sidebar.form("register_form", clear_on_submit=True):
        username = st.text_input("Tên đăng nhập (tối đa 12 ký tự)", max_chars=12)
        password = st.text_input("Mật khẩu", type="password")
        confirm = st.text_input("Xác nhận mật khẩu", type="password", max_chars=12)
        submitted = st.form_submit_button("Tạo tài khoản", use_container_width=True)

    if not submitted:
        return

    if not username or not password:
        st.sidebar.error("Vui lòng nhập đầy đủ thông tin.")
        return
    if password != confirm:
        st.sidebar.error("Mật khẩu xác nhận không khớp.")
        return

    try:
        user = register_user(username, password)
        st.sidebar.success(f"Tạo tài khoản **{user['username']}** thành công. Vui lòng đăng nhập.")
        st.session_state["auth_page"] = "login"
        st.rerun()
    except AuthError as exc:
        st.sidebar.error(str(exc))
    except Exception as exc:
        st.sidebar.error(f"Lỗi kết nối: {exc}")


def _show_url_result(url_info: dict, title_prefix: str = "URL", expanded: bool = True) -> None:
    title = f"{title_prefix}: {_verdict_vi(url_info['verdict'])} - {url_info['risk_score']}/100"
    with st.expander(title, expanded=expanded):
        cols = st.columns(3)
        cols[0].metric("Điểm rủi ro", f"{url_info['risk_score']}/100")
        cols[1].metric("Mức rủi ro", _risk_level_vi(url_info["risk_level"]))
        cols[2].metric("Tên miền", url_info["domain"] or "Không có")

        st.write("Giá trị gốc:")
        st.code(url_info["url"], language="text")
        st.write("Đích cuối cùng:")
        st.code(url_info["final_url"], language="text")

        st.write("Lý do đánh giá:")
        for reason in url_info["reasons"]:
            st.write(f"- {_message_vi(reason)}")

        st.write("Đặc trưng URL đã trích xuất:")
        st.json(_features_vi(url_info["features"]))


def _tab_url_phishing() -> None:
    st.header("Phân tích URL phishing")
    st.caption("Dán một hoặc nhiều URL. Hệ thống chấm điểm rủi ro cục bộ và không mở liên kết.")

    url_text = st.text_area(
        "Danh sách URL cần phân tích",
        height=120,
        placeholder="https://paypa1-login.xyz/verify\nbit.ly/example",
    )

    if not st.button("Phân tích URL", type="primary"):
        return

    candidates = [line.strip() for line in url_text.splitlines() if line.strip()]
    if not candidates:
        st.warning("Vui lòng nhập ít nhất một URL.")
        return

    analyzer = get_url_risk_model()
    results = [analyzer.analyze(candidate).to_dict() for candidate in candidates]
    max_score = max(result["risk_score"] for result in results)
    suspicious_count = sum(result["risk_score"] >= 35 for result in results)

    cols = st.columns(3)
    cols[0].metric("Số URL đã phân tích", len(results))
    cols[1].metric("URL đáng nghi", suspicious_count)
    cols[2].metric("Điểm rủi ro cao nhất", f"{max_score}/100")

    if max_score >= 80:
        st.error("Có ít nhất một URL có dấu hiệu phishing nghiêm trọng.")
    elif max_score >= 35:
        st.warning("Có ít nhất một URL có dấu hiệu đáng nghi.")
    else:
        st.success("Không phát hiện tín hiệu phishing mạnh trong các URL đã nhập.")

    for index, result in enumerate(results, start=1):
        _show_url_result(result, title_prefix=f"URL #{index}", expanded=result["risk_score"] >= 35)


def _feedback_controls() -> None:
    prediction_id = st.session_state.get("last_prediction_id")
    if not st.session_state["logged_in"] or not prediction_id:
        return

    with st.expander("Phản hồi kết quả dự đoán", expanded=False):
        with st.form("single_prediction_feedback"):
            feedback_display = st.radio("Kết quả này có đúng không?", ["Đúng", "Sai"], horizontal=True)
            corrected_label = st.selectbox(
                "Nhãn đúng nếu kết quả sai",
                [
                    "Safe",
                    "Spam",
                    "Phishing",
                    "Malware Risk",
                    "Business Email Compromise",
                    "Quishing",
                    "Credential Theft",
                    "Payment Scam",
                ],
                format_func=_threat_label_vi,
            )
            note = st.text_area("Ghi chú của người phân tích", height=80)
            submitted = st.form_submit_button("Lưu phản hồi")

        if submitted:
            feedback = "correct" if feedback_display == "Đúng" else "incorrect"
            feedback_id = save_prediction_feedback(
                user_id=st.session_state["user_id"],
                prediction_id=prediction_id,
                feedback=feedback,
                corrected_label=corrected_label if feedback == "incorrect" else None,
                note=note,
            )
            if feedback_id:
                st.success("Đã lưu phản hồi để phục vụ review và cải thiện mô hình.")
            else:
                st.warning("Không thể lưu phản hồi. Hãy kiểm tra migration database adaptive.")


def _tab_single_email() -> None:
    st.header("Kiểm tra email đơn")

    if not st.session_state["logged_in"]:
        st.info(
            "Bạn đang dùng chế độ khách. Kết quả sẽ không được lưu. "
            "Đăng nhập để lưu lịch sử và gửi feedback."
        )

    email_text = st.text_area(
        "Dán nội dung email vào đây",
        height=200,
        placeholder="Dear friend, I have a business proposal...",
    )

    if st.button("Phân tích email", type="primary"):
        if not email_text.strip():
            st.warning("Vui lòng nhập nội dung email.")
            return

        with st.spinner("Đang phân tích email..."):
            try:
                result = pipeline.predict_single_email(email_text)
            except Exception as exc:
                st.error(f"Lỗi phân tích: {exc}")
                return

        risk_result = result["risk_analysis"]
        threat_result = result["threat_analysis"]
        prediction = result["prediction"]
        confidence = result.get("confidence")

        if prediction == "Spam":
            st.error("Email này được phân loại là SPAM.")
        else:
            st.success("Email này được phân loại là HAM.")

        if confidence is not None:
            st.metric("Độ tin cậy", f"{confidence:.1f}%")

        st.subheader("Phân tích rủi ro MailGuard")
        risk_cols = st.columns(4)
        risk_cols[0].metric("Điểm rủi ro", f"{risk_result['risk_score']}/100")
        risk_cols[1].metric("Mức rủi ro", _risk_level_vi(risk_result["risk_level"]))
        risk_cols[2].metric(
            "Nhãn đe dọa",
            _threat_label_vi(risk_result.get("threat_label", result.get("threat_label", "Không rõ"))),
        )
        risk_cols[3].metric("Kết luận", _verdict_vi(risk_result["verdict"]))

        final_message = f"Kết luận cuối cùng: {_verdict_vi(risk_result['verdict'])} ({_risk_level_vi(risk_result['risk_level'])})"
        if risk_result["risk_score"] >= 80:
            st.error(final_message)
        elif risk_result["risk_score"] >= 35:
            st.warning(final_message)
        else:
            st.success(final_message)

        st.subheader("Thành phần phát hiện đe dọa")
        threat_cols = st.columns(4)
        threat_cols[0].metric("Điểm ML spam", risk_result["components"]["ml_spam_score"])
        threat_cols[1].metric("Phishing", threat_result["phishing_score"])
        threat_cols[2].metric("Fake link", threat_result["fake_link_score"])
        threat_cols[3].metric("Malware", threat_result["malware_score"])

        with st.expander("Vì sao có kết quả này?", expanded=risk_result["risk_score"] >= 35):
            st.write("Điểm theo từng lớp:")
            st.json(result.get("class_scores", {}))

            st.write("Chỉ báo đã trích xuất:")
            st.json(result.get("indicators", {}))

            st.write("Lý do:")
            for reason in risk_result["reasons"]:
                st.write(f"- {_message_vi(reason)}")

            st.write("Khuyến nghị:")
            for action in risk_result["recommended_actions"]:
                st.write(f"- {_message_vi(action)}")

            if threat_result["risky_files"]:
                st.write("File đáng nghi:")
                for filename in threat_result["risky_files"]:
                    st.code(filename, language="text")

        if threat_result["urls"]:
            st.subheader("Phân tích URL trong email")
            for index, url_info in enumerate(threat_result["urls"], start=1):
                _show_url_result(
                    url_info,
                    title_prefix=f"URL phát hiện #{index}",
                    expanded=url_info["risk_score"] >= 35,
                )

        if st.session_state["logged_in"] and check_db():
            try:
                prediction_id = save_single_prediction(
                    user_id=st.session_state["user_id"],
                    email_content=email_text,
                    prediction=prediction,
                    confidence=confidence,
                    threat_metadata={
                        **risk_result,
                        "threat_label": risk_result.get("threat_label", result.get("threat_label")),
                        "indicators": result.get("indicators", {}),
                    },
                )
                st.session_state["last_prediction_id"] = prediction_id
                st.caption("Đã lưu vào lịch sử.")
            except Exception as exc:
                st.caption(f"Không thể lưu lịch sử: {exc}")

    _feedback_controls()


def _tab_batch() -> None:
    st.header("Xử lý file MBOX")

    if not st.session_state["logged_in"]:
        st.warning("Chức năng này yêu cầu đăng nhập. Vui lòng đăng nhập hoặc đăng ký ở thanh bên trái.")
        return

    uploaded_file = st.file_uploader("Tải lên file MBOX", type=["mbox", "txt"])

    if uploaded_file is None or not st.button("Xử lý file", type="primary"):
        return

    with st.spinner("Đang xử lý file, vui lòng chờ..."):
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".mbox") as tmp:
                tmp.write(uploaded_file.getvalue())
                tmp_path = tmp.name

            try:
                df = pipeline.predict_mbox_file(tmp_path)
            finally:
                if os.path.exists(tmp_path):
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass
        except Exception as exc:
            st.error(f"Lỗi xử lý file: {exc}")
            return

    campaigns = df.attrs.get("campaigns", getattr(pipeline, "last_campaigns", []))
    spam_count = len(df[df["Prediction"] == "Spam"])
    ham_count = len(df[df["Prediction"] == "Ham"])

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Tổng email", len(df))
    col2.metric("Spam", spam_count)
    col3.metric("Ham", ham_count)
    col4.metric("Chiến dịch", len(campaigns))

    st.subheader("Kết quả mẫu")
    preview_columns = _safe_columns(
        df,
        ["Time", "Subject", "Prediction", "Threat Label", "Risk Score", "Risk Level", "Verdict", "Campaign ID"],
    )
    preview_df = df[preview_columns].head(10).copy()
    preview_df = preview_df.rename(
        columns={
            "Time": "Thời gian",
            "Subject": "Tiêu đề",
            "Prediction": "Kết quả",
            "Threat Label": "Nhãn đe dọa",
            "Risk Score": "Điểm rủi ro",
            "Risk Level": "Mức rủi ro",
            "Verdict": "Kết luận",
            "Campaign ID": "Mã chiến dịch",
        }
    )
    if "Nhãn đe dọa" in preview_df.columns:
        preview_df["Nhãn đe dọa"] = preview_df["Nhãn đe dọa"].map(_threat_label_vi)
    if "Mức rủi ro" in preview_df.columns:
        preview_df["Mức rủi ro"] = preview_df["Mức rủi ro"].map(_risk_level_vi)
    if "Kết luận" in preview_df.columns:
        preview_df["Kết luận"] = preview_df["Kết luận"].map(_verdict_vi)
    st.dataframe(preview_df, use_container_width=True)

    if campaigns:
        st.subheader("Chiến dịch đe dọa phát hiện được")
        campaign_df = pd.DataFrame(campaigns)
        campaign_columns = _safe_columns(
            campaign_df,
            ["campaign_id", "primary_threat_label", "risk_level", "risk_score", "email_count", "top_domains"],
        )
        campaign_display = campaign_df[campaign_columns].copy()
        campaign_display = campaign_display.rename(
            columns={
                "campaign_id": "Mã chiến dịch",
                "primary_threat_label": "Nhãn đe dọa chính",
                "risk_level": "Mức rủi ro",
                "risk_score": "Điểm rủi ro",
                "email_count": "Số email",
                "top_domains": "Tên miền nổi bật",
            }
        )
        if "Nhãn đe dọa chính" in campaign_display.columns:
            campaign_display["Nhãn đe dọa chính"] = campaign_display["Nhãn đe dọa chính"].map(_threat_label_vi)
        if "Mức rủi ro" in campaign_display.columns:
            campaign_display["Mức rủi ro"] = campaign_display["Mức rủi ro"].map(_risk_level_vi)
        st.dataframe(campaign_display, use_container_width=True)

        engine = get_campaign_engine()
        campaign_objects = [
            CampaignSummary(**{key: item[key] for key in CampaignSummary.__dataclass_fields__ if key in item})
            for item in campaigns
        ]
        st.download_button(
            "Tải tóm tắt chiến dịch (JSON)",
            data=engine.reports_json(campaign_objects),
            file_name=f"campaigns_{int(time.time())}.json",
            mime="application/json",
        )
        st.download_button(
            "Tải báo cáo chiến dịch đầu tiên (Markdown)",
            data=engine.markdown_report(campaign_objects[0], df.to_dict("records")),
            file_name=f"{campaign_objects[0].campaign_id}_report.md",
            mime="text/markdown",
        )
        with st.expander("Dữ liệu graph của chiến dịch đầu tiên", expanded=False):
            st.json(engine.graph_for_campaign(campaign_objects[0], df.to_dict("records")))
    else:
        st.info("Không phát hiện chiến dịch liên quan trong batch này.")

    csv = df.to_csv(index=False).encode("utf-8")
    st.download_button(
        "Tải kết quả CSV",
        data=csv,
        file_name=f"predictions_{int(time.time())}.csv",
        mime="text/csv",
    )

    if check_db():
        try:
            save_batch_prediction(
                user_id=st.session_state["user_id"],
                file_name=uploaded_file.name,
                total_emails=len(df),
                spam_count=spam_count,
                ham_count=ham_count,
            )
            st.caption("Đã lưu thống kê batch vào lịch sử.")
        except Exception as exc:
            st.caption(f"Không thể lưu lịch sử batch: {exc}")


def _tab_qr_image_security() -> None:
    st.header("Phân tích QR / Quishing")
    st.caption(
        "Tải lên ảnh email, ảnh biên lai hoặc ảnh QR thanh toán. "
        "Hệ thống giải mã QR và chấm điểm rủi ro mà không mở liên kết."
    )

    uploaded_image = st.file_uploader(
        "Tải ảnh có QR",
        type=["png", "jpg", "jpeg", "webp", "bmp"],
        key="qr_image_upload",
    )

    if uploaded_image is None:
        return

    image_bytes = uploaded_image.getvalue()
    st.image(image_bytes, caption=uploaded_image.name, use_container_width=True)

    if not st.button("Phân tích ảnh QR", type="primary"):
        return

    analyzer = get_qr_analyzer()
    with st.spinner("Đang phân tích QR..."):
        try:
            result = analyzer.analyze_image_bytes(image_bytes)
        except Exception as exc:
            st.error(f"Không thể phân tích ảnh: {exc}")
            return

    for warning in result.warnings:
        st.warning(_message_vi(warning))

    col1, col2, col3 = st.columns(3)
    col1.metric("Số QR tìm thấy", result.qr_count)
    col2.metric("Điểm rủi ro", result.max_risk_score)
    col3.metric("Mức rủi ro", _risk_level_vi(result.risk_level))

    if not result.qr_found:
        st.info("Không phát hiện QR code trong ảnh.")
        return

    if result.max_risk_score >= 80:
        st.error(f"Kết luận cuối cùng: {_verdict_vi(result.final_verdict)}")
    elif result.max_risk_score >= 35:
        st.warning(f"Kết luận cuối cùng: {_verdict_vi(result.final_verdict)}")
    else:
        st.success(f"Kết luận cuối cùng: {_verdict_vi(result.final_verdict)}")

    st.subheader("Nội dung QR phát hiện")
    for index, qr_result in enumerate(result.qr_results, start=1):
        _show_url_result(qr_result, title_prefix=f"QR #{index}", expanded=True)


def _tab_history() -> None:
    st.header("Lịch sử phân tích")

    if not st.session_state["logged_in"]:
        st.warning("Chức năng này yêu cầu đăng nhập.")
        return

    if not check_db():
        st.error("Không thể kết nối cơ sở dữ liệu.")
        return

    h_single, h_batch = st.tabs(["Email đơn", "File MBOX"])

    with h_single:
        try:
            rows = get_single_history(st.session_state["user_id"])
            if not rows:
                st.info("Chưa có lịch sử kiểm tra email đơn.")
            else:
                df = pd.DataFrame(rows)
                df = df.rename(
                    columns={
                        "id": "ID",
                        "prediction": "Kết quả",
                        "confidence": "Độ tin cậy (%)",
                        "created_at": "Thời gian",
                        "preview": "Nội dung xem trước",
                        "threat_label": "Nhãn đe dọa",
                        "risk_score": "Điểm rủi ro",
                        "risk_level": "Mức rủi ro",
                        "verdict": "Kết luận",
                        "campaign_id": "Mã chiến dịch",
                    }
                )
                if "Nhãn đe dọa" in df.columns:
                    df["Nhãn đe dọa"] = df["Nhãn đe dọa"].map(_threat_label_vi)
                if "Mức rủi ro" in df.columns:
                    df["Mức rủi ro"] = df["Mức rủi ro"].map(_risk_level_vi)
                if "Kết luận" in df.columns:
                    df["Kết luận"] = df["Kết luận"].map(_verdict_vi)
                st.dataframe(df, use_container_width=True)
        except Exception as exc:
            st.error(f"Lỗi tải lịch sử: {exc}")

    with h_batch:
        try:
            rows = get_batch_history(st.session_state["user_id"])
            if not rows:
                st.info("Chưa có lịch sử xử lý file MBOX.")
            else:
                df = pd.DataFrame(rows)
                df = df.rename(
                    columns={
                        "id": "ID",
                        "file_name": "Tên file",
                        "total_emails": "Tổng email",
                        "spam_count": "Spam",
                        "ham_count": "Ham",
                        "created_at": "Thời gian",
                    }
                )
                st.dataframe(df, use_container_width=True)
        except Exception as exc:
            st.error(f"Lỗi tải lịch sử: {exc}")


def main() -> None:
    _sidebar_auth()

    st.title("MailGuard AI")
    st.markdown(
        "Hệ thống phân tích an toàn email: phân loại Spam/Ham, chấm điểm rủi ro, "
        "phát hiện phishing URL, QR/quishing và campaign tấn công."
    )

    if st.session_state["logged_in"]:
        tab_dashboard, tab_single, tab_batch, tab_summary, tab_history = st.tabs(
            ["Bảng điều khiển", "Email đơn", "File MBOX", "Tóm tắt", "Lịch sử"]
        )

        with tab_dashboard:
            show_dashboard(st.session_state["user_id"])

        with tab_single:
            _tab_single_email()
            st.divider()
            _tab_url_phishing()
            st.divider()
            _tab_qr_image_security()

        with tab_batch:
            _tab_batch()

        with tab_summary:
            show_email_summarizer_tab()

        with tab_history:
            _tab_history()
    else:
        tab_single, tab_summary, tab_batch = st.tabs(["Email đơn", "Tóm tắt", "File MBOX (cần đăng nhập)"])
        with tab_single:
            _tab_single_email()
            st.divider()
            _tab_url_phishing()
            st.divider()
            _tab_qr_image_security()
        with tab_summary:
            show_email_summarizer_tab()
        with tab_batch:
            _tab_batch()


if __name__ == "__main__":
    main()
