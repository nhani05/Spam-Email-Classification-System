import matplotlib.pyplot as plt
import pandas as pd
import streamlit as st

from src.features.auth.service import export_retraining_data, get_history_campaign_candidates, get_review_queue, get_single_history
from src.features.spam_classifier.model_lab import discover_model_runs
from src.features.threat_intelligence.campaign_intelligence import CampaignIntelligenceEngine


def _risk_level_vi(value):
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


def _threat_label_vi(value):
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


def show_dashboard(user_id, translate=None):
    def text(key, default):
        return translate(key) if translate else default

    st.header(text("dashboard_title", "Bảng điều khiển bảo mật MailGuard AI"))

    rows = get_single_history(user_id)
    if not rows:
        st.warning(text("no_data", "Chưa có dữ liệu để hiển thị."))
        return

    df = pd.DataFrame(rows)
    df["created_at"] = pd.to_datetime(df["created_at"])
    df["prediction"] = df["prediction"].str.upper()
    if "risk_score" in df.columns:
        df["risk_score"] = pd.to_numeric(df["risk_score"], errors="coerce").fillna(0)

    total = len(df)
    spam = int((df["prediction"] == "SPAM").sum())
    ham = int((df["prediction"] == "HAM").sum())
    high_risk = int((df.get("risk_score", pd.Series([0] * len(df))) >= 60).sum())
    campaign_count = int(df.get("campaign_id", pd.Series(dtype=str)).dropna().replace("", pd.NA).dropna().nunique())

    spam_rate = round((spam / total) * 100, 2)
    ham_rate = round((ham / total) * 100, 2)

    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric(text("dashboard_total_emails", "Tổng email"), total)
    col2.metric("Tỉ lệ Spam", f"{spam_rate}%")
    col3.metric("Tỉ lệ Ham", f"{ham_rate}%")
    col4.metric("Email rủi ro cao", high_risk)
    col5.metric("Chiến dịch", campaign_count)

    st.divider()

    col1, col2 = st.columns(2)
    with col1:
        st.subheader(text("spam_vs_ham", "Spam và Ham"))
        fig, ax = plt.subplots()
        ax.pie([spam, ham], labels=["Spam", "Ham"], autopct="%1.1f%%")
        st.pyplot(fig)

    with col2:
        st.subheader(text("emails_over_time", "Số email theo thời gian"))
        df["date"] = df["created_at"].dt.date
        st.line_chart(df.groupby("date").size())

    if "threat_label" in df.columns:
        st.subheader("Phân bố loại đe dọa")
        st.bar_chart(df["threat_label"].fillna("Không rõ").map(_threat_label_vi).value_counts())

    if "risk_score" in df.columns:
        st.subheader("Xu hướng rủi ro cao")
        st.line_chart(df.groupby("date")["risk_score"].max())

    history_campaign_rows = get_history_campaign_candidates(user_id)
    if history_campaign_rows:
        engine = CampaignIntelligenceEngine()
        campaigns = engine.cluster(history_campaign_rows)
        if campaigns:
            st.subheader("Chiến dịch từ lịch sử đã lưu")
            campaign_df = pd.DataFrame([campaign.to_dict() for campaign in campaigns])
            campaign_df = campaign_df.rename(
                columns={
                    "campaign_id": "Mã chiến dịch",
                    "primary_threat_label": "Nhãn đe dọa chính",
                    "risk_level": "Mức rủi ro",
                    "risk_score": "Điểm rủi ro",
                    "email_count": "Số email",
                    "top_domains": "Tên miền nổi bật",
                }
            )
            if "Nhãn đe dọa chính" in campaign_df.columns:
                campaign_df["Nhãn đe dọa chính"] = campaign_df["Nhãn đe dọa chính"].map(_threat_label_vi)
            if "Mức rủi ro" in campaign_df.columns:
                campaign_df["Mức rủi ro"] = campaign_df["Mức rủi ro"].map(_risk_level_vi)
            st.dataframe(campaign_df, use_container_width=True)

    review_rows = get_review_queue(limit=10)
    if review_rows:
        st.subheader("Hàng đợi rà soát cho học thích ứng")
        review_df = pd.DataFrame(review_rows).rename(
            columns={
                "id": "ID",
                "prediction_id": "Mã dự đoán",
                "feedback": "Phản hồi",
                "corrected_label": "Nhãn sửa",
                "note": "Ghi chú",
                "created_at": "Thời gian",
            }
        )
        if "Nhãn sửa" in review_df.columns:
            review_df["Nhãn sửa"] = review_df["Nhãn sửa"].map(_threat_label_vi)
        st.dataframe(review_df, use_container_width=True)

    approved = export_retraining_data()
    if approved:
        st.caption(f"Mẫu retraining đã được duyệt: {len(approved)}")

    model_runs = discover_model_runs()
    if not model_runs.empty:
        st.subheader("Phòng thử nghiệm mô hình")
        st.dataframe(model_runs, use_container_width=True)

    st.divider()
    st.subheader(text("recent_emails", "Email gần đây"))
    recent = df.sort_values("created_at", ascending=False).head(10)
    recent_columns = [
        col
        for col in [
            "preview",
            "prediction",
            "threat_label",
            "risk_score",
            "risk_level",
            "campaign_id",
            "created_at",
        ]
        if col in recent.columns
    ]
    recent_df = recent[recent_columns].rename(
        columns={
            "preview": "Nội dung xem trước",
            "prediction": "Kết quả",
            "threat_label": "Nhãn đe dọa",
            "risk_score": "Điểm rủi ro",
            "risk_level": "Mức rủi ro",
            "campaign_id": "Mã chiến dịch",
            "created_at": "Thời gian",
        }
    )
    if "Nhãn đe dọa" in recent_df.columns:
        recent_df["Nhãn đe dọa"] = recent_df["Nhãn đe dọa"].map(_threat_label_vi)
    if "Mức rủi ro" in recent_df.columns:
        recent_df["Mức rủi ro"] = recent_df["Mức rủi ro"].map(_risk_level_vi)
    st.dataframe(recent_df, use_container_width=True)
