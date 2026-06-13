import matplotlib.pyplot as plt
import pandas as pd
import streamlit as st

from src.auth.auth import export_retraining_data, get_history_campaign_candidates, get_review_queue, get_single_history
from src.components.model_lab import discover_model_runs
from src.security.campaign_intelligence import CampaignIntelligenceEngine


def show_dashboard(user_id, translate=None):
    def text(key, default):
        return translate(key) if translate else default

    st.header(text("dashboard_title", "MailGuard AI Security Dashboard"))

    rows = get_single_history(user_id)
    if not rows:
        st.warning(text("no_data", "No data available"))
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
    col1.metric(text("dashboard_total_emails", "Total Emails"), total)
    col2.metric("Spam %", f"{spam_rate}%")
    col3.metric("Ham %", f"{ham_rate}%")
    col4.metric("High risk", high_risk)
    col5.metric("Campaigns", campaign_count)

    st.divider()

    col1, col2 = st.columns(2)
    with col1:
        st.subheader(text("spam_vs_ham", "Spam vs Ham"))
        fig, ax = plt.subplots()
        ax.pie([spam, ham], labels=["Spam", "Ham"], autopct="%1.1f%%")
        st.pyplot(fig)

    with col2:
        st.subheader(text("emails_over_time", "Emails Over Time"))
        df["date"] = df["created_at"].dt.date
        st.line_chart(df.groupby("date").size())

    if "threat_label" in df.columns:
        st.subheader("Threat taxonomy")
        st.bar_chart(df["threat_label"].fillna("Unknown").value_counts())

    if "risk_score" in df.columns:
        st.subheader("High-risk trend")
        st.line_chart(df.groupby("date")["risk_score"].max())

    history_campaign_rows = get_history_campaign_candidates(user_id)
    if history_campaign_rows:
        engine = CampaignIntelligenceEngine()
        campaigns = engine.cluster(history_campaign_rows)
        if campaigns:
            st.subheader("Campaigns from saved history")
            st.dataframe(pd.DataFrame([campaign.to_dict() for campaign in campaigns]), use_container_width=True)

    review_rows = get_review_queue(limit=10)
    if review_rows:
        st.subheader("Adaptive learning review queue")
        st.dataframe(pd.DataFrame(review_rows), use_container_width=True)

    approved = export_retraining_data()
    if approved:
        st.caption(f"Approved retraining samples available: {len(approved)}")

    model_runs = discover_model_runs()
    if not model_runs.empty:
        st.subheader("Model lab runs")
        st.dataframe(model_runs, use_container_width=True)

    st.divider()
    st.subheader(text("recent_emails", "Recent Emails"))
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
    st.dataframe(recent[recent_columns], use_container_width=True)
