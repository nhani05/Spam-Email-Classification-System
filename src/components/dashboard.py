import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from src.auth.auth import get_single_history


def show_dashboard(user_id):
    st.header("📊 Spam Detection Dashboard")

    # ===== LOAD DATA (FIX: dùng MySQL qua auth.py) =====
    rows = get_single_history(user_id)

    if not rows:
        st.warning("No data available")
        return

    df = pd.DataFrame(rows)

    # ===== FIX tên cột =====
    df["created_at"] = pd.to_datetime(df["created_at"])

    # prediction trong DB là 'SPAM' / 'HAM'
    df["prediction"] = df["prediction"].str.upper()

    # ===== STATS =====
    total = len(df)
    spam = (df["prediction"] == "SPAM").sum()
    ham = (df["prediction"] == "HAM").sum()

    spam_rate = round((spam / total) * 100, 2)
    ham_rate = round((ham / total) * 100, 2)

    # ===== KPI =====
    col1, col2, col3 = st.columns(3)
    col1.metric("📨 Total Emails", total)
    col2.metric("🚫 Spam %", f"{spam_rate}%")
    col3.metric("✅ Ham %", f"{ham_rate}%")

    st.divider()

    # ===== CHART =====
    col1, col2 = st.columns(2)

    # Pie chart
    with col1:
        st.subheader("Spam vs Ham")
        fig, ax = plt.subplots()
        ax.pie([spam, ham], labels=["Spam", "Ham"], autopct='%1.1f%%')
        st.pyplot(fig)

    # Line chart
    with col2:
        st.subheader("Emails Over Time")
        df["date"] = df["created_at"].dt.date
        trend = df.groupby("date").size()
        st.line_chart(trend)

    st.divider()

    # ===== RECENT =====
    st.subheader("📜 Recent Emails")

    recent = df.sort_values("created_at", ascending=False).head(10)

    st.dataframe(
        recent[["preview", "prediction", "created_at"]],
        use_container_width=True
    )