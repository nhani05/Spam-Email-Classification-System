import streamlit as st
import pandas as pd
import tempfile
import os
import time

from src.pipeline.prediction_pipeline import PredictionPipeline
from src.utils.history import save_single_prediction
from src.utils.db import get_connection

# Page config
st.set_page_config(
    page_title="Spam Email Classifier",
    page_icon="📧",
    layout="centered"
)

# Load model
@st.cache_resource
def get_pipeline():
    return PredictionPipeline(load_models=True)

try:
    pipeline = get_pipeline()
except Exception as e:
    st.error(f"Error loading models: {str(e)}")
    st.stop()

st.title("📧 Spam Email Classifier")
st.markdown("Classify emails as **Spam** or **Ham** using Machine Learning.")

# Tabs
tab1, tab2 = st.tabs(["Single Email", "Batch MBOX Processing"])

# ===============================
# TAB 1: SINGLE EMAIL
# ===============================
with tab1:
    st.header("Check a Single Email")

    email_text = st.text_area(
        "Paste email content:",
        height=200,
        placeholder="Dear friend, I have a business proposal..."
    )

    if st.button("Classify Email", type="primary"):
        if email_text.strip():
            with st.spinner("Analyzing..."):
                try:
                    result = pipeline.predict_single_email(email_text)

                    prediction = result["prediction"]
                    confidence = result.get("confidence", 0)

                    # ✅ SAVE TO MYSQL
                    save_single_prediction(
                        user_id=1,
                        email=email_text,
                        prediction=prediction.upper(),
                        confidence=confidence or 0
                    )

                    # UI
                    if prediction == "Spam":
                        st.error("🚨 This email is SPAM")
                    else:
                        st.success("✅ This email is HAM (Safe)")

                    if confidence:
                        st.info(f"Confidence: {confidence:.1f}%")

                except Exception as e:
                    st.error(f"Error: {str(e)}")
        else:
            st.warning("Please enter email content.")

# ===============================
# TAB 2: BATCH
# ===============================
with tab2:
    st.header("Process MBOX File")

    uploaded_file = st.file_uploader("Upload MBOX", type=["mbox", "txt"])

    if uploaded_file is not None:
        if st.button("Process File"):
            with st.spinner("Processing..."):
                try:
                    with tempfile.NamedTemporaryFile(delete=False, suffix=".mbox") as tmp:
                        tmp.write(uploaded_file.getvalue())
                        tmp_path = tmp.name

                    try:
                        df = pipeline.predict_mbox_file(tmp_path)

                        spam_count = len(df[df["Prediction"] == "Spam"])
                        ham_count = len(df[df["Prediction"] == "Ham"])

                        col1, col2 = st.columns(2)
                        col1.metric("Total Emails", len(df))
                        col2.metric("Spam Found", spam_count)

                        st.subheader("Preview")
                        st.dataframe(df[["Time", "Subject", "Prediction"]].head(10))

                        csv = df.to_csv(index=False).encode("utf-8")

                        st.download_button(
                            "Download CSV",
                            data=csv,
                            file_name=f"predictions_{int(time.time())}.csv",
                            mime="text/csv"
                        )

                    finally:
                        if os.path.exists(tmp_path):
                            os.unlink(tmp_path)

                except Exception as e:
                    st.error(f"Error: {str(e)}")

# ===============================
# HISTORY VIEW
# ===============================
st.divider()
st.subheader("📜 Prediction History")

if st.button("Load History"):
    try:
        conn = get_connection()
        df = pd.read_sql(
            "SELECT * FROM Single_Prediction_History ORDER BY created_at DESC",
            conn
        )
        st.dataframe(df)
        conn.close()
    except Exception as e:
        st.error(f"DB Error: {str(e)}")