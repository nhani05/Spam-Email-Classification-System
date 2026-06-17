"""
MailGuard AI - ung dung Streamlit.

Quyen truy cap:
- Khach: kiem tra email don, phan tich URL va phan tich QR.
- Nguoi dung da dang nhap: them dashboard, xu ly MBOX, lich su va feedback.
"""

import streamlit as st

from src.app.dashboard import show_dashboard
from src.app.pages import (
    _sidebar_auth,
    _tab_batch,
    _tab_history,
    _tab_qr_image_security,
    _tab_single_email,
    _tab_url_phishing,
)
from src.components.email_summarizer import show_email_summarizer_tab
from src.components.rag_chatbot import show_rag_chatbot_tab


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


def main() -> None:
    _sidebar_auth()

    st.title("MailGuard AI")
    st.markdown(
        "He thong phan tich an toan email: phan loai Spam/Ham, cham diem rui ro, "
        "phat hien phishing URL, QR/quishing va campaign tan cong."
    )

    if st.session_state["logged_in"]:
        tab_dashboard, tab_single, tab_batch, tab_summary, tab_chatbot, tab_history = st.tabs(
            ["Bang dieu khien", "Email don", "File MBOX", "Tom tat", "Chatbot", "Lich su"]
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

        with tab_chatbot:
            show_rag_chatbot_tab()

        with tab_history:
            _tab_history()
    else:
        tab_single, tab_summary, tab_chatbot, tab_batch = st.tabs(
            ["Email don", "Tom tat", "Chatbot", "File MBOX (can dang nhap)"]
        )
        with tab_single:
            _tab_single_email()
            st.divider()
            _tab_url_phishing()
            st.divider()
            _tab_qr_image_security()
        with tab_summary:
            show_email_summarizer_tab()
        with tab_chatbot:
            show_rag_chatbot_tab()
        with tab_batch:
            _tab_batch()


if __name__ == "__main__":
    main()
