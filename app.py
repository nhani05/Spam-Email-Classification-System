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
        "Há»‡ thá»‘ng phÃ¢n tÃ­ch an toÃ n email: phÃ¢n loáº¡i Spam/Ham, cháº¥m Ä‘iá»ƒm rá»§i ro, "
        "phÃ¡t hiá»‡n phishing URL, QR/quishing vÃ  campaign táº¥n cÃ´ng."
    )

    if st.session_state["logged_in"]:
        tab_dashboard, tab_single, tab_batch, tab_history = st.tabs(
            ["Báº£ng Ä‘iá»u khiá»ƒn", "Email Ä‘Æ¡n", "File MBOX", "Lá»‹ch sá»­"]
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

        with tab_history:
            _tab_history()
    else:
        tab_single, tab_batch = st.tabs(["Email Ä‘Æ¡n", "File MBOX (cáº§n Ä‘Äƒng nháº­p)"])
        with tab_single:
            _tab_single_email()
            st.divider()
            _tab_url_phishing()
            st.divider()
            _tab_qr_image_security()
        with tab_batch:
            _tab_batch()


if __name__ == "__main__":
    main()
