import os
import tempfile
import time

import pandas as pd
import streamlit as st

from src.app.formatting import _features_vi, _message_vi, _risk_level_vi, _threat_label_vi, _verdict_vi
from src.persistence import (
    AuthError,
    get_batch_history,
    get_single_history,
    login_user,
    register_user,
    save_batch_prediction,
    save_prediction_feedback,
    save_single_prediction,
)
from src.database.db import ping as db_ping
from src.workflows.prediction import PredictionPipeline
from src.security import CampaignIntelligenceEngine, QRImageAnalyzer, URLRiskModel
from src.security.campaign_intelligence import CampaignSummary
from src.utils.logger import get_logger

logger = get_logger(__name__)

_SESSION_DEFAULTS = {
    "logged_in": False,
    "user_id": None,
    "username": None,
    "auth_page": "login",
    "db_ok": None,
    "last_prediction_id": None,
}

@st.cache_resource
def get_pipeline() -> PredictionPipeline:
    return PredictionPipeline(load_models=True)


@st.cache_resource
def get_qr_analyzer() -> QRImageAnalyzer:
    return QRImageAnalyzer()


@st.cache_resource
def get_url_risk_model() -> URLRiskModel:
    return URLRiskModel()


@st.cache_resource
def get_campaign_engine() -> CampaignIntelligenceEngine:
    return CampaignIntelligenceEngine()


try:
    pipeline = get_pipeline()
except Exception as exc:
    st.error(f"KhÃ´ng thá»ƒ táº£i mÃ´ hÃ¬nh ML: {exc}")
    st.stop()


def check_db() -> bool:
    if "db_ok" not in st.session_state:
        st.session_state["db_ok"] = None
    if st.session_state["db_ok"] is None:
        st.session_state["db_ok"] = db_ping()
    return st.session_state["db_ok"]

def _safe_columns(df: pd.DataFrame, columns: list[str]) -> list[str]:
    return [column for column in columns if column in df.columns]


def _sidebar_auth() -> None:
    st.sidebar.title("TÃ i khoáº£n")

    if st.session_state["logged_in"]:
        st.sidebar.success(f"Xin chÃ o, **{st.session_state['username']}**!")
        if st.sidebar.button("ÄÄƒng xuáº¥t", use_container_width=True):
            for key in ("logged_in", "user_id", "username", "last_prediction_id"):
                st.session_state[key] = _SESSION_DEFAULTS[key]
            st.rerun()
        return

    if not check_db():
        st.sidebar.warning(
            "KhÃ´ng thá»ƒ káº¿t ná»‘i cÆ¡ sá»Ÿ dá»¯ liá»‡u.\n\n"
            "HÃ£y kiá»ƒm tra cÃ¡c biáº¿n mÃ´i trÆ°á»ng `DB_HOST`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`."
        )
        st.sidebar.info("Báº¡n váº«n cÃ³ thá»ƒ dÃ¹ng cháº¿ Ä‘á»™ khÃ¡ch Ä‘á»ƒ kiá»ƒm tra email Ä‘Æ¡n, URL vÃ  QR.")
        return

    col_login, col_register = st.sidebar.columns(2)
    if col_login.button(
        "ÄÄƒng nháº­p",
        use_container_width=True,
        type="primary" if st.session_state["auth_page"] == "login" else "secondary",
    ):
        st.session_state["auth_page"] = "login"
    if col_register.button(
        "ÄÄƒng kÃ½",
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
    st.sidebar.subheader("ÄÄƒng nháº­p")
    with st.sidebar.form("login_form", clear_on_submit=False):
        username = st.text_input("TÃªn Ä‘Äƒng nháº­p", max_chars=12)
        password = st.text_input("Máº­t kháº©u", type="password")
        submitted = st.form_submit_button("ÄÄƒng nháº­p", use_container_width=True)

    if not submitted:
        return

    if not username or not password:
        st.sidebar.error("Vui lÃ²ng nháº­p Ä‘áº§y Ä‘á»§ thÃ´ng tin.")
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
        st.sidebar.success("ÄÄƒng nháº­p thÃ nh cÃ´ng.")
        st.rerun()
    except AuthError as exc:
        st.sidebar.error(str(exc))
    except Exception as exc:
        st.sidebar.error(f"Lá»—i káº¿t ná»‘i: {exc}")


def _sidebar_register_form() -> None:
    st.sidebar.subheader("ÄÄƒng kÃ½")
    with st.sidebar.form("register_form", clear_on_submit=True):
        username = st.text_input("TÃªn Ä‘Äƒng nháº­p (tá»‘i Ä‘a 12 kÃ½ tá»±)", max_chars=12)
        password = st.text_input("Máº­t kháº©u", type="password")
        confirm = st.text_input("XÃ¡c nháº­n máº­t kháº©u", type="password", max_chars=12)
        submitted = st.form_submit_button("Táº¡o tÃ i khoáº£n", use_container_width=True)

    if not submitted:
        return

    if not username or not password:
        st.sidebar.error("Vui lÃ²ng nháº­p Ä‘áº§y Ä‘á»§ thÃ´ng tin.")
        return
    if password != confirm:
        st.sidebar.error("Máº­t kháº©u xÃ¡c nháº­n khÃ´ng khá»›p.")
        return

    try:
        user = register_user(username, password)
        st.sidebar.success(f"Táº¡o tÃ i khoáº£n **{user['username']}** thÃ nh cÃ´ng. Vui lÃ²ng Ä‘Äƒng nháº­p.")
        st.session_state["auth_page"] = "login"
        st.rerun()
    except AuthError as exc:
        st.sidebar.error(str(exc))
    except Exception as exc:
        st.sidebar.error(f"Lá»—i káº¿t ná»‘i: {exc}")


def _show_url_result(url_info: dict, title_prefix: str = "URL", expanded: bool = True) -> None:
    unavailable = url_info.get("risk_level") == "Unavailable" or url_info.get("verdict") == "AI_URL_MODEL_UNAVAILABLE"
    score_label = f"{url_info['risk_score']}/100" if not unavailable else "N/A"
    title = f"{title_prefix}: {_verdict_vi(url_info['verdict'])} - {score_label}"
    with st.expander(title, expanded=expanded):
        cols = st.columns(3)
        cols[0].metric("Äiá»ƒm rá»§i ro", score_label)
        cols[1].metric("Má»©c rá»§i ro", _risk_level_vi(url_info["risk_level"]))
        cols[2].metric("TÃªn miá»n", url_info["domain"] or "KhÃ´ng cÃ³")

        st.write("GiÃ¡ trá»‹ gá»‘c:")
        st.code(url_info["url"], language="text")
        st.write("ÄÃ­ch cuá»‘i cÃ¹ng:")
        st.code(url_info["final_url"], language="text")

        st.write("LÃ½ do Ä‘Ã¡nh giÃ¡:")
        for reason in url_info["reasons"]:
            st.write(f"- {_message_vi(reason)}")

        st.write("Äáº·c trÆ°ng URL Ä‘Ã£ trÃ­ch xuáº¥t:")
        ai_model = url_info.get("features", {}).get("ai_model", {})
        if ai_model:
            st.write("AI URL model:")
            st.json(ai_model)

        st.json(_features_vi(url_info["features"]))


def _tab_url_phishing() -> None:
    st.header("PhÃ¢n tÃ­ch URL phishing")
    st.caption("DÃ¡n má»™t hoáº·c nhiá»u URL. Há»‡ thá»‘ng cháº¥m Ä‘iá»ƒm rá»§i ro cá»¥c bá»™ vÃ  khÃ´ng má»Ÿ liÃªn káº¿t.")

    url_text = st.text_area(
        "Danh sÃ¡ch URL cáº§n phÃ¢n tÃ­ch",
        height=120,
        placeholder="https://paypa1-login.xyz/verify\nbit.ly/example",
    )

    if not st.button("PhÃ¢n tÃ­ch URL", type="primary"):
        return

    candidates = [line.strip() for line in url_text.splitlines() if line.strip()]
    if not candidates:
        st.warning("Vui lÃ²ng nháº­p Ã­t nháº¥t má»™t URL.")
        return

    logger.info("UI action | URL phishing analysis requested | count=%s", len(candidates))
    analyzer = get_url_risk_model()
    results = [analyzer.analyze(candidate).to_dict() for candidate in candidates]
    max_score = max(result["risk_score"] for result in results)
    model_unavailable_count = sum(
        result.get("features", {}).get("ai_model", {}).get("provenance", {}).get("risk_source") == "model_unavailable"
        or result.get("verdict") == "AI_URL_MODEL_UNAVAILABLE"
        for result in results
    )
    suspicious_count = sum(
        result["risk_score"] >= 35
        for result in results
        if result.get("verdict") != "AI_URL_MODEL_UNAVAILABLE"
    )

    cols = st.columns(3)
    cols[0].metric("Sá»‘ URL Ä‘Ã£ phÃ¢n tÃ­ch", len(results))
    cols[1].metric("URL Ä‘Ã¡ng nghi", suspicious_count)
    cols[2].metric("Äiá»ƒm rá»§i ro cao nháº¥t", f"{max_score}/100")

    if model_unavailable_count == len(results):
        st.info("ChÆ°a cÃ³ artifact AI URL model nÃªn há»‡ thá»‘ng khÃ´ng cháº¥m Ä‘iá»ƒm URL báº±ng rule. HÃ£y train model vÃ  cáº¥u hÃ¬nh ai_url_model_path.")
    elif max_score >= 80:
        st.error("CÃ³ Ã­t nháº¥t má»™t URL cÃ³ dáº¥u hiá»‡u phishing nghiÃªm trá»ng.")
    elif max_score >= 35:
        st.warning("CÃ³ Ã­t nháº¥t má»™t URL cÃ³ dáº¥u hiá»‡u Ä‘Ã¡ng nghi.")
    else:
        st.success("KhÃ´ng phÃ¡t hiá»‡n tÃ­n hiá»‡u phishing máº¡nh trong cÃ¡c URL Ä‘Ã£ nháº­p.")

    for index, result in enumerate(results, start=1):
        _show_url_result(result, title_prefix=f"URL #{index}", expanded=result["risk_score"] >= 35)


def _feedback_controls() -> None:
    prediction_id = st.session_state.get("last_prediction_id")
    if not st.session_state["logged_in"] or not prediction_id:
        return

    with st.expander("Pháº£n há»“i káº¿t quáº£ dá»± Ä‘oÃ¡n", expanded=False):
        with st.form("single_prediction_feedback"):
            feedback_display = st.radio("Káº¿t quáº£ nÃ y cÃ³ Ä‘Ãºng khÃ´ng?", ["ÄÃºng", "Sai"], horizontal=True)
            corrected_label = st.selectbox(
                "NhÃ£n Ä‘Ãºng náº¿u káº¿t quáº£ sai",
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
            note = st.text_area("Ghi chÃº cá»§a ngÆ°á»i phÃ¢n tÃ­ch", height=80)
            submitted = st.form_submit_button("LÆ°u pháº£n há»“i")

        if submitted:
            feedback = "correct" if feedback_display == "ÄÃºng" else "incorrect"
            feedback_id = save_prediction_feedback(
                user_id=st.session_state["user_id"],
                prediction_id=prediction_id,
                feedback=feedback,
                corrected_label=corrected_label if feedback == "incorrect" else None,
                note=note,
            )
            if feedback_id:
                st.success("ÄÃ£ lÆ°u pháº£n há»“i Ä‘á»ƒ phá»¥c vá»¥ review vÃ  cáº£i thiá»‡n mÃ´ hÃ¬nh.")
            else:
                st.warning("KhÃ´ng thá»ƒ lÆ°u pháº£n há»“i. HÃ£y kiá»ƒm tra migration database adaptive.")


def _tab_single_email() -> None:
    st.header("Kiá»ƒm tra email Ä‘Æ¡n")

    if not st.session_state["logged_in"]:
        st.info(
            "Báº¡n Ä‘ang dÃ¹ng cháº¿ Ä‘á»™ khÃ¡ch. Káº¿t quáº£ sáº½ khÃ´ng Ä‘Æ°á»£c lÆ°u. "
            "ÄÄƒng nháº­p Ä‘á»ƒ lÆ°u lá»‹ch sá»­ vÃ  gá»­i feedback."
        )

    email_text = st.text_area(
        "DÃ¡n ná»™i dung email vÃ o Ä‘Ã¢y",
        height=200,
        placeholder="Dear friend, I have a business proposal...",
    )

    if st.button("PhÃ¢n tÃ­ch email", type="primary"):
        if not email_text.strip():
            st.warning("Vui lÃ²ng nháº­p ná»™i dung email.")
            return

        logger.info("UI action | single email analysis requested | chars=%s", len(email_text))
        with st.spinner("Äang phÃ¢n tÃ­ch email..."):
            try:
                result = pipeline.predict_single_email(email_text)
            except Exception as exc:
                st.error(f"Lá»—i phÃ¢n tÃ­ch: {exc}")
                return

        risk_result = result["risk_analysis"]
        threat_result = result["threat_analysis"]
        prediction = result["prediction"]
        confidence = result.get("confidence")

        if prediction == "Spam":
            st.error("Email nÃ y Ä‘Æ°á»£c phÃ¢n loáº¡i lÃ  SPAM.")
        else:
            st.success("Email nÃ y Ä‘Æ°á»£c phÃ¢n loáº¡i lÃ  HAM.")

        if confidence is not None:
            st.metric("Äá»™ tin cáº­y", f"{confidence:.1f}%")

        st.subheader("PhÃ¢n tÃ­ch rá»§i ro MailGuard")
        provenance = result.get("model_provenance", {})
        risk_source = provenance.get("risk_source", "model_unavailable")
        st.caption(
            "Risk analysis source: "
            + ("AI threat model" if risk_source == "ai_model" else "AI model unavailable")
        )
        risk_cols = st.columns(4)
        risk_cols[0].metric("Äiá»ƒm rá»§i ro", f"{risk_result['risk_score']}/100" if risk_source == "ai_model" else "N/A")
        risk_cols[1].metric("Má»©c rá»§i ro", _risk_level_vi(risk_result["risk_level"]))
        risk_cols[2].metric(
            "NhÃ£n Ä‘e dá»a",
            _threat_label_vi(risk_result.get("threat_label", result.get("threat_label", "KhÃ´ng rÃµ"))),
        )
        risk_cols[3].metric("Káº¿t luáº­n", _verdict_vi(risk_result["verdict"]))

        final_message = f"Káº¿t luáº­n cuá»‘i cÃ¹ng: {_verdict_vi(risk_result['verdict'])} ({_risk_level_vi(risk_result['risk_level'])})"
        if risk_source == "model_unavailable":
            st.info("ChÆ°a cÃ³ artifact model AI nÃªn há»‡ thá»‘ng khÃ´ng cháº¥m Ä‘iá»ƒm rá»§i ro báº±ng rule. HÃ£y train model vÃ  cáº¥u hÃ¬nh path trÆ°á»›c khi demo risk scoring.")
        elif risk_result["risk_score"] >= 80:
            st.error(final_message)
        elif risk_result["risk_score"] >= 35:
            st.warning(final_message)
        else:
            st.success(final_message)

        st.subheader("ThÃ nh pháº§n phÃ¡t hiá»‡n Ä‘e dá»a")
        threat_cols = st.columns(4)
        threat_cols[0].metric("Äiá»ƒm ML spam", risk_result["components"].get("ml_spam_score"))
        threat_cols[1].metric("AI model", "CÃ³" if risk_source == "ai_model" else "ChÆ°a cÃ³")
        threat_cols[2].metric("URL trÃ­ch xuáº¥t", len(threat_result.get("urls", [])))
        threat_cols[3].metric("File Ä‘Ã¡ng chÃº Ã½", len(threat_result.get("risky_files", [])))

        with st.expander("VÃ¬ sao cÃ³ káº¿t quáº£ nÃ y?", expanded=risk_result["risk_score"] >= 35):
            st.write("Äiá»ƒm theo tá»«ng lá»›p:")
            st.json(result.get("class_scores", {}))

            st.write("Model provenance:")
            st.json(provenance)

            st.write("Chá»‰ bÃ¡o Ä‘Ã£ trÃ­ch xuáº¥t:")
            st.json(result.get("indicators", {}))

            st.write("LÃ½ do:")
            for reason in risk_result["reasons"]:
                st.write(f"- {_message_vi(reason)}")

            st.write("Khuyáº¿n nghá»‹:")
            for action in risk_result["recommended_actions"]:
                st.write(f"- {_message_vi(action)}")

            if threat_result.get("risky_files"):
                st.write("File Ä‘Ã¡ng nghi:")
                for filename in threat_result.get("risky_files", []):
                    st.code(filename, language="text")

        if threat_result.get("urls"):
            st.subheader("PhÃ¢n tÃ­ch URL trong email")
            for index, url_info in enumerate(threat_result.get("urls", []), start=1):
                _show_url_result(
                    url_info,
                    title_prefix=f"URL phÃ¡t hiá»‡n #{index}",
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
                st.caption("ÄÃ£ lÆ°u vÃ o lá»‹ch sá»­.")
            except Exception as exc:
                st.caption(f"KhÃ´ng thá»ƒ lÆ°u lá»‹ch sá»­: {exc}")

    _feedback_controls()


def _tab_batch() -> None:
    st.header("Xá»­ lÃ½ file MBOX")

    if not st.session_state["logged_in"]:
        st.warning("Chá»©c nÄƒng nÃ y yÃªu cáº§u Ä‘Äƒng nháº­p. Vui lÃ²ng Ä‘Äƒng nháº­p hoáº·c Ä‘Äƒng kÃ½ á»Ÿ thanh bÃªn trÃ¡i.")
        return

    uploaded_file = st.file_uploader("Táº£i lÃªn file MBOX", type=["mbox", "txt"])

    if uploaded_file is None or not st.button("Xá»­ lÃ½ file", type="primary"):
        return

    logger.info("UI action | MBOX batch analysis requested | file=%s", uploaded_file.name)
    with st.spinner("Äang xá»­ lÃ½ file, vui lÃ²ng chá»..."):
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
            st.error(f"Lá»—i xá»­ lÃ½ file: {exc}")
            return

    campaigns = df.attrs.get("campaigns", getattr(pipeline, "last_campaigns", []))
    spam_count = len(df[df["Prediction"] == "Spam"])
    ham_count = len(df[df["Prediction"] == "Ham"])

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Tá»•ng email", len(df))
    col2.metric("Spam", spam_count)
    col3.metric("Ham", ham_count)
    col4.metric("Chiáº¿n dá»‹ch", len(campaigns))

    st.subheader("Káº¿t quáº£ máº«u")
    preview_columns = _safe_columns(
        df,
        [
            "Time",
            "Subject",
            "Prediction",
            "Threat Label",
            "Risk Score",
            "Risk Level",
            "Verdict",
            "Risk Source",
            "Campaign ID",
        ],
    )
    preview_df = df[preview_columns].head(10).copy()
    preview_df = preview_df.rename(
        columns={
            "Time": "Thá»i gian",
            "Subject": "TiÃªu Ä‘á»",
            "Prediction": "Káº¿t quáº£",
            "Threat Label": "NhÃ£n Ä‘e dá»a",
            "Risk Score": "Äiá»ƒm rá»§i ro",
            "Risk Level": "Má»©c rá»§i ro",
            "Verdict": "Káº¿t luáº­n",
            "Campaign ID": "MÃ£ chiáº¿n dá»‹ch",
        }
    )
    if "NhÃ£n Ä‘e dá»a" in preview_df.columns:
        preview_df["NhÃ£n Ä‘e dá»a"] = preview_df["NhÃ£n Ä‘e dá»a"].map(_threat_label_vi)
    if "Má»©c rá»§i ro" in preview_df.columns:
        preview_df["Má»©c rá»§i ro"] = preview_df["Má»©c rá»§i ro"].map(_risk_level_vi)
    if "Káº¿t luáº­n" in preview_df.columns:
        preview_df["Káº¿t luáº­n"] = preview_df["Káº¿t luáº­n"].map(_verdict_vi)
    st.dataframe(preview_df, use_container_width=True)

    if campaigns:
        st.subheader("Chiáº¿n dá»‹ch Ä‘e dá»a phÃ¡t hiá»‡n Ä‘Æ°á»£c")
        campaign_df = pd.DataFrame(campaigns)
        campaign_columns = _safe_columns(
            campaign_df,
            ["campaign_id", "primary_threat_label", "risk_level", "risk_score", "email_count", "top_domains"],
        )
        campaign_display = campaign_df[campaign_columns].copy()
        campaign_display = campaign_display.rename(
            columns={
                "campaign_id": "MÃ£ chiáº¿n dá»‹ch",
                "primary_threat_label": "NhÃ£n Ä‘e dá»a chÃ­nh",
                "risk_level": "Má»©c rá»§i ro",
                "risk_score": "Äiá»ƒm rá»§i ro",
                "email_count": "Sá»‘ email",
                "top_domains": "TÃªn miá»n ná»•i báº­t",
            }
        )
        if "NhÃ£n Ä‘e dá»a chÃ­nh" in campaign_display.columns:
            campaign_display["NhÃ£n Ä‘e dá»a chÃ­nh"] = campaign_display["NhÃ£n Ä‘e dá»a chÃ­nh"].map(_threat_label_vi)
        if "Má»©c rá»§i ro" in campaign_display.columns:
            campaign_display["Má»©c rá»§i ro"] = campaign_display["Má»©c rá»§i ro"].map(_risk_level_vi)
        st.dataframe(campaign_display, use_container_width=True)

        engine = get_campaign_engine()
        campaign_objects = [
            CampaignSummary(**{key: item[key] for key in CampaignSummary.__dataclass_fields__ if key in item})
            for item in campaigns
        ]
        st.download_button(
            "Táº£i tÃ³m táº¯t chiáº¿n dá»‹ch (JSON)",
            data=engine.reports_json(campaign_objects),
            file_name=f"campaigns_{int(time.time())}.json",
            mime="application/json",
        )
        st.download_button(
            "Táº£i bÃ¡o cÃ¡o chiáº¿n dá»‹ch Ä‘áº§u tiÃªn (Markdown)",
            data=engine.markdown_report(campaign_objects[0], df.to_dict("records")),
            file_name=f"{campaign_objects[0].campaign_id}_report.md",
            mime="text/markdown",
        )
        with st.expander("Dá»¯ liá»‡u graph cá»§a chiáº¿n dá»‹ch Ä‘áº§u tiÃªn", expanded=False):
            st.json(engine.graph_for_campaign(campaign_objects[0], df.to_dict("records")))
    else:
        st.info("KhÃ´ng phÃ¡t hiá»‡n chiáº¿n dá»‹ch liÃªn quan trong batch nÃ y.")

    csv = df.to_csv(index=False).encode("utf-8")
    st.download_button(
        "Táº£i káº¿t quáº£ CSV",
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
            st.caption("ÄÃ£ lÆ°u thá»‘ng kÃª batch vÃ o lá»‹ch sá»­.")
        except Exception as exc:
            st.caption(f"KhÃ´ng thá»ƒ lÆ°u lá»‹ch sá»­ batch: {exc}")


def _tab_qr_image_security() -> None:
    st.header("PhÃ¢n tÃ­ch QR / Quishing")
    st.caption(
        "Táº£i lÃªn áº£nh email, áº£nh biÃªn lai hoáº·c áº£nh QR thanh toÃ¡n. "
        "Há»‡ thá»‘ng giáº£i mÃ£ QR vÃ  cháº¥m Ä‘iá»ƒm rá»§i ro mÃ  khÃ´ng má»Ÿ liÃªn káº¿t."
    )

    uploaded_image = st.file_uploader(
        "Táº£i áº£nh cÃ³ QR",
        type=["png", "jpg", "jpeg", "webp", "bmp"],
        key="qr_image_upload",
    )

    if uploaded_image is None:
        return

    image_bytes = uploaded_image.getvalue()
    st.image(image_bytes, caption=uploaded_image.name, use_container_width=True)

    if not st.button("PhÃ¢n tÃ­ch áº£nh QR", type="primary"):
        return

    logger.info("UI action | QR image analysis requested | file=%s | bytes=%s", uploaded_image.name, len(image_bytes))
    analyzer = get_qr_analyzer()
    with st.spinner("Äang phÃ¢n tÃ­ch QR..."):
        try:
            result = analyzer.analyze_image_bytes(image_bytes)
        except Exception as exc:
            st.error(f"KhÃ´ng thá»ƒ phÃ¢n tÃ­ch áº£nh: {exc}")
            return

    for warning in result.warnings:
        st.warning(_message_vi(warning))

    col1, col2, col3 = st.columns(3)
    col1.metric("Sá»‘ QR tÃ¬m tháº¥y", result.qr_count)
    col2.metric("Äiá»ƒm rá»§i ro", result.max_risk_score)
    col3.metric("Má»©c rá»§i ro", _risk_level_vi(result.risk_level))

    if not result.qr_found:
        st.info("KhÃ´ng phÃ¡t hiá»‡n QR code trong áº£nh.")
        return

    if result.max_risk_score >= 80:
        st.error(f"Káº¿t luáº­n cuá»‘i cÃ¹ng: {_verdict_vi(result.final_verdict)}")
    elif result.max_risk_score >= 35:
        st.warning(f"Káº¿t luáº­n cuá»‘i cÃ¹ng: {_verdict_vi(result.final_verdict)}")
    else:
        st.success(f"Káº¿t luáº­n cuá»‘i cÃ¹ng: {_verdict_vi(result.final_verdict)}")

    st.subheader("Ná»™i dung QR phÃ¡t hiá»‡n")
    for index, qr_result in enumerate(result.qr_results, start=1):
        _show_url_result(qr_result, title_prefix=f"QR #{index}", expanded=True)


def _tab_history() -> None:
    st.header("Lá»‹ch sá»­ phÃ¢n tÃ­ch")

    if not st.session_state["logged_in"]:
        st.warning("Chá»©c nÄƒng nÃ y yÃªu cáº§u Ä‘Äƒng nháº­p.")
        return

    if not check_db():
        st.error("KhÃ´ng thá»ƒ káº¿t ná»‘i cÆ¡ sá»Ÿ dá»¯ liá»‡u.")
        return

    h_single, h_batch = st.tabs(["Email Ä‘Æ¡n", "File MBOX"])

    with h_single:
        try:
            rows = get_single_history(st.session_state["user_id"])
            if not rows:
                st.info("ChÆ°a cÃ³ lá»‹ch sá»­ kiá»ƒm tra email Ä‘Æ¡n.")
            else:
                df = pd.DataFrame(rows)
                df = df.rename(
                    columns={
                        "id": "ID",
                        "prediction": "Káº¿t quáº£",
                        "confidence": "Äá»™ tin cáº­y (%)",
                        "created_at": "Thá»i gian",
                        "preview": "Ná»™i dung xem trÆ°á»›c",
                        "threat_label": "NhÃ£n Ä‘e dá»a",
                        "risk_score": "Äiá»ƒm rá»§i ro",
                        "risk_level": "Má»©c rá»§i ro",
                        "verdict": "Káº¿t luáº­n",
                        "campaign_id": "MÃ£ chiáº¿n dá»‹ch",
                    }
                )
                if "NhÃ£n Ä‘e dá»a" in df.columns:
                    df["NhÃ£n Ä‘e dá»a"] = df["NhÃ£n Ä‘e dá»a"].map(_threat_label_vi)
                if "Má»©c rá»§i ro" in df.columns:
                    df["Má»©c rá»§i ro"] = df["Má»©c rá»§i ro"].map(_risk_level_vi)
                if "Káº¿t luáº­n" in df.columns:
                    df["Káº¿t luáº­n"] = df["Káº¿t luáº­n"].map(_verdict_vi)
                st.dataframe(df, use_container_width=True)
        except Exception as exc:
            st.error(f"Lá»—i táº£i lá»‹ch sá»­: {exc}")

    with h_batch:
        try:
            rows = get_batch_history(st.session_state["user_id"])
            if not rows:
                st.info("ChÆ°a cÃ³ lá»‹ch sá»­ xá»­ lÃ½ file MBOX.")
            else:
                df = pd.DataFrame(rows)
                df = df.rename(
                    columns={
                        "id": "ID",
                        "file_name": "TÃªn file",
                        "total_emails": "Tá»•ng email",
                        "spam_count": "Spam",
                        "ham_count": "Ham",
                        "created_at": "Thá»i gian",
                    }
                )
                st.dataframe(df, use_container_width=True)
        except Exception as exc:
            st.error(f"Lá»—i táº£i lá»‹ch sá»­: {exc}")


