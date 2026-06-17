import os
import re
import tempfile
import mailbox
import numpy as np
import streamlit as st
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans
from sklearn.metrics import pairwise_distances_argmin_min

def extract_text_from_mbox_bytes(file_bytes: bytes) -> str:
    """Trích xuất toàn bộ văn bản (text/plain) từ một file MBOX."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".mbox") as tmp:
        tmp.write(file_bytes)
        tmp_path = tmp.name
    
    text_parts = []
    try:
        mbox = mailbox.mbox(tmp_path)
        for message in mbox:
            if message.is_multipart():
                for part in message.walk():
                    if part.get_content_type() == 'text/plain':
                        payload = part.get_payload(decode=True)
                        if payload:
                            text_parts.append(payload.decode('utf-8', errors='ignore'))
            else:
                payload = message.get_payload(decode=True)
                if payload:
                    text_parts.append(payload.decode('utf-8', errors='ignore'))
    finally:
        if os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            
    return "\n\n---\n\n".join(text_parts)

def ml_extractive_summarize(text: str, num_sentences: int = 5) -> str:
    """
    Tóm tắt văn bản bằng Học máy Không giám sát (Unsupervised ML).
    Thuật toán: TF-IDF kết hợp K-Means Clustering.
    """
    # Xóa khoảng trắng thừa
    text = re.sub(r'\s+', ' ', text).strip()
    if not text:
        return ""

    # Tách văn bản thành các câu
    sentences = re.split(r'(?<=[.!?]) +', text)
    if len(sentences) <= num_sentences:
        return text

    # 1. Feature Engineering: Dùng TF-IDF để học từ vựng và chuyển câu thành vector
    vectorizer = TfidfVectorizer(stop_words='english')
    try:
        X = vectorizer.fit_transform(sentences)
    except ValueError:
        return text # Lỗi nếu tập không có từ vựng nào hợp lệ

    # 2. Học máy (Machine Learning): Dùng K-Means để phân cụm (Clustering)
    k = min(num_sentences, len(sentences))
    # Khởi tạo mô hình K-Means
    kmeans = KMeans(n_clusters=k, random_state=42, n_init=10)
    # Tiến hành "Train" (Fit) để tìm ra các tâm cụm (centroids) mang ý nghĩa khác nhau
    kmeans.fit(X)

    # 3. Trích xuất: Tìm câu có ngữ nghĩa sát với tâm cụm nhất để làm câu tóm tắt
    avg = []
    for j in range(k):
        idx = np.where(kmeans.labels_ == j)[0]
        if len(idx) == 0:
            continue
        closest, _ = pairwise_distances_argmin_min(kmeans.cluster_centers_[j].reshape(1, -1), X[idx])
        avg.append(idx[closest[0]])

    # Sắp xếp lại câu theo thứ tự ban đầu trong văn bản
    avg.sort()
    summary = [sentences[i] for i in avg]
    
    return " ".join(summary)

def show_email_summarizer_tab():
    """Giao diện UI cho tab Tóm tắt Email sử dụng Học Máy"""
    st.header("Tóm tắt nội dung Email bằng Học Máy (ML)")
    st.caption("Sử dụng thuật toán học máy không giám sát K-Means Clustering và TF-IDF để tự động học, phân nhóm và trích xuất ý chính.")

    st.subheader("Nhập dữ liệu")
    input_type = st.radio("Chọn cách nhập dữ liệu", ["Nhập văn bản (Paste nội dung)", "Tải lên file MBOX"], horizontal=True)
    combined_text = ""

    if input_type == "Nhập văn bản (Paste nội dung)":
        text_input = st.text_area(
            "Dán nội dung của 1 hoặc nhiều email vào đây:", 
            height=200, 
            placeholder="Email 1: ...\n\nEmail 2: ..."
        )
        if text_input:
            combined_text = text_input
    else:
        uploaded_file = st.file_uploader("Tải lên file MBOX chứa các email cần gộp", type=["mbox", "txt"], key="mbox_summarizer_llm")
        if uploaded_file is not None:
            with st.spinner("Đang đọc file MBOX..."):
                combined_text = extract_text_from_mbox_bytes(uploaded_file.getvalue())
                st.success(f"Đã trích xuất thành công {len(combined_text)} ký tự từ file {uploaded_file.name}")

    num_sentences = st.slider("Số lượng câu tóm tắt mong muốn", min_value=1, max_value=20, value=5)

    if st.button("Tiến hành chạy thuật toán (Train & Rút trích)", type="primary"):
        if not combined_text.strip():
            st.warning("Vui lòng cung cấp nội dung email để mô hình ML phân tích.")
        else:
            with st.spinner("Hệ thống đang tiến hành Vector hóa (TF-IDF) và Phân cụm (K-Means Clustering)..."):
                try:
                    summary = ml_extractive_summarize(combined_text, num_sentences)
                    
                    st.subheader("Kết quả trích xuất từ Mô hình ML")
                    st.info(summary)
                    
                    with st.expander("Xem toàn bộ nội dung gốc"):
                        st.text(combined_text)
                except Exception as e:
                    st.error(f"Đã xảy ra lỗi trong quá trình chạy học máy: {str(e)}")