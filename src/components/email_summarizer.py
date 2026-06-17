import os
import re
import tempfile
import mailbox
import numpy as np
import streamlit as st

import sys

# Cố gắng import các thư viện AI
try:
    import torch
            
    from transformers import AutoTokenizer, AutoModelForSeq2SeqLM
    
    # --- VÁ LỖI THƯ VIỆN TRANSFORMERS MỚI NHẤT ---
    import transformers.models.t5.tokenization_t5 as t5_tok
    if hasattr(t5_tok, "Unigram"):
        orig_unigram = t5_tok.Unigram
        def patched_unigram(vocab, *args, **kwargs):
            if isinstance(vocab, dict):
                vocab = list(vocab.items())
            return orig_unigram(vocab, *args, **kwargs)
        t5_tok.Unigram = patched_unigram
except ImportError:
    torch = None
    AutoTokenizer = None
    AutoModelForSeq2SeqLM = None

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
            
    # Thêm dải phân cách để AI dễ nhận biết các email khác nhau
    return "\n\n---\n\n".join(text_parts)

@st.cache_resource
def load_local_summarizer():
    """Tải mô hình AI và Tokenizer vào RAM (chỉ tải 1 lần)."""
    if AutoTokenizer is None or AutoModelForSeq2SeqLM is None:
        return None
        
    # Tự động dùng Card đồ họa (GPU) nếu có để chạy nhanh hơn
    device = "cuda" if torch.cuda.is_available() else "cpu"
    
    # Dùng mô hình "nhà trồng" vừa train xong
    model_path = "outputs/my_tiny_summarizer"
    tokenizer = AutoTokenizer.from_pretrained(model_path, use_fast=False, legacy=True)
    model = AutoModelForSeq2SeqLM.from_pretrained(model_path).to(device)
    return tokenizer, model, device

def local_ai_summarize(text: str, max_length: int = 150, min_length: int = 40) -> str:
    """Tóm tắt văn bản bằng AI chạy trực tiếp trên máy."""
    summarizer = load_local_summarizer()
    if not summarizer:
        raise RuntimeError("Thư viện 'transformers' hoặc 'torch' chưa được cài đặt. Vui lòng chạy: pip install transformers torch")
        
    tokenizer, model, device = summarizer
    
    # Chia nhỏ văn bản vì mô hình cục bộ thường giới hạn 1024 token/lần đọc
    # 3000 ký tự là một ước lượng an toàn cho 1024 token
    chunk_size = 3000
    chunks = [text[i:i+chunk_size] for i in range(0, len(text), chunk_size)]
    
    summaries = []
    for chunk in chunks:
        # Bỏ qua các đoạn quá ngắn (vd: rác, chữ ký)
        if len(chunk.split()) > 20: 
            # ViT5 yêu cầu thêm tiền tố "vietnews: " trước văn bản để hiểu đây là tác vụ tóm tắt
            prompt = "vietnews: " + chunk
            inputs = tokenizer(prompt, max_length=1024, truncation=True, return_tensors="pt").to(device)
            
            # AI tiến hành sinh (generate) bản tóm tắt
            summary_ids = model.generate(
                inputs["input_ids"], 
                max_length=max_length, 
                min_length=min_length, 
                num_beams=4, # Dùng beam search để kết quả mượt mà hơn
                length_penalty=2.0,
                early_stopping=True
            )
            
            # Dịch ngược ID thành văn bản
            summary_text = tokenizer.decode(summary_ids[0], skip_special_tokens=True)
            summaries.append(summary_text)
            
    return "\n\n".join(summaries)

def show_email_summarizer_tab():
    """Giao diện UI cho tab Tóm tắt Email sử dụng Local AI"""
    st.header("Tóm tắt nội dung Email bằng AI cục bộ (Local AI)")
    st.caption("Mô hình AI tự chạy trên máy của bạn, tự đọc hiểu và viết lại bản tóm tắt mà không cần gửi dữ liệu ra ngoài.")

    if AutoTokenizer is None:
        st.error("⚠️ Bạn cần cài đặt thư viện để chạy tính năng này. Mở terminal và chạy lệnh:\n\n`pip install transformers torch sentencepiece`")
        return
        
    st.subheader("Nhập dữ liệu")
    input_type = st.radio("Chọn cách nhập dữ liệu", ["Nhập văn bản (Paste nội dung)", "Tải lên file MBOX"], horizontal=True, key="summarizer_input_type")
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
        uploaded_file = st.file_uploader("Tải lên file MBOX chứa các email cần gộp", type=["mbox", "txt"], key="mbox_summarizer_local_ai")
        if uploaded_file is not None:
            with st.spinner("Đang đọc file MBOX..."):
                combined_text = extract_text_from_mbox_bytes(uploaded_file.getvalue())
                st.success(f"Đã trích xuất thành công {len(combined_text)} ký tự từ file {uploaded_file.name}")

    st.subheader("Tùy chỉnh độ dài")
    col1, col2 = st.columns(2)
    min_len = col1.slider("Độ dài tóm tắt tối thiểu (số từ)", min_value=10, max_value=100, value=40)
    max_len = col2.slider("Độ dài tóm tắt tối đa (số từ)", min_value=50, max_value=300, value=150)


    if st.button("Tóm tắt ngay bằng AI", type="primary"):
        if not combined_text.strip():
            st.warning("Vui lòng cung cấp nội dung email để AI tóm tắt.")
        else:
            with st.spinner("AI đang khởi động và tiến hành đọc hiểu để tóm tắt văn bản, vui lòng đợi..."):
                try:
                    summary = local_ai_summarize(combined_text, max_length=max_len, min_length=min_len)
                    
                    st.subheader("Kết quả tóm tắt từ AI cục bộ")
                    st.info(summary)
                    
                    with st.expander("Xem toàn bộ nội dung đã gộp"):
                        st.text(combined_text)
                except Exception as e:
                    st.error(f"Đã xảy ra lỗi khi chạy AI cục bộ: {str(e)}")