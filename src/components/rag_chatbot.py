import os
import tempfile
import mailbox
import streamlit as st
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_core.documents import Document
from langchain_community.vectorstores import FAISS
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_core.prompts import PromptTemplate
from langchain_community.llms.huggingface_pipeline import HuggingFacePipeline
from transformers import pipeline, AutoTokenizer, AutoModelForCausalLM
import torch


@st.cache_resource
def load_chat_model():
    """Tải mô hình ngôn ngữ lớn chuyên biệt cho Chatbot (Qwen2.5)"""
    # Dùng Qwen2.5 0.5B: Siêu nhẹ (~1GB) nhưng cực kỳ thông minh trong việc hỏi đáp và logic
    model_name = "Qwen/Qwen2.5-0.5B-Instruct"
    device = "cuda" if torch.cuda.is_available() else "cpu"
    
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForCausalLM.from_pretrained(model_name).to(device)
    
    pipe = pipeline(
        "text-generation", 
        model=model, 
        tokenizer=tokenizer, 
        max_new_tokens=512, 
        device=0 if device == "cuda" else -1,
        return_full_text=False # Rất quan trọng để AI không lặp lại câu hỏi
    )
    return pipe

@st.cache_resource
def get_embedding_model():
    """Tải mô hình embedding (chỉ tải 1 lần)"""
    # Dùng một mô hình embedding đa ngôn ngữ, nhẹ và hiệu quả
    return HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")

def build_vector_db(uploaded_file):
    """Xây dựng cơ sở dữ liệu vector từ file MBOX được tải lên."""
    if uploaded_file is None:
        return None

    with tempfile.NamedTemporaryFile(delete=False, suffix=".mbox") as tmp:
        tmp.write(uploaded_file.getvalue())
        tmp_path = tmp.name

    try:
        # 1. Đọc toàn bộ email từ file MBOX bằng thư viện chuẩn của Python
        mbox = mailbox.mbox(tmp_path)
        docs = []
        for i, message in enumerate(mbox):
            text_parts = []
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
            
            content = "\n".join(text_parts).strip()
            if content:
                # Lấy thêm tiêu đề làm metadata để AI trích dẫn cho chuẩn
                subject = str(message.get('Subject', f'Email {i+1}'))
                docs.append(Document(page_content=content, metadata={"source": subject}))

        # 2. Chia nhỏ các email thành các đoạn văn bản (chunks)
        text_splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=150)
        texts = text_splitter.split_documents(docs)

        # 3. Dùng mô hình embedding để "dịch" các đoạn văn bản thành vector
        embeddings = get_embedding_model()

        # 4. Lưu các vector vào FAISS - một cơ sở dữ liệu vector siêu nhanh
        vector_store = FAISS.from_documents(texts, embedding=embeddings)
        return vector_store

    finally:
        if os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

def show_rag_chatbot_tab():
    """Giao diện cho Tab Chatbot RAG"""
    st.header("Trò chuyện với Hộp thư của bạn (RAG)")
    st.caption("Tải lên file MBOX, AI sẽ đọc và bạn có thể hỏi bất cứ điều gì về nội dung bên trong.")

    uploaded_file = st.file_uploader("Tải lên file MBOX của bạn", type=["mbox", "txt"], key="rag_mbox_uploader")

    if uploaded_file:
        if "vector_store" not in st.session_state or st.session_state.get("rag_file_name") != uploaded_file.name:
            with st.spinner("AI đang đọc và 'số hóa' hàng ngàn email... Quá trình này có thể mất vài phút."):
                st.session_state.vector_store = build_vector_db(uploaded_file)
                st.session_state.rag_file_name = uploaded_file.name
                
                # Khởi tạo mô hình và chuỗi hỏi đáp thủ công (bỏ qua langchain.chains bị lỗi)
                pipe = load_chat_model()
                st.session_state.llm = HuggingFacePipeline(pipeline=pipe)
                
                prompt_template = """<|im_start|>system
Bạn là một trợ lý AI thông minh. Hãy đọc kỹ thông tin email được cung cấp và trả lời câu hỏi của người dùng. Nếu được yêu cầu thống kê hoặc đếm số lượng, hãy đếm thật cẩn thận và đưa ra con số chính xác.<|im_end|>
<|im_start|>user

Thông tin email: {context}

Câu hỏi: {question}<|im_end|>
<|im_start|>assistant
"""
                st.session_state.qa_prompt = PromptTemplate.from_template(prompt_template)
                
            st.success(f"Đã sẵn sàng! Bạn có thể bắt đầu hỏi về nội dung trong file '{uploaded_file.name}'.")

        if "messages" not in st.session_state:
            st.session_state.messages = []

        for message in st.session_state.messages:
            with st.chat_message(message["role"]):
                st.markdown(message["content"])

        if prompt := st.chat_input("Hỏi AI về nội dung email..."):
            st.session_state.messages.append({"role": "user", "content": prompt})
            with st.chat_message("user"):
                st.markdown(prompt)

            with st.spinner("AI đang tìm kiếm và suy nghĩ..."):
                # Lục tìm email thủ công bằng FAISS
                retriever = st.session_state.vector_store.as_retriever(search_kwargs={"k": 3})
                docs = retriever.invoke(prompt)
                context = "\n\n".join(doc.page_content for doc in docs)
                
                # Đưa vào AI xử lý
                chain = st.session_state.qa_prompt | st.session_state.llm
                response = chain.invoke({"context": context, "question": prompt})
                
                st.session_state.messages.append({"role": "assistant", "content": response})
                with st.chat_message("assistant"):
                    st.markdown(response)
                    with st.expander("Xem các đoạn email liên quan"):
                        for doc in docs:
                            st.write(doc.page_content)
                            st.write("---")