# MailGuard AI - Spam Email Classification System

Cap nhat: 18/06/2026

MailGuard AI la ung dung Streamlit phan loai email `Spam`/`Ham` bang Machine Learning. Du an tap trung vao spam classifier, xu ly MBOX, lich su nguoi dung, dashboard, feedback, tom tat email bang local AI va chatbot RAG tren hop thu.

## Tinh Nang Chinh

- Phan loai email don thanh `Spam` hoac `Ham`.
- Hien thi do tin cay neu model ho tro `predict_proba`.
- Xu ly file MBOX theo lo va xuat ket qua CSV.
- Dang ky, dang nhap, dang xuat va luu lich su bang MySQL.
- Dashboard cho nguoi dung da dang nhap: tong email, ti le Spam/Ham, email theo thoi gian, review queue va Model Lab runs.
- Feedback loop: nguoi dung danh dau ket qua dung/sai de phuc vu review va cai thien model.
- Tom tat email bang local AI tren van ban paste hoac file MBOX.
- Chatbot RAG tren file MBOX: tao vector store FAISS va hoi dap theo noi dung email.
- Pipeline huan luyen lai spam classifier va sinh artifact Model Lab.

## Cong Nghe Su Dung

- Python 3.13+
- Streamlit
- Pandas, Scikit-learn
- TF-IDF word features, character n-gram features va numeric features
- MySQL Connector, python-dotenv
- Transformers, Torch, SentencePiece cho local summarizer
- LangChain, FAISS, sentence-transformers cho RAG chatbot

## Cau Truc Thu Muc

```text
.
|-- app.py                              # Entrypoint Streamlit
|-- README.md                           # Tong quan va cach chay nhanh
|-- requirements.txt                    # Dependencies pip
|-- pyproject.toml                      # Cau hinh uv/Python
|-- data/
|   |-- dataset/dataset.csv             # Dataset huan luyen mac dinh
|   `-- models/v1/                      # Model/vectorizer fallback
|-- docs/                               # Tai lieu cau truc va demo
|-- notebooks/                          # Notebook thu nghiem
|-- outputs/                            # Artifact local khi train/chay AI
|-- src/
|   |-- config/config.py                # Cau hinh dataset/model/output
|   |-- features/
|   |   |-- auth/                       # Auth, history, feedback, review queue
|   |   |-- dashboard/                  # Dashboard va Model Lab view
|   |   |-- email_summarizer/           # Tom tat email bang local AI
|   |   |-- rag_chatbot/                # Chatbot RAG tren MBOX
|   |   `-- spam_classifier/            # Train/predict spam classifier
|   |-- infrastructure/database/        # MySQL schema va adapter
|   `-- shared/                         # Logger, email utils, state
`-- venv/                               # Moi truong ao local, khong commit
```

## Cai Dat

Tao va kich hoat moi truong ao:

```bash
python -m venv venv
venv\Scripts\activate
```

Cai dependencies:

```bash
pip install -r requirements.txt
```

Neu dung `uv`:

```bash
uv sync
```

## Cau Hinh Database

Database chi bat buoc khi demo dang nhap, lich su, dashboard, MBOX batch history va feedback. Neu khong co MySQL, app van demo duoc che do khach: email don, tom tat va chatbot.

Tao database MySQL:

```bash
mysql -u root -p < src/infrastructure/database/schema.sql
```

Tao file `.env` o thu muc goc:

```env
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=your_password
DB_NAME=spam_detection
```

## Cau Hinh Model

Ung dung tu tim artifact spam classifier moi nhat trong `outputs/` neu thu muc do co du model va vectorizer. Neu khong tim thay, app fallback ve:

```text
data/models/v1/model.pkl
data/models/v1/feature.pkl
```

Logic nam trong `src/config/config.py`.

## Chay Ung Dung

```bash
streamlit run app.py
```

Mo URL Streamlit hien tren terminal, thuong la:

```text
http://localhost:8501
```

## Luong Su Dung Nhanh

Che do khach:

- `Email don`: dan noi dung email va nhan ket qua `Spam`/`Ham`.
- `Tom tat`: paste van ban hoac upload MBOX de local AI tom tat.
- `Chatbot`: upload MBOX va hoi dap theo noi dung email.
- `File MBOX (can dang nhap)`: hien canh bao yeu cau dang nhap.

Che do da dang nhap:

- `Bang dieu khien`: thong ke Spam/Ham, email theo thoi gian, review queue va Model Lab.
- `Email don`: phan loai email va luu lich su.
- `File MBOX`: xu ly batch va xuat CSV.
- `Tom tat`: local AI summarizer.
- `Chatbot`: RAG chatbot tren MBOX.
- `Lich su`: xem lich su email don va batch MBOX.

## Huan Luyen Lai Spam Classifier

Dataset mac dinh:

```text
data/dataset/dataset.csv
```

Chay pipeline:

```bash
python -m src.features.spam_classifier.training_pipeline
```

Pipeline se doc dataset, tien xu ly label, chia train/test, vector hoa, train nhieu model, chon model tot nhat va luu artifact vao `outputs/<timestamp>/`.

## Kiem Tra Nhanh

```bash
python -m compileall src app.py
```

## Tai Lieu Quan Trong

- `docs/HUONG_DAN_DEMO_DU_AN.md`: kich ban demo hien tai.
- `docs/PROJECT_STRUCTURE_LOCAL.md`: giai thich cau truc thu muc hien tai.

## Luu Y Demo

- Chuan bi san input email an toan, email spam va file MBOX mau.
- Neu demo dashboard/history/feedback/MBOX batch history, hay bat MySQL va tao schema truoc.
- Khong nen train model live neu thoi gian demo ngan, vi pipeline co the mat thoi gian.
