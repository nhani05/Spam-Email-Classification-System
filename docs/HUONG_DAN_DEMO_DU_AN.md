# Huong Dan Demo Du An MailGuard AI

Cap nhat: 18/06/2026

Tai lieu nay dung de demo cac feature hien co sau khi da bo cac phan phan tich rule-based URL/QR/threat. Trong demo, nen trinh bay du an nhu mot he thong phan loai Spam/Ham co them dashboard, feedback, tom tat email va chatbot.

## 1. Thong Diep Mo Dau

Noi ngan gon:

```text
Du an MailGuard AI phan loai email thanh Spam hoac Ham bang Machine Learning.

Ngoai phan loai email don, he thong con co:
- Xu ly file MBOX theo lo.
- Luu lich su va feedback khi dang nhap.
- Dashboard thong ke Spam/Ham.
- Tom tat email bang local AI.
- Chatbot hoi dap tren hop thu bang RAG.
```

## 2. Chuan Bi Truoc Khi Demo

### 2.1 Moi Truong

```bash
venv\Scripts\activate
pip install -r requirements.txt
```

Neu dung `uv`:

```bash
uv sync
```

### 2.2 Database

Can MySQL neu demo dang nhap, dashboard, lich su, feedback va MBOX batch history.

```bash
mysql -u root -p < src/infrastructure/database/schema.sql
```

File `.env`:

```env
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=your_password
DB_NAME=spam_detection
```

Neu MySQL chua san sang, van demo duoc che do khach: email don, tom tat va chatbot.

### 2.3 Artifact Can Co

Spam classifier fallback:

```text
data/models/v1/model.pkl
data/models/v1/feature.pkl
```

Local AI summarizer neu demo tinh nang tom tat:

```text
outputs/email_summarizer_vi/
```

### 2.4 Smoke Check

```bash
python -m compileall src app.py
```

### 2.5 Chay App

```bash
streamlit run app.py
```

Mo:

```text
http://localhost:8501
```

## 3. Thu Tu Demo Khuyen Nghi

Neu co 10-15 phut:

1. Gioi thieu MailGuard AI va sidebar tai khoan.
2. Demo email an toan.
3. Demo email spam.
4. Dang nhap va demo dashboard.
5. Demo MBOX batch.
6. Demo lich su va feedback loop.
7. Demo tom tat email bang local AI.
8. Demo chatbot RAG tren MBOX.
9. Noi ve training pipeline va Model Lab.

Neu chi co 5-7 phut, uu tien email don, dashboard, MBOX batch va feedback. Khong train live.

## 4. Demo Sidebar Tai Khoan

### Cach Thao Tac

1. Mo app.
2. Chi vao sidebar `Tai khoan`.
3. Noi rang ung dung co 2 che do:
   - Khach: dung duoc email don, tom tat, chatbot.
   - Da dang nhap: co them dashboard, MBOX batch, lich su va feedback.
4. Neu MySQL da cau hinh, dang nhap bang user mau trong schema nhu `alice` / `pass123`, hoac dang ky user moi.

## 5. Demo Email Don An Toan

Tab: `Email don`

### Input

```text
Hi team,

Please review the project report before our meeting tomorrow morning.
I updated the dashboard screenshots and attached the latest notes.

Thanks.
```

### Thao Tac

1. Dan noi dung vao o email.
2. Bam `Phan tich email`.
3. Chi vao ket qua:
   - `Email nay duoc phan loai la HAM`.
   - `Do tin cay` neu model ho tro.

### Ket Qua Mong Doi

- Prediction: `Ham`.
- Neu model khong co `predict_proba`, do tin cay co the khong hien.

## 6. Demo Email Spam

Tab: `Email don`

### Input

```text
Congratulations! You have won a free prize.
Click now to claim your reward and send your account information immediately.
```

### Thao Tac

1. Dan input vao `Email don`.
2. Bam `Phan tich email`.
3. Neu da dang nhap, ket qua se duoc luu vao lich su.

### Ket Qua Mong Doi

- Prediction thuong la `Spam`.
- Do tin cay hien neu model ho tro.

## 7. Demo Dashboard

Can dang nhap va database hoat dong.

Tab: `Bang dieu khien`

Noi khi demo:

```text
Dashboard tong hop lich su phan loai email cua nguoi dung:
- Tong email.
- Ti le Spam.
- Ti le Ham.
- Bieu do Spam/Ham.
- So email theo thoi gian.
- Review queue va Model Lab runs neu co.
```

## 8. Demo MBOX Batch

Can dang nhap.

Tab: `File MBOX`

### Thao Tac

1. Upload file `.mbox` hoac `.txt`.
2. Bam `Xu ly file`.
3. Xem thong ke tong email, Spam, Ham.
4. Xem bang ket qua mau.
5. Tai file CSV ket qua.

## 9. Demo Lich Su Va Feedback

### Lich Su

Tab: `Lich su`

- Xem lich su email don.
- Xem lich su xu ly file MBOX.

### Feedback

Sau khi phan loai email don:

1. Mo expander `Phan hoi ket qua du doan`.
2. Chon ket qua dung/sai.
3. Neu sai, chon nhan dung `Spam` hoac `Ham`.
4. Them ghi chu neu can.
5. Bam `Luu phan hoi`.

## 10. Demo Tom Tat Email

Tab: `Tom tat`

### Thao Tac

1. Paste noi dung email hoac upload MBOX.
2. Chay tom tat.
3. Giai thich day la local AI summarizer, phu hop khi can doc nhanh noi dung hop thu.

## 11. Demo Chatbot RAG

Tab: `Chatbot`

### Thao Tac

1. Upload MBOX.
2. Tao vector store.
3. Dat cau hoi ve noi dung email.

Vi du:

```text
Nhung email nao noi ve hoa don?
Tom tat cac email lien quan den hop dong.
```

## 12. Noi Ve Training Pipeline

Lenh train:

```bash
python -m src.features.spam_classifier.training_pipeline
```

Noi khi demo:

```text
Pipeline doc dataset, tien xu ly label, vector hoa noi dung email, train nhieu model,
chon model tot nhat va luu artifact vao outputs/<timestamp>/.
```

## 13. Checklist Truoc Khi Bao Ve

- [ ] `python -m compileall src app.py` pass.
- [ ] `streamlit run app.py` mo duoc.
- [ ] Model fallback ton tai trong `data/models/v1/`.
- [ ] Neu demo dashboard/history, MySQL dang chay va `.env` dung.
- [ ] Co san email Ham, email Spam va file MBOX mau.
