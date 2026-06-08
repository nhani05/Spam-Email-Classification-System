# Phan cong tinh nang cho 2 thanh vien

Tai lieu nay phan chia cac tinh nang hien co cua du an Spam Email Classification System cho 2 thanh vien phu trach. Viec phan cong dua tren cau truc source code hien tai va cac module dang co trong du an.

## Tong quan phan cong

| Thanh vien | Vai tro chinh | Pham vi phu trach |
| --- | --- | --- |
| Thanh vien 1 | Machine Learning va xu ly du lieu | Dataset, training pipeline, prediction pipeline, xu ly email/MBOX, model va vectorizer |
| Thanh vien 2 | Ung dung, database va bao mat | Giao dien Streamlit, dang nhap/dang ky, MySQL, dashboard, lich su, threat detection URL/QR/email |

## Thanh vien 1: Machine Learning va xu ly du lieu

### Tinh nang phu trach

- Nap du lieu huan luyen tu `data/dataset/dataset.csv`.
- Tien xu ly du lieu email, tach feature va label.
- Ma hoa nhan:
  - `spam` thanh `0`.
  - `ham` thanh `1`.
- Chia tap train/test theo ti le 70/30.
- Vector hoa noi dung email bang TF-IDF.
- Huan luyen va so sanh nhieu mo hinh:
  - Logistic Regression.
  - Decision Tree.
  - SVM.
  - KNN.
  - Random Forest.
- Tim tham so tot nhat bang GridSearchCV.
- Luu model, vectorizer va cac file danh gia vao thu muc `outputs/`.
- Nap model da huan luyen de du doan email don.
- Xu ly file MBOX va phan loai hang loat email.
- Xuat ket qua batch thanh DataFrame/CSV.

### File/module lien quan

| File | Noi dung phu trach |
| --- | --- |
| `src/components/data_ingestion.py` | Doc dataset huan luyen |
| `src/components/data_transformation.py` | Xu ly label, chia train/test, TF-IDF |
| `src/components/model_training.py` | Huan luyen, danh gia va luu model |
| `src/pipeline/training_pipeline.py` | Dieu phoi toan bo pipeline huan luyen |
| `src/pipeline/prediction_pipeline.py` | Du doan email don va file MBOX |
| `src/utils/email_utils.py` | Tach noi dung email, lam sach text, lay nguoi nhan |
| `src/utils/state.py` | Quan ly state cho training/prediction |
| `src/config/config.py` | Cau hinh duong dan dataset, model va vectorizer |
| `data/dataset/dataset.csv` | Du lieu huan luyen |
| `data/models/v1/` | Model va vectorizer co san |

### Ket qua can dam bao

- Pipeline huan luyen chay duoc bang lenh:

```bash
python -m src.pipeline.training_pipeline
```

- Model va vectorizer duoc luu dung cau truc:

```text
outputs/<timestamp>/models/
```

- Duong dan `model_path` va `feature_path` trong `src/config/config.py` tro dung file model dang su dung.
- Chuc nang du doan email don tra ve:
  - `prediction`
  - `confidence`
  - `raw_prediction`
- Chuc nang xu ly MBOX tra ve bang ket qua co cot `Prediction`.

## Thanh vien 2: Ung dung, database va bao mat

### Tinh nang phu trach

- Xay dung va van hanh giao dien Streamlit trong `app.py`.
- Thiet lap layout, sidebar, tabs va cac luong thao tac nguoi dung.
- Che do khach:
  - Kiem tra email don.
  - Phan tich QR image.
- Che do nguoi dung da dang nhap:
  - Dashboard.
  - Kiem tra email don va luu lich su.
  - Xu ly file MBOX va luu thong ke.
  - Xem lich su phan loai.
- Dang ky, dang nhap va dang xuat tai khoan.
- Ket noi MySQL bang bien moi truong trong `.env`.
- Tao database va bang bang script SQL.
- Luu lich su du doan email don.
- Luu lich su xu ly file MBOX.
- Hien thi dashboard thong ke.
- Phan tich de doa trong email:
  - Phishing.
  - Fake link.
  - Malware.
  - File dinh kem/ten file dang nghi.
- Phan tich QR code trong anh va danh gia rui ro URL.

### File/module lien quan

| File | Noi dung phu trach |
| --- | --- |
| `app.py` | Giao dien Streamlit va dieu phoi cac tab |
| `src/auth/auth.py` | Dang ky, dang nhap, luu va doc lich su |
| `src/database/db.py` | Ket noi MySQL va health check |
| `src/components/dashboard.py` | Dashboard thong ke nguoi dung |
| `src/security/email_threat_analyzer.py` | Phan tich rui ro noi dung email |
| `src/security/url_risk_model.py` | Cham diem rui ro URL |
| `src/security/qr_image_analyzer.py` | Doc QR code tu anh va phan tich URL |
| `db/db.sql` | Script tao database va du lieu mau |
| `.env` | Bien moi truong ket noi database |

### Ket qua can dam bao

- Ung dung chay duoc bang lenh:

```bash
streamlit run app.py
```

- Khi MySQL san sang, nguoi dung co the:
  - Dang ky tai khoan.
  - Dang nhap.
  - Luu lich su du doan.
  - Xem dashboard va lich su.
- Khi MySQL khong san sang, ung dung van cho phep khach kiem tra email don.
- File MBOX upload duoc xu ly va co the tai ket qua CSV.
- QR image upload duoc phan tich va hien thi:
  - So QR tim thay.
  - Diem rui ro.
  - Muc rui ro.
  - URL giai ma.
  - Ly do danh gia.

## Phan chia theo man hinh/chuc nang nguoi dung

| Chuc nang | Thanh vien phu trach chinh | Thanh vien phoi hop |
| --- | --- | --- |
| Kiem tra email don | Thanh vien 1 | Thanh vien 2 |
| Hien thi ket qua email don tren UI | Thanh vien 2 | Thanh vien 1 |
| Phan tich rui ro trong email | Thanh vien 2 | Thanh vien 1 |
| Phan tich QR image | Thanh vien 2 | Thanh vien 1 |
| Xu ly file MBOX | Thanh vien 1 | Thanh vien 2 |
| Upload MBOX va tai CSV | Thanh vien 2 | Thanh vien 1 |
| Huan luyen lai model | Thanh vien 1 | Thanh vien 2 |
| Cau hinh duong dan model | Thanh vien 1 | Thanh vien 2 |
| Dang ky/dang nhap | Thanh vien 2 | Thanh vien 1 |
| Luu lich su du doan | Thanh vien 2 | Thanh vien 1 |
| Dashboard | Thanh vien 2 | Thanh vien 1 |
| README va tai lieu cai dat | Thanh vien 2 | Thanh vien 1 |

## Tieu chi nghiem thu

### Phan cua Thanh vien 1

- Chay duoc pipeline huan luyen khong loi.
- Co model/vectorizer hop le de app load khi khoi dong.
- Du doan email don tra ve dung format.
- Xu ly duoc file MBOX va sinh ket qua co nhan `Spam`/`Ham`.
- Co bao cao metric sau khi huan luyen.

### Phan cua Thanh vien 2

- App Streamlit khoi dong duoc.
- Cac tab hien thi dung theo trang thai dang nhap.
- Dang ky/dang nhap hoat dong khi MySQL da cau hinh.
- Lich su single email va batch MBOX duoc luu/doc tu database.
- Dashboard hien thi du lieu cua nguoi dung.
- Phan tich QR va threat detection hien thi ket qua ro rang.

## Ghi chu khi lam viec nhom

- Truoc khi demo, can thong nhat duong dan model trong `src/config/config.py`.
- Neu dung model trong repo, co the cau hinh:

```python
model_path = "data/models/v1/model.pkl"
feature_path = "data/models/v1/feature.pkl"
```

- Neu huan luyen model moi, can cap nhat lai duong dan toi thu muc `outputs/<timestamp>/models/`.
- Thanh vien 1 nen ban giao cho Thanh vien 2 mot cap file model/vectorizer da test thanh cong.
- Thanh vien 2 nen bao lai loi load model, loi database hoac loi format output de Thanh vien 1 dieu chinh pipeline.

## Phan cong cho huong cai tien MailGuard AI

Chi tiet roadmap nam trong `docs/KE_HOACH_CAI_TIEN_DU_AN.md`. Tom tat phan cong nang cap:

| Hang muc cai tien | Thanh vien 1 | Thanh vien 2 |
| --- | --- | --- |
| Risk score tong hop | Mapping confidence tu ML model sang spam score | Tong hop spam/phishing/URL/QR/file score va hien thi UI |
| Explainable reasons | Ly do lien quan spam keywords, vectorizer/model output | Ly do lien quan URL, QR, phishing, malware, attachment |
| URL phishing detection | Ho tro feature engineering va test case | Phu trach rule-based URL analyzer |
| QR phishing detection | Ho tro bo mau QR test | Phu trach QR analyzer va UI |
| Security dashboard | Cung cap metric model va batch prediction | Truy van DB, ve bieu do, hien thi risky domains |
| Feedback loop | Chuan bi cach dung feedback cho retraining | Tao form feedback va bang DB |
| Model evaluation | Accuracy, precision, recall, F1, confusion matrix | Hien thi bang/bieu do tren Streamlit |
| Admin mode | Chuan hoa format blacklist/whitelist cho analyzer | Role admin, CRUD blacklist/whitelist, dashboard tong |
| FastAPI/Docker | Dong goi prediction logic thanh service | Tich hop app, DB va huong dan deployment |

Uu tien cao nhat nen lam truoc:

1. Risk score tong hop.
2. Explainable reasons.
3. URL phishing va QR phishing.
4. Security dashboard.
5. Feedback loop.
