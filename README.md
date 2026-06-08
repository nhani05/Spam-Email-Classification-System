# Spam Email Classification System

He thong phan loai email spam/ham bang Machine Learning, co giao dien Streamlit de kiem tra email don, xu ly file MBOX, phan tich rui ro URL/QR va luu lich su du doan theo tai khoan nguoi dung.

## Tinh nang chinh

- Phan loai noi dung email thanh `Spam` hoac `Ham`.
- Hien thi do tin cay cua du doan neu model ho tro `predict_proba`.
- Phan tich dau hieu de doa trong email: phishing, fake link, malware va file dang nghi.
- Phan tich anh co QR code va cham diem rui ro URL trong QR.
- Xu ly hang loat email tu file MBOX va xuat ket qua CSV.
- Dang ky, dang nhap va luu lich su du doan bang MySQL.
- Dashboard va lich su cho nguoi dung da dang nhap.
- Pipeline huan luyen lai model tu dataset CSV.

## Cong nghe su dung

- Python
- Streamlit
- Pandas
- Scikit-learn
- OpenCV
- BeautifulSoup
- MySQL Connector
- TF-IDF vectorizer va cac mo hinh ML nhu Logistic Regression, Decision Tree, SVM, KNN, Random Forest

## Cau truc thu muc

```text
.
|-- app.py                         # Ung dung Streamlit
|-- requirements.txt               # Danh sach package Python
|-- pyproject.toml                  # Cau hinh du an khi dung uv
|-- data/
|   |-- dataset/dataset.csv         # Du lieu huan luyen
|   `-- models/v1/                  # Model/vectorizer co san
|-- db/
|   `-- db.sql                      # Script tao database MySQL
|-- src/
|   |-- auth/                       # Dang nhap, dang ky, luu lich su
|   |-- components/                 # Ingestion, transformation, training, dashboard
|   |-- config/                     # Cau hinh duong dan du lieu/model
|   |-- database/                   # Ket noi MySQL
|   |-- pipeline/                   # Training va prediction pipeline
|   |-- security/                   # Phan tich URL, QR, email threat
|   `-- utils/                      # Logger, email utils, state, DB helpers
`-- Notebook Experiments/           # Notebook thu nghiem
```

## Yeu cau moi truong

- Python 3.13 tro len theo `pyproject.toml`.
- MySQL neu muon dung chuc nang dang nhap, lich su va dashboard.
- Co san file model va vectorizer dung voi duong dan trong `src/config/config.py`.

## Cai dat

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

## Cau hinh database

Tao database MySQL bang file script:

```bash
mysql -u root -p < db/db.sql
```

Tao file `.env` o thu muc goc du an:

```env
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=your_password
DB_NAME=spam_detection
```

Neu MySQL chua san sang, ung dung van co the chay che do khach de kiem tra email don, nhung cac chuc nang dang nhap, lich su va dashboard se khong hoat dong.

## Cau hinh model

Ung dung load model tu `src/config/config.py`:

```python
model_path = "outputs/2026-03-21_15-14-51/models/SVM_model.pkl"
feature_path = "outputs/2026-03-21_15-14-51/models/vectorizer.pkl"
```

Neu thu muc `outputs/...` khong ton tai, cap nhat thanh model co san trong repo:

```python
model_path = "data/models/v1/model.pkl"
feature_path = "data/models/v1/feature.pkl"
```

Hoac chay lai pipeline huan luyen de sinh model moi trong thu muc `outputs/`.

## Chay ung dung

```bash
streamlit run app.py
```

Sau khi chay, mo duong dan Streamlit hien tren terminal, thuong la:

```text
http://localhost:8501
```

## Huan luyen lai model

Dataset mac dinh nam tai:

```text
data/dataset/dataset.csv
```

Chay pipeline huan luyen:

```bash
python -m src.pipeline.training_pipeline
```

Pipeline se:

1. Doc du lieu tu CSV.
2. Ma hoa nhan `spam` thanh `0`, `ham` thanh `1`.
3. Chia train/test theo ti le 70/30.
4. Vector hoa noi dung email bang TF-IDF.
5. Huan luyen va tim tham so tot nhat cho nhieu mo hinh.
6. Luu model, vectorizer va bao cao metric vao `outputs/<timestamp>/`.

Sau khi huan luyen, cap nhat `model_path` va `feature_path` trong `src/config/config.py` de tro toi model moi.

## Su dung ung dung

- Khach: kiem tra email don va phan tich QR image.
- Nguoi dung da dang nhap: co them dashboard, xu ly file MBOX va xem lich su.
- File MBOX ho tro upload qua tab `File MBOX`.
- Ket qua batch co the tai xuong duoi dang CSV.

## Tai lieu du an

- `docs/PHAN_CONG_TINH_NANG.md`: Phan cong cac tinh nang hien co cho 2 thanh vien.
- `docs/KE_HOACH_CAI_TIEN_DU_AN.md`: Roadmap nang cap du an thanh MailGuard AI - Email Threat Detection System.

## Huong phat trien

Du an co the duoc nang cap tu Spam Email Classification thanh he thong phan tich an toan email tong hop:

- Cham diem rui ro tong hop `0-100`.
- Giai thich ly do email bi danh dau nguy hiem.
- Phat hien phishing URL va QR phishing.
- Dashboard bao mat theo risk level, risky domain va lich su high risk.
- Feedback loop de nguoi dung bao ket qua dung/sai.
- Admin mode de quan ly blacklist/whitelist domain.

## Ghi chu

- File `.env`, `outputs/`, `venv/`, log va file MBOX duoc bo qua trong `.gitignore`.
- Mat khau hien dang duoc luu theo logic hien co cua du an; khi trien khai thuc te nen bo sung hashing va rang buoc bao mat tot hon.
- Neu loi load model xay ra khi mo app, hay kiem tra lai duong dan `model_path` va `feature_path`.
