# Giai Thich Cau Truc Thu Muc Du An

Cap nhat: 18/06/2026

Tai lieu nay mo ta cau truc feature-based hien tai cua du an MailGuard AI sau khi bo cac module phan tich rule-based URL/QR/threat.

## Tong Quan

- `app.py` la entrypoint Streamlit.
- `src/features/` gom code theo tung tinh nang nguoi dung nhin thay.
- `src/shared/` gom helper dung chung.
- `src/infrastructure/` gom adapter ha tang nhu database.
- `data/` chua dataset va model fallback co the version trong repo.
- `outputs/` chua artifact sinh ra khi train/chay local, khong nen commit.
- `docs/` chua tai lieu cau truc va demo.

## Root Project

`app.py`

Entrypoint Streamlit:

```bash
streamlit run app.py
```

`README.md`

Tai lieu tong quan: tinh nang, cai dat, cau hinh database, cau hinh model va cach chay nhanh.

`requirements.txt`, `pyproject.toml`, `uv.lock`

Quan ly moi truong Python va dependencies.

`.env`

Bien moi truong ket noi MySQL. File nay la local secret va khong nen commit.

## `src/`

Package Python chinh cua ung dung.

### `src/config/`

`config.py` cau hinh:

- Dataset train mac dinh.
- Thu muc output.
- Logic tu tim spam classifier artifact moi nhat trong `outputs/`.
- Fallback model/vectorizer trong `data/models/v1/`.

### `src/features/`

Code chia theo tinh nang:

- `auth/`: dang ky, dang nhap, dang xuat, lich su, feedback, review queue.
- `dashboard/`: dashboard Spam/Ham, review queue va Model Lab view.
- `email_summarizer/`: local AI summarizer cho van ban paste hoac MBOX.
- `rag_chatbot/`: RAG chatbot tren MBOX bang FAISS va local model.
- `spam_classifier/`: data ingestion, transformation, training, prediction pipeline va Model Lab.

### `src/infrastructure/`

Adapter ha tang.

- `database/db.py`: ket noi MySQL, execute/query helper va health check.
- `src/infrastructure/database/schema.sql`: tao database `spam_detection`, user, history, feedback va review queue. Mot so bang threat metadata/campaign co the con trong schema de tuong thich du lieu cu, nhung app hien tai khong ghi cac metadata nay.

### `src/shared/`

Helper dung chung:

- `email_utils.py`: tach body email, lam sach text, lay metadata email.
- `logger.py`: logger dung chung.
- `state.py`: state object cho training va prediction.

## `data/`

Du lieu va artifact fallback duoc version trong repo.

- `data/dataset/dataset.csv`: dataset huan luyen mac dinh.
- `data/models/v1/model.pkl`: spam classifier fallback.
- `data/models/v1/feature.pkl`: vectorizer/feature pipeline fallback.

## `outputs/`

Artifact sinh ra khi train hoac chay local AI.

Dang co cac kieu thu muc:

- `outputs/<timestamp>/`: artifact spam classifier tu cac lan train cu.
- `outputs/email_summarizer_vi/`: local summarizer model.
- `outputs/my_tiny_summarizer/`: artifact thu nghiem summarizer.

Thu muc nay la runtime output va khong nen commit.

## `docs/`

Tai lieu du an:

- `HUONG_DAN_DEMO_DU_AN.md`: demo cac feature hien co.
- `PROJECT_STRUCTURE_LOCAL.md`: giai thich cau truc thu muc.

## Nguyen Tac Khi Them File Moi

- Code cua mot tinh nang nguoi dung thay: dat trong `src/features/<ten_tinh_nang>/`.
- Helper dung chung: dat trong `src/shared/`.
- Adapter ha tang: dat trong `src/infrastructure/`.
- SQL schema/migration: dat trong `src/infrastructure/database/`.
- Script chay mot lan hoac smoke test: dat trong `scripts/`.
- Dataset/model fallback can version: dat trong `data/`.
- Artifact sinh ra khi train/chay demo: dat trong `outputs/`, khong commit.
