# Giai Thich Cau Truc Thu Muc Du An

Tai lieu nay mo ta cau truc feature-based hien tai cua du an Spam Email Classification System.

## Tong Quan

Du an duoc sap xep theo muc tieu demo:

- `app.py` la entrypoint Streamlit.
- `src/features/` gom code theo tung tinh nang nguoi dung nhin thay.
- `src/shared/` gom helper dung chung.
- `src/infrastructure/` gom adapter ha tang nhu database.
- `data/`, `outputs/`, `database/`, `docs/`, `scripts/` nam ngoai source code de de quan sat khi demo.

## Root Project

`app.py`

Entrypoint Streamlit cua ung dung:

```bash
streamlit run app.py
```

`README.md`

Tai lieu tong quan: tinh nang, cai dat, cau hinh database, cau hinh model va cach chay nhanh.

`requirements.txt`, `pyproject.toml`, `uv.lock`

File quan ly moi truong Python va dependencies.

## `src/`

Thu muc chua package Python chinh cua ung dung.

`src/config/`

Cau hinh duong dan dataset, model, vectorizer va thu muc output. File chinh la `src/config/config.py`.

`src/features/`

Code duoc gom theo tinh nang:

- `auth/`: dang ky, dang nhap, lich su du doan, feedback, review queue.
- `dashboard/`: dashboard thong ke, model lab, review queue, campaign overview.
- `email_summarizer/`: UI tom tat email va script train summarizer.
- `rag_chatbot/`: chatbot hoi dap tren noi dung email.
- `spam_classifier/`: ingestion, transformation, training, prediction pipeline va model lab cho spam classifier.
- `threat_intelligence/`: URL risk, QR/quishing, phishing detector, email threat analyzer, taxonomy, risk aggregator va campaign intelligence.

`src/infrastructure/`

Adapter ket noi he thong ngoai. Hien tai co `src/infrastructure/database/db.py` cho MySQL.

`src/shared/`

Helper dung chung giua cac feature:

- `email_utils.py`: tach body email, lam sach text, lay nguoi gui/nhan.
- `logger.py`: logger dung chung.
- `state.py`: state object cho training va prediction.

## `data/`

Chua dataset va model mau duoc version theo repo.

`data/dataset/`

Dataset huan luyen mac dinh, hien tai la `data/dataset/dataset.csv`.

`data/models/v1/`

Model va vectorizer fallback neu chua co artifact hop le trong `outputs/`.

## `outputs/`

Artifact sinh ra khi train/chay local. Cac thu muc model nen dat ten theo tinh nang:

- `outputs/email_spam_classifier/`
- `outputs/email_summarizer_vi/`
- `outputs/email_phishing_detector_vi/`

Thu muc nay la runtime output va khong nen commit.

## `database/`

Tai nguyen database tach khoi package code.

`database/schema.sql`

Schema MySQL chinh, bao gom login, lich su du doan va cac bang Adaptive Threat Intelligence.

## `docs/`

Tai lieu du an, huong dan demo, roadmap va phan cong tinh nang.

## `scripts/`

Smoke test va tien ich demo:

```bash
python scripts\smoke_adaptive_threat_intelligence.py
```

## Nguyen Tac Khi Them File Moi

- Code cua mot tinh nang: dat trong `src/features/<ten_tinh_nang>/`.
- Helper dung chung: dat trong `src/shared/`.
- Adapter ha tang: dat trong `src/infrastructure/`.
- SQL schema: dat trong `database/`.
- Script chay mot lan hoac smoke test: dat trong `scripts/`.
- Dataset/model mau can version: dat trong `data/`.
- Artifact sinh ra khi chay/train: dat trong `outputs/`, khong commit.
