# Ke Hoach Cai Tien Du An

Tai lieu nay mo ta trang thai hien tai va huong phat trien tiep theo cua MailGuard AI.

## Trang thai hien tai

Du an da co:

- Streamlit app cho single email, URL, QR va MBOX batch.
- AI threat lifecycle cho email threat classifier va URL phishing classifier.
- Canonical data layout cho raw, interim, canonical, manifests, feedback va fixtures.
- Publish gate va current runtime artifacts trong `outputs/ai-threat-current/models/`.
- Feedback export va lifecycle smoke cho retraining.

## Muc tieu tiep theo

### 1. Cung co data pipeline

- Bo sung them du lieu that tai local hoac export reviewed feedback.
- Nang cao validation, dedupe va provenance cho canonical datasets.
- Giam phu thuoc vao fixture/smoke data khi demo production.

### 2. Nang cao model quality

- Mo rong class support cho cac threat label it du lieu.
- Theo doi per-class recall, macro F1 va weighted F1 ro hon.
- Thu nghiem them candidate model neu co du lieu phu hop.

### 3. Hoan thien runtime UX

- Hien thi ro hon run id, dataset version, source counts va label counts.
- Giu model-unavailable behavior khi artifact thieu hoac khong hop schema.
- Tiep tuc tang do ro rang cho reasons va campaign evidence.

### 4. Mo rong dashboard va report

- Bieu do threat taxonomy, risk trend va review queue.
- Report cho campaign, error analysis va retraining input.
- Tai xuat JSON/CSV phuc vu demo va bao cao.

### 5. Feedback loop an toan

- Chi export reviewed feedback da duyet.
- Loai duplicate va weak labels khoi primary evaluation mac dinh.
- Ghi nhan provenance cho moi lan retraining.

### 6. Deployment tuy chon

- Giua Streamlit local va service API neu can demo mo rong.
- Dong goi moi truong chay neu can share artifact on dinh.

## Thu tu uu tien

1. Data provenance va publish gate.
2. Model quality va evaluation.
3. Demo UX va dashboard.
4. Feedback loop va retraining.
5. Deployment neu con thoi gian.

## Cach demo an toan

- Dung `python scripts\train_ai_threat_models.py --fixture-mode --force` cho smoke.
- Dung `python scripts\train_ai_threat_models.py --force --publish` khi muon cap nhat current artifacts.
- Neu artifact chua san sang, app phai tra `model_unavailable` thay vi fallback rule-based verdict.

## Ghi chu

Tai lieu nay la roadmap hien tai, khong phai mo ta muc tieu ban dau. Khi code thay doi, cap nhat cac command va duong dan trong README, DEMO, va tai lieu kien truc cho dong bo.
