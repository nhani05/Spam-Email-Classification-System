# Phan Cong Tinh Nang Cho 2 Thanh Vien

Tai lieu nay cap nhat phan cong theo source code hien tai cua du an MailGuard AI.

## Tong Quan

| Thanh vien | Vai tro chinh | Pham vi phu trach |
| --- | --- | --- |
| Thanh vien 1 | ML, data lifecycle, model lab | `src/ml/threat_classifier/*`, `src/ml/model_lab/*`, `scripts/train_ai_threat_models.py`, `scripts/smoke_ai_threat_models.py`, `scripts/smoke_email_threat_lifecycle.py`, `data/ai_threat/*` |
| Thanh vien 2 | App, database, security UX | `app.py`, `src/security/*`, `src/persistence/*`, `src/core/config.py`, `scripts/smoke_adaptive_threat_intelligence.py` |

## Thanh vien 1: ML va data lifecycle

### Cong viec

- Quan ly canonical email/URL datasets.
- Import nguon local: PhishFuzzer, Nazario, SpamAssassin, Enron, PhishTank, URLhaus.
- Lam sach, validate, dedupe va phan loai weak labels.
- Train email threat classifier va URL phishing classifier.
- Tao model bundle, metadata va evaluation reports.
- Van hanh publish gate va smoke test cho fixture mode.

### File chinh

| File | Nhiem vu |
| --- | --- |
| `src/ml/threat_classifier/schema.py` | Schema, data layout, publish gate config |
| `src/ml/threat_classifier/importers.py` | Import dataset tu local sources |
| `src/ml/threat_classifier/canonical.py` | Cleaning, normalization, dedupe, validation |
| `src/ml/threat_classifier/lifecycle.py` | Orchestrate import -> train -> evaluate -> publish |
| `src/ml/threat_classifier/artifacts.py` | Stamp metadata, validate bundle, publish gate |
| `src/ml/threat_classifier/legacy.py` | Runtime compatibility va training logic con lai |
| `src/ml/model_lab/evaluation.py` | Model lab discovery va report indexing |
| `scripts/train_ai_threat_models.py` | CLI train/import/publish |
| `scripts/smoke_ai_threat_models.py` | Smoke test model load/predict |
| `scripts/smoke_email_threat_lifecycle.py` | End-to-end lifecycle smoke |

### Acceptance

- `python scripts\train_ai_threat_models.py --fixture-mode --force`
- `python scripts\train_ai_threat_models.py --force --publish`
- Artifact current duoc copy ve `outputs/ai-threat-current/models/` khi gate pass.
- Seed/fixture-only data khong duoc dung cho production training.

## Thanh vien 2: App, database va security UX

### Cong viec

- Van hanh Streamlit app va cac tab nguoi dung.
- Hien thi prediction, URL analysis, QR/quishing, batch MBOX va dashboard.
- Luu history, feedback va review queue qua persistence layer.
- Bao dam runtime load dung current artifacts va tra `model_unavailable` neu artifact thieu.
- Cap nhat huong dan demo, dashboard copy va input mau.

### File chinh

| File | Nhiem vu |
| --- | --- |
| `app.py` | Streamlit entrypoint va orchestration |
| `src/security/*` | URL, QR, email threat, campaign logic |
| `src/persistence/*` | History, feedback, review queue, campaign persistence |
| `src/core/config.py` | Default paths cho baseline va AI threat artifacts |
| `docs/DEMO.md` | Kich ban demo va input mau |
| `docs/ADAPTIVE_THREAT_INTELLIGENCE.md` | Tai lieu kien truc va lifecycle |

### Acceptance

- `streamlit run app.py` khoi dong duoc.
- Single email, URL, QR va MBOX flows hoat dong voi current artifacts.
- Khi artifact AI thieu hoac khong hop schema, app tra `model_unavailable`.
- Feedback duoc luu va co the export cho retraining.

## Nguong phoi hop

- Model path mac dinh: `outputs/ai-threat-current/models/email_threat_model.pkl` va `outputs/ai-threat-current/models/url_phishing_model.pkl`.
- Spam/ham baseline van giu compatibility artifacts trong `outputs/<latest_run>/models/` va `data/models/v1/`.
- Truoc khi bao ve, chay:

```bash
python -m compileall src app.py scripts
python scripts\smoke_adaptive_threat_intelligence.py
python scripts\smoke_email_threat_lifecycle.py
```
