# Ke hoach cai tien du an

Tai lieu nay mo ta huong nang cap du an tu mot he thong phan loai spam/ham thanh mot he thong phan tich an toan email tong hop. Dinh huong de xuat la:

```text
MailGuard AI: Intelligent Email Threat Detection System
```

Muc tieu khong chi tra loi "email nay la spam hay ham", ma tra loi day du hon:

```text
Email nay co nguy hiem khong?
Nguy hiem o diem nao?
Vi sao he thong danh gia nhu vay?
Nguoi dung nen lam gi tiep theo?
```

## Muc tieu nang cap

- Bien du an thanh he thong Email Threat Detection thay vi chi Spam Classification.
- Ket hop Machine Learning voi rule-based security analysis.
- Tang tinh giai thich cua ket qua du doan.
- Bo sung dashboard, feedback loop va kha nang mo rong thanh san pham thuc te.
- Tao them cac diem demo thuyet phuc: risk score, explainable reasons, QR phishing, URL analysis, admin/security dashboard.

## Kien truc muc tieu

```text
Email input / MBOX / QR image
        |
        v
Text preprocessing + email parsing
        |
        +--> ML Spam/Ham model
        |
        +--> URL risk analyzer
        |
        +--> QR phishing analyzer
        |
        +--> Attachment/header/brand impersonation rules
        |
        v
Risk Aggregator
        |
        v
Final verdict + reasons + recommended actions
        |
        v
Streamlit UI + history + dashboard + feedback
```

## Roadmap tong quan

| Giai doan | Muc tieu | Do kho | Gia tri khi demo |
| --- | --- | --- | --- |
| Phase 1 | Risk score tong hop va explainable reasons | Trung binh | Rat cao |
| Phase 2 | URL phishing va QR phishing nang cao | Trung binh/cao | Rat cao |
| Phase 3 | Security dashboard va history nang cap | Trung binh | Cao |
| Phase 4 | Feedback loop va model evaluation | Trung binh | Cao |
| Phase 5 | Admin mode, blacklist/whitelist, report export | Cao | Rat cao |
| Phase 6 | FastAPI/Docker neu con thoi gian | Cao | Cong diem ky thuat |

## Phase 1: Risk score tong hop

### Muc tieu

Thay vi chi hien thi `Spam` hoac `Ham`, he thong can hien thi:

- Spam prediction.
- Spam confidence.
- Phishing score.
- Fake link score.
- Malware/file risk score.
- QR risk score neu co anh QR.
- Overall risk score tu `0-100`.
- Risk level:
  - `Low`
  - `Medium`
  - `High`
  - `Critical`
- Final verdict:
  - `Safe`
  - `Suspicious`
  - `Spam`
  - `Phishing`
  - `Malware Risk`
  - `High Risk`

### De xuat xu ly

Tao module moi:

```text
src/security/risk_aggregator.py
```

Module nay nhan ket qua tu ML model va cac analyzer hien co, sau do tinh diem tong hop.

Cong thuc ban dau co the la rule-based:

```text
overall_risk = max(
    spam_score * 0.35,
    phishing_score * 0.30,
    fake_link_score * 0.20,
    malware_score * 0.15,
    qr_score
)
```

Sau do co the tinh lai theo tong co trong so neu can.

### File can tac dong

- `src/security/email_threat_analyzer.py`
- `src/security/url_risk_model.py`
- `src/security/qr_image_analyzer.py`
- `app.py`
- `src/auth/auth.py`
- `db/db.sql`

### Tieu chi hoan thanh

- Moi lan phan tich email co risk score `0-100`.
- UI hien thi risk level va final verdict.
- Ket qua co danh sach ly do ro rang.
- Lich su luu them risk score va risk level.

## Phase 2: Phishing URL va QR phishing

### Muc tieu

Nang cap phan tich link trong email va link giai ma tu QR code.

### URL features nen bo sung

- URL dung IP thay vi domain.
- URL qua dai.
- Nhieu subdomain bat thuong.
- Co ky tu `@`, `%`, nhieu dau `-`.
- Dung `http` thay vi `https`.
- Domain giong thuong hieu lon nhung khong phai domain chinh thuc.
- URL shortener: `bit.ly`, `tinyurl`, `t.co`, `goo.gl`.
- Tu khoa nhay cam: `login`, `verify`, `secure`, `bank`, `wallet`, `otp`, `password`.

### QR phishing

Dat ten tinh nang:

```text
Quishing Detection
```

Quy trinh:

1. Nguoi dung upload anh.
2. He thong decode QR.
3. Phan tich URL trong QR.
4. Hien thi URL that va domain.
5. Canh bao neu QR an link dang nghi.

### File can tac dong

- `src/security/url_risk_model.py`
- `src/security/qr_image_analyzer.py`
- `src/security/email_threat_analyzer.py`
- `app.py`

### Tieu chi hoan thanh

- URL analyzer tra ve `features`, `risk_score`, `verdict`, `reasons`.
- QR analyzer dung lai URL analyzer.
- UI hien thi tung ly do cho moi URL/QR.

## Phase 3: Security dashboard

### Muc tieu

Dashboard khong chi thong ke spam/ham, ma tro thanh dashboard an toan email.

### Chi so nen co

- Tong email da phan tich.
- So email theo nhan `Spam`/`Ham`.
- So email theo risk level.
- Ty le email high risk.
- Top risky domains.
- Top suspicious keywords.
- So QR nguy hiem da phat hien.
- Bieu do risk theo thoi gian.
- Danh sach email nguy hiem gan day.

### File can tac dong

- `src/components/dashboard.py`
- `src/auth/auth.py`
- `db/db.sql`
- `app.py`

### Tieu chi hoan thanh

- Dashboard co it nhat 4 metric chinh.
- Co bang email high risk gan day.
- Co bieu do phan bo risk level.

## Phase 4: Feedback loop va model evaluation

### Feedback loop

Sau khi he thong du doan, cho nguoi dung phan hoi:

```text
Ket qua dung
Ket qua sai
```

Du lieu feedback duoc luu vao DB de phuc vu retraining.

Bang de xuat:

```sql
CREATE TABLE Prediction_Feedback (
    id INT NOT NULL AUTO_INCREMENT,
    user_id INT NOT NULL,
    prediction_id INT NOT NULL,
    feedback ENUM('correct', 'incorrect') NOT NULL,
    corrected_label ENUM('spam', 'ham', 'phishing', 'safe') NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id)
);
```

### Model evaluation

Them tab `Model Evaluation` de hien thi:

- Accuracy.
- Precision.
- Recall.
- F1-score.
- Confusion matrix.
- Bang so sanh model.
- Best model.

### File can tac dong

- `src/components/model_training.py`
- `src/components/dashboard.py`
- `app.py`
- `src/auth/auth.py`
- `db/db.sql`

### Tieu chi hoan thanh

- Nguoi dung gui feedback duoc.
- Feedback duoc luu DB.
- Co man hinh/phan hien thi metric model.
- Co confusion matrix hoac bang ket qua danh gia.

## Phase 5: Admin mode va rule management

### Muc tieu

Them vai tro admin de du an giong mot san pham that hon.

### Chuc nang admin

- Xem thong ke toan he thong.
- Xem danh sach email high risk.
- Quan ly blacklist domain.
- Quan ly whitelist domain.
- Quan ly keyword dang nghi.
- Xem feedback cua nguoi dung.

### Bang DB de xuat

```sql
ALTER TABLE User ADD COLUMN role ENUM('user', 'admin') NOT NULL DEFAULT 'user';

CREATE TABLE Domain_Blacklist (
    id INT NOT NULL AUTO_INCREMENT,
    domain VARCHAR(255) NOT NULL UNIQUE,
    reason TEXT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id)
);

CREATE TABLE Domain_Whitelist (
    id INT NOT NULL AUTO_INCREMENT,
    domain VARCHAR(255) NOT NULL UNIQUE,
    reason TEXT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id)
);
```

### Tieu chi hoan thanh

- User role duoc luu trong DB.
- Admin thay duoc dashboard toan he thong.
- Admin them/xoa domain blacklist/whitelist duoc.
- URL analyzer doc duoc blacklist/whitelist khi tinh risk.

## Phase 6: FastAPI va Docker

### Muc tieu

Neu con thoi gian, bo sung kha nang trien khai va tich hop.

### FastAPI endpoint de xuat

```text
POST /predict-email
POST /analyze-url
POST /analyze-qr
GET /history
GET /dashboard
```

### Docker

Them:

```text
Dockerfile
docker-compose.yml
```

Service de xuat:

- `app`: Streamlit/FastAPI.
- `mysql`: MySQL database.

### Tieu chi hoan thanh

- Chay duoc app bang Docker Compose.
- API tra ve JSON dung format.
- README co huong dan chay Docker.

## Thu tu uu tien de dat diem cao

Nen lam theo thu tu:

1. Risk score tong hop.
2. Explainable reasons.
3. URL phishing detection nang cao.
4. QR phishing/quishing detection.
5. Security dashboard.
6. Feedback loop.
7. Model evaluation.
8. Admin mode.
9. Report export.
10. FastAPI/Docker.

## Ban demo de xuat

Khi bao ve, nen demo theo kich ban:

1. Mo dashboard gioi thieu he thong MailGuard AI.
2. Nhap mot email binh thuong va cho thay verdict `Safe`.
3. Nhap mot email lua dao co link dang nghi va cho thay risk score cao.
4. Mo phan `Why this result?` de giai thich cac ly do.
5. Upload anh QR chua link dang nghi va demo Quishing Detection.
6. Dang nhap tai khoan va xem lich su.
7. Xu ly mot file MBOX va tai ket qua CSV.
8. Xem dashboard security sau khi co du lieu.
9. Gui feedback dung/sai de cho thay he thong co kha nang cai tien.

## Phan cong cho 2 thanh vien theo roadmap

| Hang muc | Thanh vien 1 | Thanh vien 2 |
| --- | --- | --- |
| Risk score aggregator | Phoi hop mapping score tu ML | Phu trach logic security score va UI |
| Explainable reasons | Ly do tu model/spam keywords | Ly do URL/QR/phishing/malware |
| URL phishing | Ho tro feature engineering | Phu trach rule-based analyzer |
| QR phishing | Ho tro test case | Phu trach QR analyzer va UI |
| Dashboard | Cung cap metric tu pipeline | Phu trach truy van DB va bieu do |
| Feedback loop | Dung feedback cho retraining | Phu trach form va DB feedback |
| Model evaluation | Phu trach metric va confusion matrix | Hien thi tren UI |
| Admin mode | Phoi hop data/rule format | Phu trach role, CRUD rule va dashboard |
| Docker/API | Phoi hop endpoint predict | Phu trach deployment/app integration |

## Rui ro va cach giam thieu

| Rui ro | Cach giam thieu |
| --- | --- |
| Thieu dataset phishing/malware | Ket hop ML spam/ham voi rule-based analyzer |
| Model path khong khop | Chuan hoa `Config` va README |
| DB schema thay doi gay loi app | Viet migration SQL rieng va cap nhat `auth.py` |
| UI qua nhieu tab | Gom theo nhom: Analyze, Batch, Dashboard, History, Admin |
| Cham khi xu ly MBOX lon | Gioi han preview, cache model, xu ly theo batch |

## Ket qua mong doi

Sau khi hoan thanh cac phase uu tien, du an co the duoc trinh bay nhu mot he thong:

```text
MailGuard AI phan tich email bang cach ket hop machine learning,
phishing URL detection, QR threat analysis, explainable risk scoring,
dashboard bao mat va feedback loop de cai thien model.
```

## Huong nang cap moi: Adaptive Threat Intelligence Platform

De bien de tai kho hon nua, roadmap moi nang cap he thong thanh:

```text
MailGuard AI: Adaptive Email Threat Intelligence Platform
```

Khac voi spam classifier thong thuong, he thong nay phan tich email nhu mot security event:

- Trich xuat IoC: sender, domain, URL, QR payload, risky file, brand impersonation, keyword.
- Phan loai threat taxonomy: Safe, Spam, Phishing, Malware Risk, Business Email Compromise, Quishing, Credential Theft, Payment Scam.
- Model Lab: so sanh model, threshold tuning, calibration metadata, error analysis.
- Campaign Intelligence: gom cac email lien quan thanh phishing/scam campaign.
- Threat Graph: tao node/edge giua campaign, email, sender, URL, domain, brand.
- Adaptive Learning: feedback nguoi dung, review queue, export du lieu retraining.

Demo nang cao nen gom:

1. Chay email safe va email phishing de thay threat label khac spam/ham.
2. Xu ly batch co nhieu email cung domain phishing de hien campaign.
3. Tai campaign report Markdown/JSON.
4. Mo dashboard thay threat taxonomy, high-risk trend, review queue va model lab.
5. Gui feedback sai nhan va xuat approved retraining data.
