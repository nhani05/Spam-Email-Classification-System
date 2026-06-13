# Huong dan demo du an MailGuard AI

Tai lieu nay dung de demo du an truoc giang vien/hoi dong. Muc tieu la trinh bay du an khong chi la spam/ham classifier, ma la mot he thong phan tich an toan email: risk score, threat taxonomy, URL phishing, QR/quishing, campaign detection, dashboard, feedback loop va model lab.

## 1. Thong diep chinh khi gioi thieu

Nen mo dau ngan gon:

```text
Du an ban dau la Spam Email Classification System.
Em da nang cap thanh MailGuard AI - Adaptive Email Threat Intelligence Platform.

He thong khong chi hoi "email nay la spam hay ham",
ma tra loi:
- Email co nguy hiem khong?
- Nguy hiem theo loai nao: phishing, credential theft, quishing, malware risk?
- Vi sao he thong danh gia nhu vay?
- Nhung email nguy hiem co thuoc cung mot chien dich tan cong khong?
- Nguoi dung co the feedback de cai thien model khong?
```

## 2. Chuan bi truoc khi demo

### 2.1 Kich hoat moi truong

```bash
venv\Scripts\activate
```

Neu chua cai thu vien:

```bash
pip install -r requirements.txt
```

### 2.2 Kiem tra model path

Ung dung doc model trong `src/config/config.py`:

```python
model_path = "outputs/2026-06-08_09-08-52/models/SVM_model.pkl"
feature_path = "outputs/2026-06-08_09-08-52/models/vectorizer.pkl"
```

Neu thu muc `outputs/...` khong co, doi ve model co san:

```python
model_path = "data/models/v1/model.pkl"
feature_path = "data/models/v1/feature.pkl"
```

### 2.3 Kiem tra nhanh truoc gio demo

Chay:

```bash
python -m compileall src app.py scripts
python scripts\smoke_adaptive_threat_intelligence.py
```

Ket qua mong doi:

```text
adaptive threat intelligence smoke passed
```

### 2.4 Cau hinh database neu muon demo dang nhap/dashboard/history

Tao database:

```bash
mysql -u root -p < db/db.sql
```

Tao file `.env`:

```env
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=your_password
DB_NAME=spam_detection
```

Neu MySQL khong san sang, van demo duoc che do khach: single email, URL phishing va QR image. Cac phan can dang nhap nhu dashboard, MBOX, history, feedback se khong hoat dong day du.

### 2.5 Chay ung dung

```bash
streamlit run app.py
```

Mo:

```text
http://localhost:8501
```

## 3. Luong demo tong the

Nen demo theo thu tu nay:

```text
1. Gioi thieu dashboard va muc tieu he thong
2. Demo safe email
3. Demo spam/phishing email
4. Demo URL phishing detection
5. Demo QR/quishing detection
6. Demo MBOX batch + campaign detection
7. Demo history/dashboard sau khi co du lieu
8. Demo feedback loop
9. Demo model lab va tai lieu ky thuat
```

Neu thoi gian chi co 5-7 phut, bo qua training live va chi noi model lab qua docs/output.

## 4. Demo 1 - Email binh thuong

### Input mau

Dan vao tab `Email Don`:

```text
Hi team,

Please review the project report before our meeting tomorrow morning.
I updated the dashboard screenshots and attached the latest notes.

Thanks.
```

### Ket qua mong doi

- Prediction: `Ham`.
- Risk score thap.
- Risk level: `Low`.
- Threat label: `Safe` hoac risk thap.
- Reasons noi khong co dau hieu phishing/link/malware manh.

### Noi khi demo

```text
Voi email cong viec binh thuong, model phan loai la Ham.
Risk aggregator ket hop ML va rule-based analyzer nen ket qua cuoi cung la Low risk.
He thong khong chi hien Ham/Spam ma con hien risk score, threat label va ly do.
```

## 5. Demo 2 - Email phishing/credential theft

### Input mau

```text
URGENT: Your PayPal account has been suspended.

We detected unusual login activity. Verify your password immediately at:
http://paypa1-login.xyz/reset

If you do not verify within 24 hours, your account will be permanently locked.
```

### Ket qua mong doi

- Prediction thuong la `Spam`.
- Risk score cao.
- Risk level: `High` hoac `Critical`.
- Threat label co the la `Spam`, `Phishing` hoac `Credential Theft` tuy score.
- URL analyzer hien domain `paypa1-login.xyz`.
- Reasons co cac dau hieu:
  - urgency/pressure language.
  - password/login/verify.
  - URL khong dung HTTPS.
  - domain/TLD dang nghi.

### Noi khi demo

```text
Email nay co nhieu dau hieu tan cong: yeu cau xac minh mat khau, tao ap luc thoi gian va chua link dang nghi.
He thong dung ML de du doan spam, sau do dung rule-based threat analyzer de cham phishing, fake link, malware.
Risk aggregator hop nhat cac tin hieu nay thanh final verdict va recommended actions.
```

## 6. Demo 3 - Phishing URL Detection

Mo muc `Phishing URL Detection`, dan nhieu URL, moi dong mot URL:

```text
https://google.com
http://paypa1-login.xyz/verify?account=locked
https://bit.ly/free-gift-login
http://192.168.1.10/login
```

### Ket qua mong doi

- URL an toan co score thap.
- URL gia mao/shortener/IP co score cao hon.
- Moi URL co:
  - final destination.
  - domain.
  - extracted features.
  - reasons.

### Noi khi demo

```text
Phan nay khong mo link that, chi phan tich cu phap va dac trung URL.
He thong phat hien short link, raw IP, tu khoa login/verify, TLD rui ro va domain gia mao thuong hieu.
```

## 7. Demo 4 - QR / Quishing Detection

Mo muc `Quishing Detection`, upload anh co QR code.

### Mau QR nen chuan bi

Chuan bi truoc 1 anh QR chua link:

```text
http://paypa1-login.xyz/verify
```

Hoac QR thanh toan neu muon demo payment QR review.

### Ket qua mong doi

- He thong doc QR payload.
- Neu QR chua URL dang nghi, hien URL analysis.
- Neu QR la payment payload, verdict co the la `PAYMENT_QR_REVIEW`.

### Noi khi demo

```text
Quishing la phishing qua QR code.
Nguoi dung thuong khong thay URL that truoc khi quet, nen he thong giai ma QR va cham diem rui ro truoc khi nguoi dung mo link.
```

## 8. Demo 5 - MBOX batch va campaign detection

Phan nay can dang nhap va database hoat dong.

### Cach demo

1. Dang nhap bang tai khoan co san hoac dang ky tai khoan moi.
2. Mo tab `File MBOX`.
3. Upload file MBOX.
4. Bam xu ly.

### Ket qua mong doi

Bang ket qua co cac cot:

- `Prediction`
- `Threat Label`
- `Risk Score`
- `Risk Level`
- `Verdict`
- `Campaign ID`

Neu co nhieu email nguy hiem lien quan, he thong hien `Threat Campaigns`:

- `campaign_id`
- `primary_threat_label`
- `risk_level`
- `risk_score`
- `email_count`
- `top_domains`

Co nut tai:

- Campaign summaries JSON.
- First campaign report Markdown.

### Noi khi demo

```text
Day la diem nang cap lon nhat cua du an.
He thong khong chi phan loai tung email rieng le, ma con gom cac email co chung domain, URL, subject/body, brand hoac thoi gian thanh mot phishing campaign.
No giong mot mini SOC investigation platform.
```

## 9. Demo 6 - Dashboard bao mat

Sau khi da phan tich mot so email, mo tab `Dashboard`.

### Noi dung can chi ra

- Total emails.
- Spam/Ham ratio.
- High risk count.
- Campaign count.
- Threat taxonomy distribution.
- High-risk trend.
- Adaptive learning review queue neu co.
- Model lab runs neu da train model moi.

### Noi khi demo

```text
Dashboard khong chi thong ke spam/ham.
No duoc nang cap thanh security dashboard: risk trend, threat taxonomy, campaign count va review queue.
```

## 10. Demo 7 - Feedback loop va active learning

Phan nay can dang nhap.

### Cach demo

1. Phan tich mot email.
2. Sau khi ket qua duoc luu, mo `Prediction feedback`.
3. Chon:
   - `correct` neu ket qua dung.
   - `incorrect` neu ket qua sai.
4. Neu sai, chon corrected threat label, vi du `Phishing`.
5. Nhap analyst note.
6. Bam `Save feedback`.

### Ket qua mong doi

- Feedback duoc luu neu DB migration da chay.
- Case sai duoc dua vao review queue.
- Dashboard co the hien review queue.

### Noi khi demo

```text
He thong khong retrain truc tiep tu feedback vi co nguy co feedback sai hoac doc.
Thay vao do, feedback di vao review queue. Chi nhung item duoc duyet moi duoc export thanh retraining data.
```

## 11. Demo 8 - Model Evaluation Lab

Khong nen train live neu thoi gian demo ngan, vi GridSearchCV co the lau.

### Noi ve pipeline

Training pipeline:

```bash
python -m src.pipeline.training_pipeline
```

Sau khi train, he thong sinh:

```text
outputs/<timestamp>/models/
outputs/<timestamp>/observations/model_metadata.csv
outputs/<timestamp>/observations/model_comparison_summary.csv
outputs/<timestamp>/observations/threshold_analysis.csv
outputs/<timestamp>/observations/error_analysis.json
outputs/<timestamp>/observations/model_lab_metadata.json
```

### Diem can nhan manh

```text
Model lab khong chi bao accuracy.
No bao per-class precision/recall/F1, macro F1, weighted F1, confusion matrix, threshold analysis va error analysis.
Dieu nay phu hop hon voi bai toan spam/phishing vi du lieu bi lech lop.
```

## 12. Cac cau hoi hoi dong co the hoi

### Cau hoi: Du an khac gi spam classifier co ban?

Tra loi:

```text
Spam classifier co ban chi tra ve Spam/Ham.
Du an nay co them risk score, threat taxonomy, URL/QR analysis, campaign detection, graph-ready investigation, feedback loop va model lab.
No phan tich email nhu mot security event.
```

### Cau hoi: Vi sao khong dung Transformer?

Tra loi:

```text
Transformer co the la huong mo rong, nhung voi do an nay em uu tien hybrid sklearn pipeline vi nhe, giai thich duoc, chay local tot va phu hop demo.
He thong da thiet ke model lab nen sau nay co the them Transformer nhu mot benchmark moi.
```

### Cau hoi: Neu model bao Ham nhung URL nguy hiem thi sao?

Tra loi:

```text
Risk aggregator xu ly truong hop model-rule conflict.
Neu ML bao Ham nhung URL/QR/malware signal cao, risk score van duoc day len va case co the vao review queue.
```

### Cau hoi: Campaign detection dua vao gi?

Tra loi:

```text
He thong tinh similarity dua tren text similarity, domain overlap, URL overlap, sender-domain, brand, QR payload, threat label va time window.
Neu nhieu email co score vuot threshold, chung duoc gom vao mot campaign.
```

### Cau hoi: Feedback co lam model hoc sai khong?

Tra loi:

```text
Khong retrain truc tiep tu feedback.
Feedback vao review queue. Chi item duoc approve moi duoc export thanh retraining data.
Day la cach giam nguy co poisoning.
```

## 13. Loi thuong gap khi demo

### Loi khong load duoc model

Kiem tra `src/config/config.py`. Neu path trong `outputs/...` khong ton tai, doi ve:

```python
model_path = "data/models/v1/model.pkl"
feature_path = "data/models/v1/feature.pkl"
```

### Loi khong dang nhap duoc

Kiem tra:

- MySQL dang chay.
- `.env` dung user/password/database.
- Da chay `mysql -u root -p < db/db.sql`.

### QR khong doc duoc

Thu:

- Anh ro net hon.
- QR lon hon.
- Dinh dang `png` hoac `jpg`.
- QR khong bi nghieng/cat goc.

### MBOX khong co campaign

Khong phai loi. Neu file chi co email rieng le, he thong se khong ep tao campaign. Muon demo campaign, can file co nhieu email cung domain/link/subject phishing.

## 14. Checklist ngay truoc khi bao ve

- [ ] Chay `python -m compileall src app.py scripts`.
- [ ] Chay `python scripts\smoke_adaptive_threat_intelligence.py`.
- [ ] Kiem tra model path trong `src/config/config.py`.
- [ ] Chay Streamlit va mo `http://localhost:8501`.
- [ ] Chuan bi san input safe email.
- [ ] Chuan bi san input phishing email.
- [ ] Chuan bi san danh sach URL demo.
- [ ] Chuan bi san anh QR neu demo quishing.
- [ ] Chuan bi san file MBOX neu demo campaign.
- [ ] Dang nhap thu truoc neu demo dashboard/history/feedback.

## 15. Ket luan nen noi

```text
Ket qua cuoi cung la MailGuard AI - mot he thong phan tich an toan email tong hop.
Du an van co nen tang ML spam classification, nhung duoc nang cap them risk scoring, explainability, URL/QR phishing detection, campaign intelligence, dashboard va adaptive feedback learning.
Huong phat trien tiep theo la bo sung du lieu phishing that, them header authentication SPF/DKIM/DMARC va benchmark Transformer trong Model Lab.
```
