# MailGuard AI Demo Inputs

All demo data in this folder is written in English to match the current Spam/Ham and phishing models.

## Recommended Demo Order

1. Copy content from `emails/01_ham_project_update.txt` into the `Single Email` tab.
2. Copy content from `emails/02_spam_prize_claim.txt` into the `Single Email` tab.
3. Copy content from `emails/03_phishing_account_lock.txt` into the `Phishing Detector > Email/Text` tab.
4. Upload `qr/qr_phishing_login.png` into `Phishing Detector > QR phishing`.
5. Log in, then upload `mbox/mailguard_demo_inbox.mbox` into the `File MBOX` tab.
6. Upload the same MBOX file into `Summarizer` or `Chatbot`.
7. Ask the chatbot questions from `chatbot_questions.txt`.

## Files

| Path | Purpose |
| --- | --- |
| `emails/01_ham_project_update.txt` | Safe business email for Ham classification |
| `emails/02_spam_prize_claim.txt` | Obvious promotional spam |
| `emails/03_phishing_account_lock.txt` | Credential phishing email/text |
| `emails/04_phishing_invoice_payment.txt` | Payment/invoice phishing email/text |
| `emails/05_ham_invoice_notice.txt` | Legitimate invoice-style email |
| `emails/06_long_thread_for_summary.txt` | Longer email thread for summarizer |
| `urls/demo_urls.txt` | Safe and suspicious URLs for phishing text testing |
| `mbox/mailguard_demo_inbox.mbox` | Mixed mailbox for MBOX batch, summarizer and RAG chatbot |
| `qr/qr_payloads.txt` | Payloads encoded in generated QR images |
| `qr/qr_phishing_login.png` | QR code containing a suspicious login URL |
| `qr/qr_safe_company_page.png` | QR code containing a benign company URL |
| `chatbot_questions.txt` | Ready-to-use RAG chatbot questions |

## Expected Behavior

- Ham examples should usually be classified as `Ham`.
- Spam examples should usually be classified as `Spam`.
- Phishing examples should usually receive a high phishing score.
- Model behavior can vary depending on the currently loaded artifacts in `outputs/` or `data/models/v1/`.

