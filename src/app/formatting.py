import re

import pandas as pd

def _risk_level_vi(value: str) -> str:
    if value is None:
        return "KhÃ´ng rÃµ"
    try:
        if pd.isna(value):
            return "KhÃ´ng rÃµ"
    except (TypeError, ValueError):
        pass
    mapping = {
        "Low": "Tháº¥p",
        "Medium": "Trung bÃ¬nh",
        "High": "Cao",
        "Critical": "NghiÃªm trá»ng",
    }
    return mapping.get(str(value), str(value))


def _verdict_vi(value: str) -> str:
    mapping = {
        "LOW_RISK_EMAIL": "Email rá»§i ro tháº¥p",
        "SPAM_LOW_THREAT": "Spam nhÆ°ng tÃ­n hiá»‡u Ä‘e dá»a tháº¥p",
        "SUSPICIOUS_EMAIL": "Email Ä‘Ã¡ng nghi",
        "HIGH_RISK_EMAIL": "Email rá»§i ro cao",
        "CRITICAL_EMAIL_THREAT": "Email nguy hiá»ƒm nghiÃªm trá»ng",
        "MALWARE_RISK_EMAIL": "Email cÃ³ nguy cÆ¡ mÃ£ Ä‘á»™c",
        "FAKE_LINK_PHISHING": "Email cÃ³ liÃªn káº¿t giáº£ máº¡o",
        "QUISHING_EMAIL": "Email cÃ³ dáº¥u hiá»‡u quishing",
        "PAYMENT_SCAM_EMAIL": "Email cÃ³ dáº¥u hiá»‡u lá»«a Ä‘áº£o thanh toÃ¡n",
        "CREDENTIAL_THEFT_EMAIL": "Email cÃ³ dáº¥u hiá»‡u Ä‘Ã¡nh cáº¯p thÃ´ng tin Ä‘Äƒng nháº­p",
        "LOW_RISK_URL": "URL rá»§i ro tháº¥p",
        "UNKNOWN_SHORT_LINK": "LiÃªn káº¿t rÃºt gá»n cáº§n kiá»ƒm tra",
        "SUSPICIOUS_URL": "URL Ä‘Ã¡ng nghi",
        "HIGH_RISK_URL": "URL rá»§i ro cao",
        "PHISHING_URL": "URL phishing",
        "PAYMENT_QR_REVIEW": "QR thanh toÃ¡n cáº§n kiá»ƒm tra",
        "NON_URL_QR": "QR khÃ´ng chá»©a URL",
        "NO_QR_FOUND": "KhÃ´ng tÃ¬m tháº¥y QR",
        "LOW_RISK_QR_IMAGE": "áº¢nh QR rá»§i ro tháº¥p",
        "SUSPICIOUS_QR_IMAGE": "áº¢nh QR Ä‘Ã¡ng nghi",
        "HIGH_RISK_QR_IMAGE": "áº¢nh QR rá»§i ro cao",
        "PHISHING_QR_IMAGE": "áº¢nh QR phishing",
    }
    return mapping.get(str(value), str(value))


def _threat_label_vi(value: str) -> str:
    if value is None:
        return "KhÃ´ng rÃµ"
    try:
        if pd.isna(value):
            return "KhÃ´ng rÃµ"
    except (TypeError, ValueError):
        pass
    mapping = {
        "Safe": "An toÃ n",
        "Spam": "Spam",
        "Phishing": "Phishing",
        "Malware Risk": "Nguy cÆ¡ mÃ£ Ä‘á»™c",
        "Business Email Compromise": "Giáº£ máº¡o email doanh nghiá»‡p",
        "Quishing": "Quishing",
        "Credential Theft": "ÄÃ¡nh cáº¯p thÃ´ng tin Ä‘Äƒng nháº­p",
        "Payment Scam": "Lá»«a Ä‘áº£o thanh toÃ¡n",
    }
    return mapping.get(str(value), str(value))


def _message_vi(message: object) -> str:
    text = str(message)
    exact = {
        "No strong spam, phishing, fake-link, or malware indicator found.": (
            "KhÃ´ng phÃ¡t hiá»‡n chá»‰ bÃ¡o máº¡nh vá» spam, phishing, liÃªn káº¿t giáº£ hoáº·c mÃ£ Ä‘á»™c."
        ),
        "ML classifier predicts Spam.": "MÃ´ hÃ¬nh ML dá»± Ä‘oÃ¡n email lÃ  Spam.",
        "ML classifier predicts Ham, but confidence was unavailable.": (
            "MÃ´ hÃ¬nh ML dá»± Ä‘oÃ¡n email lÃ  Ham, nhÆ°ng khÃ´ng cÃ³ Ä‘á»™ tin cáº­y."
        ),
        "Rule-based threat analysis found high-risk signals even though the ML label is Ham.": (
            "Bá»™ phÃ¢n tÃ­ch theo luáº­t phÃ¡t hiá»‡n tÃ­n hiá»‡u rá»§i ro cao dÃ¹ nhÃ£n ML lÃ  Ham."
        ),
        "ML spam signal is the main risk indicator; rule-based threat signals are low.": (
            "TÃ­n hiá»‡u spam tá»« ML lÃ  chá»‰ bÃ¡o rá»§i ro chÃ­nh; tÃ­n hiá»‡u theo luáº­t Ä‘ang tháº¥p."
        ),
        "No strong phishing signal found.": "KhÃ´ng phÃ¡t hiá»‡n tÃ­n hiá»‡u phishing máº¡nh.",
        "URL does not use HTTPS.": "URL khÃ´ng sá»­ dá»¥ng HTTPS.",
        "URL uses a raw IP address instead of a domain.": "URL dÃ¹ng Ä‘á»‹a chá»‰ IP trá»±c tiáº¿p thay vÃ¬ tÃªn miá»n.",
        "URL points to a shortened URL.": "URL trá» tá»›i dá»‹ch vá»¥ rÃºt gá»n liÃªn káº¿t.",
        "URL contains a nested redirect parameter.": "URL chá»©a tham sá»‘ chuyá»ƒn hÆ°á»›ng lá»“ng nhau.",
        "URL contains '@', which can hide the real destination.": "URL chá»©a kÃ½ tá»± '@', cÃ³ thá»ƒ che giáº¥u Ä‘Ã­ch tháº­t.",
        "URL contains encoded characters such as '%', which can hide text.": (
            "URL chá»©a kÃ½ tá»± mÃ£ hÃ³a nhÆ° '%', cÃ³ thá»ƒ che giáº¥u ná»™i dung."
        ),
        "Domain has an unusual number of subdomains.": "TÃªn miá»n cÃ³ sá»‘ lÆ°á»£ng subdomain báº¥t thÆ°á»ng.",
        "URL is unusually long.": "URL dÃ i báº¥t thÆ°á»ng.",
        "Domain name is unusually long.": "TÃªn miá»n dÃ i báº¥t thÆ°á»ng.",
        "Domain contains many digits.": "TÃªn miá»n chá»©a nhiá»u chá»¯ sá»‘.",
        "Domain contains many hyphens.": "TÃªn miá»n chá»©a nhiá»u dáº¥u gáº¡ch ná»‘i.",
        "Domain uses a high-risk top-level domain.": "TÃªn miá»n dÃ¹ng TLD cÃ³ rá»§i ro cao.",
        "URL appears to point to a risky executable file.": "URL cÃ³ váº» trá» tá»›i file thá»±c thi rá»§i ro.",
        "QR code contains a payment payload, not a web URL.": "QR chá»©a ná»™i dung thanh toÃ¡n, khÃ´ng pháº£i URL web.",
        "Verify recipient name, bank, and account number before transferring money.": (
            "HÃ£y xÃ¡c minh tÃªn ngÆ°á»i nháº­n, ngÃ¢n hÃ ng vÃ  sá»‘ tÃ i khoáº£n trÆ°á»›c khi chuyá»ƒn tiá»n."
        ),
        "Payment QR codes in unexpected emails can be used for invoice or receipt scams.": (
            "QR thanh toÃ¡n trong email báº¥t ngá» cÃ³ thá»ƒ bá»‹ dÃ¹ng cho lá»«a Ä‘áº£o hÃ³a Ä‘Æ¡n hoáº·c biÃªn lai."
        ),
        "QR code was decoded, but it does not contain a web URL.": "QR Ä‘Ã£ Ä‘Æ°á»£c giáº£i mÃ£ nhÆ°ng khÃ´ng chá»©a URL web.",
        "No QR code was detected in this image.": "KhÃ´ng phÃ¡t hiá»‡n QR code trong áº£nh nÃ y.",
        "OpenCV is not installed. Install opencv-python to enable QR detection.": (
            "ChÆ°a cÃ i OpenCV. HÃ£y cÃ i `opencv-python` Ä‘á»ƒ báº­t nháº­n diá»‡n QR."
        ),
        "Do not click links, scan QR codes, download files, or reply to this email.": (
            "KhÃ´ng nháº¥p liÃªn káº¿t, quÃ©t QR, táº£i file hoáº·c tráº£ lá»i email nÃ y."
        ),
        "Report or delete the message after preserving evidence if needed.": (
            "BÃ¡o cÃ¡o hoáº·c xÃ³a thÆ° sau khi lÆ°u báº±ng chá»©ng náº¿u cáº§n."
        ),
        "Treat this email as dangerous until verified through a trusted channel.": (
            "Xem email nÃ y lÃ  nguy hiá»ƒm cho tá»›i khi xÃ¡c minh qua kÃªnh tin cáº­y."
        ),
        "Do not provide passwords, OTP codes, payment details, or personal information.": (
            "KhÃ´ng cung cáº¥p máº­t kháº©u, mÃ£ OTP, thÃ´ng tin thanh toÃ¡n hoáº·c thÃ´ng tin cÃ¡ nhÃ¢n."
        ),
        "Review the sender, links, and attachments carefully before taking action.": (
            "Kiá»ƒm tra ká»¹ ngÆ°á»i gá»­i, liÃªn káº¿t vÃ  tá»‡p Ä‘Ã­nh kÃ¨m trÆ°á»›c khi thao tÃ¡c."
        ),
        "Open the official website directly instead of using links in the email.": (
            "Má»Ÿ website chÃ­nh thá»©c trá»±c tiáº¿p thay vÃ¬ dÃ¹ng liÃªn káº¿t trong email."
        ),
        "No urgent action is required, but keep normal email safety checks in mind.": (
            "KhÃ´ng cáº§n hÃ nh Ä‘á»™ng kháº©n cáº¥p, nhÆ°ng váº«n nÃªn kiá»ƒm tra an toÃ n email nhÆ° bÃ¬nh thÆ°á»ng."
        ),
        "Verify detected domains before opening any link.": "XÃ¡c minh cÃ¡c tÃªn miá»n phÃ¡t hiá»‡n Ä‘Æ°á»£c trÆ°á»›c khi má»Ÿ liÃªn káº¿t.",
        "Do not open mentioned attachments or downloads unless you trust the sender.": (
            "KhÃ´ng má»Ÿ tá»‡p Ä‘Ã­nh kÃ¨m hoáº·c ná»™i dung táº£i xuá»‘ng náº¿u chÆ°a tin cáº­y ngÆ°á»i gá»­i."
        ),
    }
    if text in exact:
        return exact[text]

    match = re.fullmatch(r"ML classifier predicts Spam with ([0-9.]+)% confidence\.", text)
    if match:
        return f"MÃ´ hÃ¬nh ML dá»± Ä‘oÃ¡n email lÃ  Spam vá»›i Ä‘á»™ tin cáº­y {match.group(1)}%."

    match = re.fullmatch(r"ML classifier predicts Ham, but confidence is low \(([0-9.]+)%\)\.", text)
    if match:
        return f"MÃ´ hÃ¬nh ML dá»± Ä‘oÃ¡n email lÃ  Ham nhÆ°ng Ä‘á»™ tin cáº­y tháº¥p ({match.group(1)}%)."

    match = re.fullmatch(r"ML classifier predicts Ham with ([0-9.]+)% confidence\.", text)
    if match:
        return f"MÃ´ hÃ¬nh ML dá»± Ä‘oÃ¡n email lÃ  Ham vá»›i Ä‘á»™ tin cáº­y {match.group(1)}%."

    match = re.fullmatch(r"URL contains sensitive phishing keywords: (.+)\.", text)
    if match:
        return f"URL chá»©a tá»« khÃ³a nháº¡y cáº£m thÆ°á»ng gáº·p trong phishing: {match.group(1)}."

    match = re.fullmatch(r"Domain resembles (.+) but is not the official domain (.+)\.", text)
    if match:
        return f"TÃªn miá»n giá»‘ng {match.group(1)} nhÆ°ng khÃ´ng pháº£i tÃªn miá»n chÃ­nh thá»©c {match.group(2)}."

    match = re.fullmatch(r"Email is linked to campaign (.+) \((.+) risk\)\.", text)
    if match:
        return f"Email liÃªn quan tá»›i chiáº¿n dá»‹ch {match.group(1)} vá»›i má»©c rá»§i ro {_risk_level_vi(match.group(2))}."

    match = re.fullmatch(r"QR #([0-9]+): (.+)", text)
    if match:
        return f"QR #{match.group(1)}: {_message_vi(match.group(2))}"

    return text


def _features_vi(features: dict) -> dict:
    labels = {
        "uses_https": "DÃ¹ng HTTPS",
        "uses_ip_address": "DÃ¹ng Ä‘á»‹a chá»‰ IP",
        "is_shortened": "LiÃªn káº¿t rÃºt gá»n",
        "has_nested_redirect": "CÃ³ chuyá»ƒn hÆ°á»›ng lá»“ng nhau",
        "has_at_symbol": "CÃ³ kÃ½ tá»± @",
        "has_encoded_chars": "CÃ³ kÃ½ tá»± mÃ£ hÃ³a",
        "has_many_subdomains": "Nhiá»u subdomain",
        "url_length": "Äá»™ dÃ i URL",
        "domain_length": "Äá»™ dÃ i tÃªn miá»n",
        "digit_count": "Sá»‘ chá»¯ sá»‘ trong tÃªn miá»n",
        "hyphen_count": "Sá»‘ dáº¥u gáº¡ch ná»‘i",
        "encoded_char_count": "Sá»‘ kÃ½ tá»± mÃ£ hÃ³a",
        "suspicious_tld": "TLD rá»§i ro cao",
        "keyword_hits": "Tá»« khÃ³a nháº¡y cáº£m",
        "brand_impersonation": "Dáº¥u hiá»‡u giáº£ máº¡o thÆ°Æ¡ng hiá»‡u",
        "is_url": "LÃ  URL",
        "is_payment_payload": "Ná»™i dung thanh toÃ¡n",
        "payload_length": "Äá»™ dÃ i ná»™i dung",
    }
    result = {}
    for key, value in features.items():
        if isinstance(value, bool):
            value = "CÃ³" if value else "KhÃ´ng"
        result[labels.get(key, key)] = value
    return result
