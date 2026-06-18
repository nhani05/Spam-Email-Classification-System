from pathlib import Path

import cv2


OUTPUT_DIR = Path(__file__).resolve().parent / "qr"
PAYLOADS = {
    "qr_phishing_login.png": "http://secure-login-example.com/account/verify",
    "qr_safe_company_page.png": "https://www.example.com/company/news",
}


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    encoder = cv2.QRCodeEncoder_create()

    for filename, payload in PAYLOADS.items():
        matrix = encoder.encode(payload)
        image = cv2.resize(matrix, (420, 420), interpolation=cv2.INTER_NEAREST)
        output_path = OUTPUT_DIR / filename
        if not cv2.imwrite(str(output_path), image):
            raise RuntimeError(f"Could not write {output_path}")
        print(f"generated {output_path}")


if __name__ == "__main__":
    main()

