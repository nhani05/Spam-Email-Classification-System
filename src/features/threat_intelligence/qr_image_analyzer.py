from dataclasses import dataclass, field
from io import BytesIO
from typing import Dict, List

import numpy as np
from PIL import Image, ImageEnhance, ImageFilter

from .url_risk_model import URLRiskModel


@dataclass
class QRImageAnalysisResult:
    qr_found: bool
    qr_count: int
    image_size: tuple[int, int]
    max_risk_score: int
    final_verdict: str
    risk_level: str
    qr_results: List[Dict[str, object]] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "qr_found": self.qr_found,
            "qr_count": self.qr_count,
            "image_size": self.image_size,
            "max_risk_score": self.max_risk_score,
            "final_verdict": self.final_verdict,
            "risk_level": self.risk_level,
            "qr_results": self.qr_results,
            "reasons": self.reasons,
            "warnings": self.warnings,
        }


class QRImageAnalyzer:
    """Detect QR codes in email images and classify phishing risk."""

    def __init__(self) -> None:
        self.url_model = URLRiskModel()

    def analyze_image_bytes(self, image_bytes: bytes) -> QRImageAnalysisResult:
        image = Image.open(BytesIO(image_bytes)).convert("RGB")
        decoded_values, warnings = self._decode_qr_values(image)

        qr_results = []
        for value in decoded_values:
            qr_results.append(self.url_model.analyze(value).to_dict())

        if not qr_results:
            return QRImageAnalysisResult(
                qr_found=False,
                qr_count=0,
                image_size=image.size,
                max_risk_score=0,
                final_verdict="NO_QR_FOUND",
                risk_level="Low",
                reasons=["No QR code was detected in this image."],
                warnings=warnings,
            )

        max_score = max(item["risk_score"] for item in qr_results)
        risk_level = self._risk_level(max_score)
        final_verdict = self._final_verdict(max_score)
        reasons = self._combine_reasons(qr_results)

        return QRImageAnalysisResult(
            qr_found=True,
            qr_count=len(qr_results),
            image_size=image.size,
            max_risk_score=max_score,
            final_verdict=final_verdict,
            risk_level=risk_level,
            qr_results=qr_results,
            reasons=reasons,
            warnings=warnings,
        )

    def _decode_qr_values(self, image: Image.Image) -> tuple[List[str], List[str]]:
        warnings: List[str] = []
        try:
            import cv2
        except ImportError:
            return [], [
                "OpenCV is not installed. Install opencv-python to enable QR detection."
            ]

        candidates = self._image_candidates(image)
        found: List[str] = []

        for candidate in candidates:
            array = np.array(candidate)
            detector = cv2.QRCodeDetector()

            decoded_multi = detector.detectAndDecodeMulti(array)
            if decoded_multi and decoded_multi[0]:
                for value in decoded_multi[1]:
                    if value and value not in found:
                        found.append(value)

            value, _, _ = detector.detectAndDecode(array)
            if value and value not in found:
                found.append(value)

        return found, warnings

    def _image_candidates(self, image: Image.Image) -> List[Image.Image]:
        grayscale = image.convert("L")
        contrast = ImageEnhance.Contrast(grayscale).enhance(2.0)
        sharpened = contrast.filter(ImageFilter.SHARPEN)
        padded = self._pad_image(image)
        large = self._scale_image(padded, 3)
        cv_candidates = self._stylized_qr_candidates(image)

        return [
            image,
            padded,
            large,
            grayscale.convert("RGB"),
            contrast.convert("RGB"),
            sharpened.convert("RGB"),
            *cv_candidates,
        ]

    def _stylized_qr_candidates(self, image: Image.Image) -> List[Image.Image]:
        """Build black/white crops for colored QR codes such as VietQR."""
        try:
            import cv2
        except ImportError:
            return []

        rgb = np.array(image.convert("RGB"))
        hsv = cv2.cvtColor(rgb, cv2.COLOR_RGB2HSV)
        gray = cv2.cvtColor(rgb, cv2.COLOR_RGB2GRAY)

        saturation = hsv[:, :, 1]
        value = hsv[:, :, 2]
        colored_dark = ((saturation > 35) & (value < 210)).astype("uint8") * 255
        dark = (gray < 175).astype("uint8") * 255
        mask = cv2.bitwise_or(colored_dark, dark)

        kernel = np.ones((9, 9), np.uint8)
        merged = cv2.dilate(mask, kernel, iterations=2)
        merged = cv2.morphologyEx(merged, cv2.MORPH_CLOSE, kernel, iterations=2)

        contours, _ = cv2.findContours(merged, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        crops: List[Image.Image] = []
        image_area = image.size[0] * image.size[1]

        for contour in contours:
            x, y, w, h = cv2.boundingRect(contour)
            area = w * h
            if area < image_area * 0.03:
                continue
            aspect = w / h if h else 0
            if not 0.65 <= aspect <= 1.35:
                continue

            margin = max(20, int(max(w, h) * 0.18))
            x1 = max(0, x - margin)
            y1 = max(0, y - margin)
            x2 = min(rgb.shape[1], x + w + margin)
            y2 = min(rgb.shape[0], y + h + margin)
            crop = rgb[y1:y2, x1:x2]
            crops.extend(self._binarized_crop_variants(crop))

        if crops:
            return crops

        return self._binarized_crop_variants(rgb)

    def _binarized_crop_variants(self, crop_rgb: np.ndarray) -> List[Image.Image]:
        try:
            import cv2
        except ImportError:
            return []

        gray = cv2.cvtColor(crop_rgb, cv2.COLOR_RGB2GRAY)
        hsv = cv2.cvtColor(crop_rgb, cv2.COLOR_RGB2HSV)

        masks = [
            cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1],
            np.where((hsv[:, :, 1] > 25) & (hsv[:, :, 2] < 230), 0, 255).astype("uint8"),
            np.where(gray < 190, 0, 255).astype("uint8"),
        ]

        variants: List[Image.Image] = []
        for binary in masks:
            cleaned = cv2.morphologyEx(binary, cv2.MORPH_CLOSE, np.ones((3, 3), np.uint8))
            pil = Image.fromarray(cleaned).convert("RGB")
            padded = self._pad_image(pil)
            variants.append(padded)
            variants.append(self._scale_image(padded, 3))

        return variants

    def _pad_image(self, image: Image.Image) -> Image.Image:
        width, height = image.size
        padding = max(24, min(width, height) // 10)
        padded = Image.new("RGB", (width + padding * 2, height + padding * 2), "white")
        padded.paste(image.convert("RGB"), (padding, padding))
        return padded

    def _scale_image(self, image: Image.Image, factor: int) -> Image.Image:
        width, height = image.size
        return image.resize((width * factor, height * factor), Image.Resampling.NEAREST)

    def _combine_reasons(self, qr_results: List[Dict[str, object]]) -> List[str]:
        reasons: List[str] = []
        for index, result in enumerate(qr_results, start=1):
            for reason in result["reasons"]:
                tagged = f"QR #{index}: {reason}"
                if tagged not in reasons:
                    reasons.append(tagged)
        return reasons

    def _risk_level(self, score: int) -> str:
        if score >= 80:
            return "Critical"
        if score >= 60:
            return "High"
        if score >= 35:
            return "Medium"
        return "Low"

    def _final_verdict(self, score: int) -> str:
        if score >= 80:
            return "PHISHING_QR_IMAGE"
        if score >= 60:
            return "HIGH_RISK_QR_IMAGE"
        if score >= 35:
            return "SUSPICIOUS_QR_IMAGE"
        return "LOW_RISK_QR_IMAGE"
