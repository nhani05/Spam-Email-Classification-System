from src.shared.logger import get_logger
from src.config.config import Config
from src.shared.state import TrainingState
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.pipeline import FeatureUnion
from scipy.sparse import csr_matrix
import numpy as np
import re

logger = get_logger(__name__)


class SecurityNumericFeatureTransformer(BaseEstimator, TransformerMixin):
    """Small explainable numeric features for hybrid email-threat modeling."""

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        rows = []
        for value in X:
            text = str(value or "")
            lower = text.lower()
            urls = re.findall(r"(?i)\b(?:https?://|www\.)\S+|(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/\S*)?", text)
            rows.append([
                len(text),
                sum(ch.isdigit() for ch in text),
                len(urls),
                lower.count("!"),
                int(any(token in lower for token in ("urgent", "immediately", "verify", "account locked"))),
                int(any(token in lower for token in ("password", "otp", "login", "2fa"))),
                int(any(token in lower for token in ("invoice", "payment", "bank", "refund", "$"))),
                int(any(token in lower for token in (".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".apk"))),
            ])
        return csr_matrix(np.asarray(rows, dtype=float))

class DataTransformation:
    def __init__(self):
        self.config = Config()
    
    def transform_data(self, state: TrainingState) -> TrainingState:
        logger.info("Data transformation started")
        try:
            data = state.training_data.copy()
            
            # Encode labels: spam -> 0, ham -> 1
            data.loc[data['Category'] == 'spam', 'Category'] = 0
            data.loc[data['Category'] == 'ham', 'Category'] = 1
            
            # Ensure Category column is integer type
            data['Category'] = data['Category'].astype(int)
            
            logger.info(f"Label encoding completed. Data shape: {data.shape}")
            logger.info(f"Unique labels: {data['Category'].unique()}")
            logger.info(f"Label dtype: {data['Category'].dtype}")
            
            # Threat taxonomy baseline labels for reporting/model-lab exports.
            data["ThreatLabel"] = data["Category"].map({0: "Spam", 1: "Safe"}).fillna("Safe")

            # Split features and target
            X = data['Message']
            y = data['Category']
            
            # Convert y to numpy array of integers to ensure proper type
            import numpy as np
            y = np.array(y, dtype=int)
            
            # Split into train and test sets (70:30 ratio)
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.3, random_state=42, stratify=y
            )
            
            logger.info(f"Train/test split completed. Train size: {len(X_train)}, Test size: {len(X_test)}")
            
            # Apply hybrid vectorization: word TF-IDF + char n-grams + numeric security signals.
            tfidf_vectorizer = FeatureUnion([
                ("word_tfidf", TfidfVectorizer(lowercase=True, stop_words='english', ngram_range=(1, 2), max_features=30000)),
                ("char_tfidf", TfidfVectorizer(lowercase=True, analyzer="char_wb", ngram_range=(3, 5), max_features=20000)),
                ("security_numeric", SecurityNumericFeatureTransformer()),
            ])
            X_train_tfidf = tfidf_vectorizer.fit_transform(X_train)
            X_test_tfidf = tfidf_vectorizer.transform(X_test)
            
            logger.info(f"TF-IDF transformation completed. Feature shape: {X_train_tfidf.shape}")
            
            # Save to state
            state.transformed_data = data
            state.X_train = X_train
            state.X_test = X_test
            state.y_train = y_train
            state.y_test = y_test
            state.X_train_tfidf = X_train_tfidf
            state.X_test_tfidf = X_test_tfidf
            state.tfidf_vectorizer = tfidf_vectorizer
            state.threat_labels = data["ThreatLabel"]
            state.feature_config = {
                "word_tfidf": {"ngram_range": [1, 2], "max_features": 30000, "stop_words": "english"},
                "char_tfidf": {"analyzer": "char_wb", "ngram_range": [3, 5], "max_features": 20000},
                "security_numeric": [
                    "length",
                    "digit_count",
                    "url_count",
                    "exclamation_count",
                    "urgency_flag",
                    "credential_flag",
                    "payment_flag",
                    "risky_file_flag",
                ],
                "taxonomy": {"spam": "Spam", "ham": "Safe"},
            }
            
            logger.info("Data transformation completed")
            return state
        except Exception as e:
            logger.error(f"Failed to transform data: {str(e)}")
            raise e
