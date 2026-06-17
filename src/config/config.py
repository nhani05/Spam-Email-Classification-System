import os
import glob
from dataclasses import dataclass

CURRENT_OUTPUT_DIR_NAME = "email_spam_classifier"


def _classifier_artifacts_exist(output_dir: str) -> bool:
    """Check whether an output directory has the legacy spam classifier artifacts."""
    model_path = os.path.join(output_dir, "models", "model.pkl")
    legacy_model_path = os.path.join(output_dir, "models", "SVM_model.pkl")
    feature_path = os.path.join(output_dir, "models", "vectorizer.pkl")
    return (os.path.isfile(model_path) or os.path.isfile(legacy_model_path)) and os.path.isfile(feature_path)


def get_latest_output_dir(base_dir="outputs"):
    """Tự động tìm thư mục huấn luyện mới nhất có đủ artifact classifier."""
    try:
        current_dir = os.path.join(base_dir, CURRENT_OUTPUT_DIR_NAME)
        if os.path.isdir(current_dir) and _classifier_artifacts_exist(current_dir):
            return current_dir.replace("\\", "/")

        dirs = [d for d in glob.glob(f"{base_dir}/*") if os.path.isdir(d)]
        # Bỏ qua thư mục của AI tóm tắt và các run chỉ chứa artifact threat-intelligence.
        valid_dirs = [d for d in dirs if _classifier_artifacts_exist(d)]
        if valid_dirs:
            return max(valid_dirs, key=os.path.getmtime).replace('\\', '/')
    except Exception:
        pass
    return "data/models/v1"

LATEST_DIR = get_latest_output_dir("outputs")
LATEST_MODEL_FILE = "model.pkl"
if not LATEST_DIR.startswith("data/models/v1") and not os.path.isfile(os.path.join(LATEST_DIR, "models", "model.pkl")):
    LATEST_MODEL_FILE = "SVM_model.pkl"

@dataclass
class Config:
    training_data_path: str = "data/dataset/dataset.csv"
    validation_data_path: str = "data/dataset/All_mail_Including_Spam_and_Trash.mbox"
    OUTPUT_BASE_DIR: str = "outputs"
    current_output_dir: str = f"outputs/{CURRENT_OUTPUT_DIR_NAME}"
    model_path: str = (
        f"{LATEST_DIR}/model.pkl"
        if LATEST_DIR.startswith("data/models/v1")
        else f"{LATEST_DIR}/models/{LATEST_MODEL_FILE}"
    )
    feature_path: str = (
        f"{LATEST_DIR}/feature.pkl"
        if LATEST_DIR.startswith("data/models/v1")
        else f"{LATEST_DIR}/models/vectorizer.pkl"
    )

class ModelConfig:
    models = {
        'LogisticRegression': {
            'C': [1],
            'solver': ['liblinear'],
            'max_iter': [1000]
        },
        'DecisionTree': {
            'criterion': ['gini'],
            'max_depth': [None],
            'min_samples_split': [2],
            'min_samples_leaf': [1]
        },
        'SVM': {
            'C': [1],
            'kernel': ['linear'],
            'gamma': ['scale']
        },
        'KNN': {
            'n_neighbors': [5],
            'weights': ['uniform'],
            'metric': ['euclidean']
        },
        'RandomForest': {
            'n_estimators': [100],
            'max_depth': [None],
            'min_samples_split': [2],
            'min_samples_leaf': [1],
            'max_features': ['sqrt']
        }
    }
