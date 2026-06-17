import glob
import os
from dataclasses import dataclass


def get_latest_output_dir(base_dir: str = "outputs") -> str:
    """Find the newest training output directory for the spam classifier."""
    try:
        dirs = [d for d in glob.glob(f"{base_dir}/*") if os.path.isdir(d)]
        dirs = [d for d in dirs if "my_tiny_summarizer" not in d]
        if dirs:
            return max(dirs, key=os.path.getmtime).replace("\\", "/")
    except Exception:
        pass
    return "outputs/2026-06-08_09-08-52"


LATEST_DIR = get_latest_output_dir("outputs")


@dataclass
class Config:
    training_data_path: str = "data/dataset/dataset.csv"
    ai_threat_data_base_dir: str = "data/ai_threat"
    ai_threat_raw_dir: str = "data/ai_threat/raw"
    ai_threat_interim_dir: str = "data/ai_threat/interim"
    ai_threat_canonical_dir: str = "data/ai_threat/canonical"
    ai_threat_manifest_dir: str = "data/ai_threat/manifests"
    ai_threat_feedback_dir: str = "data/ai_threat/feedback"
    ai_threat_fixture_dir: str = "data/ai_threat/fixtures"
    ai_threat_email_data_path: str = "data/ai_threat/canonical/email_threat_canonical.csv"
    ai_threat_url_data_path: str = "data/ai_threat/canonical/url_threat_canonical.csv"
    ai_threat_email_fixture_path: str = "data/ai_threat/email_threat_seed.csv"
    ai_threat_url_fixture_path: str = "data/ai_threat/url_threat_seed.csv"
    ai_threat_dataset_manifest_path: str = "data/ai_threat/manifests/latest_sources.json"
    ai_threat_published_run_path: str = "outputs/ai-threat-current/published_run.json"
    ai_threat_fixture_mode: bool = False
    ai_threat_publish_min_total_rows: int = 40
    ai_threat_publish_min_per_class: int = 2
    ai_threat_publish_min_macro_f1: float = 0.35
    ai_threat_publish_min_required_recall: float = 0.20
    validation_data_path: str = "data/dataset/All_mail_Including_Spam_and_Trash.mbox"
    OUTPUT_BASE_DIR: str = "outputs"
    model_path: str = f"{LATEST_DIR}/models/SVM_model.pkl"
    feature_path: str = f"{LATEST_DIR}/models/vectorizer.pkl"
    ai_threat_model_path: str = "outputs/ai-threat-current/models/email_threat_model.pkl"
    ai_url_model_path: str = "outputs/ai-threat-current/models/url_phishing_model.pkl"


class ModelConfig:
    models = {
        "LogisticRegression": {
            "C": [0.01, 0.1, 1, 10, 100],
            "solver": ["lbfgs", "liblinear"],
            "max_iter": [100, 200, 300],
        },
        "DecisionTree": {
            "criterion": ["gini", "entropy"],
            "max_depth": [5, 10, 15, 20, None],
            "min_samples_split": [2, 5, 10],
            "min_samples_leaf": [1, 2, 4],
        },
        "SVM": {
            "C": [0.1, 1, 10],
            "kernel": ["linear", "rbf"],
            "gamma": ["scale", "auto"],
        },
        "KNN": {
            "n_neighbors": [3, 5, 7, 9, 11],
            "weights": ["uniform", "distance"],
            "metric": ["euclidean", "manhattan"],
        },
        "RandomForest": {
            "n_estimators": [50, 100, 200],
            "max_depth": [10, 20, 30, None],
            "min_samples_split": [2, 5, 10],
            "min_samples_leaf": [1, 2, 4],
            "max_features": ["sqrt", "log2"],
        },
    }
