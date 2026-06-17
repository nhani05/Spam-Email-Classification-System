import os
import glob
from dataclasses import dataclass

def get_latest_output_dir(base_dir="outputs"):
    """Tự động tìm thư mục huấn luyện mới nhất"""
    try:
        dirs = [d for d in glob.glob(f"{base_dir}/*") if os.path.isdir(d)]
        # Bỏ qua thư mục của AI tóm tắt để tránh việc tải nhầm model Spam
        dirs = [d for d in dirs if "my_tiny_summarizer" not in d]
        if dirs:
            return max(dirs, key=os.path.getmtime).replace('\\', '/')
    except Exception:
        pass
    return "outputs/2026-06-08_09-08-52"

LATEST_DIR = get_latest_output_dir("outputs")

@dataclass
class Config:
    training_data_path: str = "data/dataset/dataset.csv"
    validation_data_path: str = "data/dataset/All_mail_Including_Spam_and_Trash.mbox"
    OUTPUT_BASE_DIR: str = "outputs"
    model_path: str = f"{LATEST_DIR}/models/SVM_model.pkl"
    feature_path: str = f"{LATEST_DIR}/models/vectorizer.pkl"

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
