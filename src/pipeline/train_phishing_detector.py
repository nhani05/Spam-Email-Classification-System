import os
import torch
from datasets import load_dataset
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    TrainingArguments,
    Trainer,
)

def main():
    print("=== BẮT ĐẦU QUÁ TRÌNH ETL & TRAINING AI PHÁT HIỆN LỪA ĐẢO ===")
    
    # 1. EXTRACT (Trích xuất dữ liệu)
    print("\n1. Đang tải Dataset Lừa đảo từ HuggingFace...")
    try:
        dataset = load_dataset("phish-eval-vi", split="train")
    except Exception as e:
        print(f"Lỗi tải dataset: {e}")
        print("Gợi ý: Thư viện HuggingFace không tìm thấy bộ 'phish-eval-vi', bạn có thể tự tạo file CSV lừa đảo để train nhé!")
        return
    
    # Chia tập train / test
    dataset = dataset.train_test_split(test_size=0.1)
    
    # 2. TRANSFORM
    print("\n2. Đang chuẩn bị Tokenizer...")
    model_name = "nxtcute/xlm-r-phishing-and-social-engineering-detector-vi"
    tokenizer = AutoTokenizer.from_pretrained(model_name)

    def preprocess_function(examples):
        return tokenizer(examples["text"], truncation=True, max_length=512)

    tokenized_datasets = dataset.map(preprocess_function, batched=True)

    # 3. TRAIN
    print("\n3. Đang khởi tạo mô hình và Huấn luyện...")
    model = AutoModelForSequenceClassification.from_pretrained(model_name, num_labels=2)
    
    output_dir = "outputs/phishing_detector_vi"
    
    training_args = TrainingArguments(
        output_dir=output_dir, eval_strategy="epoch", learning_rate=2e-5,
        per_device_train_batch_size=8, per_device_eval_batch_size=8,
        num_train_epochs=3, fp16=torch.cuda.is_available(),
    )
    
    trainer = Trainer(model=model, args=training_args, train_dataset=tokenized_datasets["train"], eval_dataset=tokenized_datasets["test"], processing_class=tokenizer)
    trainer.train()
    
    print(f"\n4. Hoàn thành! Đang lưu mô hình tại: {output_dir}")
    trainer.save_model(output_dir)

if __name__ == "__main__":
    main()