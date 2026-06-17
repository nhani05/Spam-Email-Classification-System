import os
import torch
from datasets import load_dataset
import sys

from transformers import (
    AutoTokenizer,
    AutoModelForSeq2SeqLM,
    Seq2SeqTrainingArguments,
    Seq2SeqTrainer,
    DataCollatorForSeq2Seq
)

# --- VÁ LỖI THƯ VIỆN TRANSFORMERS MỚI NHẤT ---
import transformers.models.t5.tokenization_t5 as t5_tok
if hasattr(t5_tok, "Unigram"):
    orig_unigram = t5_tok.Unigram
    def patched_unigram(vocab, *args, **kwargs):
        if isinstance(vocab, dict):
            vocab = list(vocab.items())
        return orig_unigram(vocab, *args, **kwargs)
    t5_tok.Unigram = patched_unigram
# ---------------------------------------------

def main():
    print("=== BẮT ĐẦU QUÁ TRÌNH ETL & TRAINING AI TÓM TẮT ===")
    
    # 1. EXTRACT (Trích xuất dữ liệu)
    # Dùng tập dữ liệu VietNews. Giới hạn 5000 bài để cân bằng giữa chất lượng và thời gian train.
    print("\n1. Đang tải Dataset Tiếng Việt từ HuggingFace (Extract)...")
    dataset = load_dataset("nam194/vietnews", split="train[:5000]")
    
    # Chia tập train / test (90% để học, 10% để thi)
    dataset = dataset.train_test_split(test_size=0.1)
    print(f" - Số lượng mẫu học (Train): {len(dataset['train'])}")
    print(f" - Số lượng mẫu kiểm tra (Test): {len(dataset['test'])}")
    
    # 2. TRANSFORM (Biến đổi & Tiền xử lý)
    print("\n2. Đang chuẩn bị Tokenizer và biến đổi dữ liệu (Transform)...")
    # Dùng mô hình nền ViT5 (phiên bản gốc chưa biết tóm tắt) để dạy từ đầu
    model_name = "VietAI/vit5-base" 
    tokenizer = AutoTokenizer.from_pretrained(model_name, use_fast=False, legacy=True)
    
    # Mô hình ViT5 yêu cầu có từ khóa "vietnews: " ở đầu
    prefix = "vietnews: "

    def preprocess_function(examples):
        # Cột văn bản gốc trong VietNews tên là 'article'
        inputs = [prefix + str(doc) for doc in examples["article"]]
        model_inputs = tokenizer(inputs, max_length=512, truncation=True)

        # Cột tóm tắt trong VietNews tên là 'abstract'
        labels = tokenizer(text_target=[str(doc) for doc in examples["abstract"]], max_length=128, truncation=True)
        model_inputs["labels"] = labels["input_ids"]
        return model_inputs

    # Áp dụng hàm Transform cho toàn bộ dataset
    tokenized_datasets = dataset.map(preprocess_function, batched=True)
    
    # 3. LOAD / TRAIN (Huấn luyện)
    print("\n3. Đang khởi tạo mô hình AI và bắt đầu Huấn luyện (Train)...")
    model = AutoModelForSeq2SeqLM.from_pretrained(model_name)
    
    output_dir = "outputs/email_summarizer_vi"
    
    training_args = Seq2SeqTrainingArguments(
        output_dir=output_dir,
        eval_strategy="epoch",        # Đánh giá sau mỗi epoch (vòng học)
        learning_rate=2e-5,           # Tốc độ học
        per_device_train_batch_size=2,# Số mẫu học cùng lúc (Giảm để tránh tràn RAM với model to)
        per_device_eval_batch_size=2,
        weight_decay=0.01,
        save_total_limit=2,
        num_train_epochs=1,           # Chạy 1 vòng để demo (Tăng lên 3-5 nếu muốn xịn hơn)
        predict_with_generate=True,
        fp16=torch.cuda.is_available(), # Tự động kích hoạt GPU nếu máy có Card đồ họa
        logging_steps=10,
    )
    
    data_collator = DataCollatorForSeq2Seq(tokenizer=tokenizer, model=model)
    
    trainer = Seq2SeqTrainer(
        model=model,
        args=training_args,
        train_dataset=tokenized_datasets["train"],
        eval_dataset=tokenized_datasets["test"],
        processing_class=tokenizer,
        data_collator=data_collator,
    )
    
    print("Đang tiến hành chạy thuật toán (Cần vài phút đến vài chục phút tùy cấu hình máy)...")
    trainer.train()
    
    # 4. LƯU MÔ HÌNH
    print(f"\n4. Hoàn thành! Đang lưu mô hình của riêng bạn tại: {output_dir}")
    trainer.save_model(output_dir)
    tokenizer.save_pretrained(output_dir)
    
    print("\n🎉 CHÚC MỪNG! BẠN ĐÃ TỰ TRAIN THÀNH CÔNG MỘT MÔ HÌNH AI CHO RIÊNG MÌNH!")

if __name__ == "__main__":
    main()
