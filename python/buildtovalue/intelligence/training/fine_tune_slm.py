"""
Fine-Tune SLM v1.0 — QLoRA fine-tuning pipeline for prompt injection detection (ADR-046).

Produces a GGUF model optimized for the Medium-confidence zone classification.

Usage:
    python -m buildtovalue.intelligence.training.fine_tune_slm \
        --base-model phi-4-mini \
        --dataset-dir data/datasets/prompt_injection \
        --output-dir models/fine-tuned \
        --epochs 3
"""

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger("btv.training.fine_tune")

# Training prompt template — matches MEDIUM_ZONE_PROMPT structure
TRAINING_TEMPLATE = """You are analyzing text that was flagged as MEDIUM confidence by a heuristic prompt injection detector.

Categories:
- benign: False alarm
- prompt_injection: Direct instruction override
- evasion_attempt: Semantic evasion of security controls
- social_engineering: Manipulative deception

Input: {text}

Respond with ONLY a JSON object:"""

EXPECTED_OUTPUT_TEMPLATE = '{{"intent": "{label}", "risk": {risk}, "confidence": {confidence}}}'


def prepare_training_data(
    samples: list,
    output_path: Path,
) -> int:
    """
    Convert TrainingSamples to chat-format JSONL for fine-tuning.

    Format per line:
    {"messages": [{"role": "system", ...}, {"role": "user", ...}, {"role": "assistant", ...}]}
    """
    count = 0
    risk_map = {
        "benign": 0.1,
        "prompt_injection": 0.9,
        "evasion_attempt": 0.85,
        "pii_extraction": 0.7,
        "data_exfiltration": 0.8,
        "social_engineering": 0.75,
    }
    with open(output_path, "w", encoding="utf-8") as f:
        for sample in samples:
            risk = risk_map.get(sample.label, 0.5) if hasattr(sample, 'label') else risk_map.get(sample.get("label", ""), 0.5)
            label = sample.label if hasattr(sample, 'label') else sample.get("label", "unknown")
            text = sample.text if hasattr(sample, 'text') else sample.get("text", "")
            confidence = sample.confidence if hasattr(sample, 'confidence') else sample.get("confidence", 0.8)

            messages = {
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a security classifier specializing in semantic evasion detection. Respond with valid JSON only.",
                    },
                    {
                        "role": "user",
                        "content": TRAINING_TEMPLATE.format(text=text),
                    },
                    {
                        "role": "assistant",
                        "content": EXPECTED_OUTPUT_TEMPLATE.format(
                            label=label,
                            risk=risk,
                            confidence=confidence,
                        ),
                    },
                ]
            }
            f.write(json.dumps(messages, ensure_ascii=False) + "\n")
            count += 1

    logger.info("Prepared %d training samples at %s", count, output_path)
    return count


def run_fine_tune(
    base_model: str,
    training_data: Path,
    output_dir: Path,
    epochs: int = 3,
    lora_r: int = 16,
    lora_alpha: int = 32,
    learning_rate: float = 2e-4,
    batch_size: int = 4,
) -> Optional[Path]:
    """
    Run QLoRA fine-tuning on the base model.

    Requires: transformers, peft, trl, bitsandbytes, datasets.
    These are NOT runtime dependencies — only needed for training.

    Returns path to output model directory, or None on failure.
    """
    try:
        from datasets import load_dataset
        from peft import LoraConfig, get_peft_model
        from transformers import (
            AutoModelForCausalLM,
            AutoTokenizer,
            BitsAndBytesConfig,
            TrainingArguments,
        )
        from trl import SFTTrainer
    except ImportError as e:
        logger.error(
            "Fine-tuning dependencies not installed. "
            "Install with: pip install transformers peft trl bitsandbytes datasets. "
            "Error: %s", e,
        )
        return None

    output_dir.mkdir(parents=True, exist_ok=True)

    logger.info("Loading base model: %s", base_model)

    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_use_double_quant=True,
    )

    tokenizer = AutoTokenizer.from_pretrained(base_model)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    model = AutoModelForCausalLM.from_pretrained(
        base_model,
        quantization_config=bnb_config,
        device_map="auto",
    )

    lora_config = LoraConfig(
        r=lora_r,
        lora_alpha=lora_alpha,
        target_modules=["q_proj", "v_proj", "k_proj", "o_proj"],
        lora_dropout=0.05,
        bias="none",
        task_type="CAUSAL_LM",
    )

    model = get_peft_model(model, lora_config)
    logger.info("Trainable params: %d", model.num_parameters(only_trainable=True))

    dataset = load_dataset("json", data_files=str(training_data), split="train")

    training_args = TrainingArguments(
        output_dir=str(output_dir),
        num_train_epochs=epochs,
        per_device_train_batch_size=batch_size,
        learning_rate=learning_rate,
        warmup_ratio=0.1,
        logging_steps=10,
        save_strategy="epoch",
        fp16=True,
        report_to="none",
    )

    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        args=training_args,
        train_dataset=dataset,
    )

    logger.info("Starting fine-tuning for %d epochs...", epochs)
    trainer.train()

    final_path = output_dir / "final"
    model.save_pretrained(str(final_path))
    tokenizer.save_pretrained(str(final_path))
    logger.info("Model saved to %s", final_path)

    return final_path


def main() -> None:
    """CLI entry point for fine-tuning."""
    logging.basicConfig(level=logging.INFO, format="%(name)s %(levelname)s %(message)s")

    parser = argparse.ArgumentParser(description="Fine-tune SLM for prompt injection detection")
    parser.add_argument("--base-model", default="microsoft/phi-4-mini", help="Base model name/path")
    parser.add_argument("--dataset-dir", default="data/datasets/prompt_injection", help="Dataset directory")
    parser.add_argument("--output-dir", default="models/fine-tuned", help="Output directory")
    parser.add_argument("--epochs", type=int, default=3, help="Training epochs")
    parser.add_argument("--lr", type=float, default=2e-4, help="Learning rate")
    parser.add_argument("--batch-size", type=int, default=4, help="Batch size")
    args = parser.parse_args()

    from .dataset_loader import DatasetLoader

    loader = DatasetLoader(args.dataset_dir)
    samples = loader.load_all()
    if not samples:
        logger.error("No training samples found in %s", args.dataset_dir)
        sys.exit(1)

    dist = loader.label_distribution(samples)
    logger.info("Label distribution: %s", dist)
    logger.info("Total samples: %d", len(samples))

    output = Path(args.output_dir)
    training_file = output / "training_data.jsonl"
    output.mkdir(parents=True, exist_ok=True)

    prepare_training_data(samples, training_file)
    run_fine_tune(
        base_model=args.base_model,
        training_data=training_file,
        output_dir=output,
        epochs=args.epochs,
        learning_rate=args.lr,
        batch_size=args.batch_size,
    )


if __name__ == "__main__":
    main()
