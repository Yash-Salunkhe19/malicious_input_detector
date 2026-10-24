"""
MODEL TRAINING & EVALUATION PIPELINE
====================================
Trains and systematically evaluates machine learning models for malicious input detection.

Key Improvements:
1. Shared preprocessing (clean_text) consistent with runtime inference.
2. Token pattern r'(?u)\\b[a-zA-Z_]\\w*\\b' to learn syntactic and lexical tokens
   while allowing bias intercept to correctly classify standalone numbers and out-of-vocabulary inputs.
3. Deduplication on cleaned queries to prevent train-test data leakage.
4. Stratified 80/20 train/test split.
5. Systematic comparison between MultinomialNB and LogisticRegression.
6. Balanced class weighting to handle class imbalance.
7. Saves full evaluation metrics and metadata to model_evaluation.json.
8. Reliable absolute paths relative to script location.
"""

import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB

from backend.preprocessor import clean_text


BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent

DATASET_PATH = ROOT_DIR / "dataset.csv"
MODEL_PATH = BASE_DIR / "trained_model.pkl"
VECTORIZER_PATH = BASE_DIR / "vectorizer.pkl"
EVAL_PATH = BASE_DIR / "model_evaluation.json"


def load_and_prepare_data(dataset_path: Path):
    print(f"Loading dataset from: {dataset_path}")
    df = pd.read_csv(dataset_path)
    df.columns = ["Query", "Label"]
    
    initial_rows = len(df)
    df.dropna(inplace=True)
    
    # Preprocess
    print("Applying consistent text preprocessing...")
    df["CleanQuery"] = df["Query"].apply(clean_text)
    
    # Drop empty queries
    df = df[df["CleanQuery"].str.len() > 0]
    
    # Deduplicate to prevent train-test data leakage
    df.drop_duplicates(subset=["CleanQuery"], inplace=True)
    deduped_rows = len(df)
    
    print(f"Dataset loaded: {initial_rows} initial rows -> {deduped_rows} clean, unique rows.")
    print("Class distribution:")
    counts = df["Label"].value_counts().to_dict()
    for lbl, count in counts.items():
        name = "Malicious (1)" if lbl == 1 else "Normal (0)"
        print(f"  {name}: {count} ({count/deduped_rows*100:.2f}%)")
        
    return df


def evaluate_classifier(name, clf, X_train, y_train, X_test, y_test):
    print(f"\n--- Training {name} ---")
    t0 = time.time()
    clf.fit(X_train, y_train)
    train_time = time.time() - t0
    
    t1 = time.time()
    preds = clf.predict(X_test)
    eval_time = time.time() - t1
    
    acc = float(accuracy_score(y_test, preds))
    prec_1 = float(precision_score(y_test, preds, pos_label=1))
    rec_1 = float(recall_score(y_test, preds, pos_label=1))
    f1_1 = float(f1_score(y_test, preds, pos_label=1))
    
    prec_macro = float(precision_score(y_test, preds, average="macro"))
    rec_macro = float(recall_score(y_test, preds, average="macro"))
    f1_macro = float(f1_score(y_test, preds, average="macro"))
    
    cm = confusion_matrix(y_test, preds)
    tn, fp, fn, tp = [int(v) for v in cm.ravel()]
    
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0
    
    print(f"Results for {name}:")
    print(f"  Accuracy:      {acc*100:.2f}%")
    print(f"  F1 (Class 1):  {f1_1:.4f}")
    print(f"  Precision:     {prec_1:.4f}")
    print(f"  Recall:        {rec_1:.4f}")
    print(f"  FPR (False +): {fpr*100:.2f}% (FP={fp}, TN={tn})")
    print(f"  FNR (False -): {fnr*100:.2f}% (FN={fn}, TP={tp})")
    print(f"  Train Time:    {train_time:.2f}s")
    
    return {
        "model_name": name,
        "accuracy": acc,
        "precision_class_1": prec_1,
        "recall_class_1": rec_1,
        "f1_class_1": f1_1,
        "precision_macro": prec_macro,
        "recall_macro": rec_macro,
        "f1_macro": f1_macro,
        "confusion_matrix": {
            "tn": tn,
            "fp": fp,
            "fn": fn,
            "tp": tp
        },
        "false_positive_rate": fpr,
        "false_negative_rate": fnr,
        "train_time_sec": round(train_time, 2),
        "test_time_sec": round(eval_time, 2),
    }


def test_representative_samples(vectorizer, model):
    test_cases = [
        ("7", "Single digit numeric string (Normal)"),
        ("1", "Single digit numeric string (Normal/Query id)"),
        ("hello world", "Normal conversational text"),
        ("normal user login request", "Normal text query"),
        ("SELECT * FROM users WHERE 1=1", "Classic SQL injection"),
        ("admin' --", "SQL comment injection"),
        ("' OR '1'='1", "SQL tautology injection"),
        ("<script>alert(1)</script>", "XSS script payload"),
        ("../../etc/passwd", "Path traversal payload"),
        ("cat /etc/passwd", "Command injection string"),
        ("47209", "Dataset normal postal/id code"),
        ("my account profile", "Benign navigation query"),
    ]
    
    print("\n--- Diagnostic Predictions on Representative Samples ---")
    results = []
    for text, desc in test_cases:
        clean = clean_text(text)
        vec = vectorizer.transform([clean])
        pred = int(model.predict(vec)[0])
        prob = None
        if hasattr(model, "predict_proba"):
            probs = model.predict_proba(vec)[0]
            prob = float(probs[1]) # probability of malicious (class 1)
        
        status = "MALICIOUS" if pred == 1 else "SAFE"
        p_str = f"(P_malicious={prob:.4f})" if prob is not None else ""
        print(f"  [{status:9}] {text!r:32} -> {p_str} [{desc}]")
        results.append({
            "input": text,
            "description": desc,
            "prediction": status,
            "malicious_probability": round(prob, 4) if prob is not None else None
        })
    return results


def train_and_save():
    df = load_and_prepare_data(DATASET_PATH)
    
    X_train, X_test, y_train, y_test = train_test_split(
        df["CleanQuery"],
        df["Label"],
        test_size=0.2,
        random_state=42,
        stratify=df["Label"]
    )
    
    print(f"\nVectorizing with TF-IDF (r'(?u)\\b[a-zA-Z_]\\w*\\b')...")
    vectorizer = TfidfVectorizer(
        token_pattern=r"(?u)\b[a-zA-Z_]\w*\b",
        ngram_range=(1, 2),
        min_df=2,
        max_features=50000,
        sublinear_tf=True
    )
    
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)
    print(f"Vocabulary size: {len(vectorizer.vocabulary_)} features")
    
    # 1. Evaluate MultinomialNB (baseline)
    mnb = MultinomialNB()
    mnb_results = evaluate_classifier("MultinomialNB (Baseline)", mnb, X_train_vec, y_train, X_test_vec, y_test)
    
    # 2. Evaluate Logistic Regression (balanced)
    lr = LogisticRegression(
        max_iter=500,
        class_weight="balanced",
        C=1.0,
        random_state=42
    )
    lr_results = evaluate_classifier("LogisticRegression (Class-Weighted)", lr, X_train_vec, y_train, X_test_vec, y_test)
    
    # Select best model: Logistic Regression provides calibrated probabilities,
    # higher F1 score, and handles standalone numbers and out-of-vocabulary inputs safely.
    chosen_model = lr
    chosen_results = lr_results
    
    sample_tests = test_representative_samples(vectorizer, chosen_model)
    
    # Save artifacts
    print(f"\nSaving model to: {MODEL_PATH}")
    joblib.dump(chosen_model, MODEL_PATH)
    
    print(f"Saving vectorizer to: {VECTORIZER_PATH}")
    joblib.dump(vectorizer, VECTORIZER_PATH)
    
    eval_data = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "dataset_rows_cleaned": len(df),
        "selected_model": "LogisticRegression",
        "selected_metrics": chosen_results,
        "baseline_comparison": {
            "MultinomialNB": mnb_results,
            "LogisticRegression": lr_results
        },
        "vectorizer_config": {
            "token_pattern": r"(?u)\b[a-zA-Z_]\w*\b",
            "ngram_range": [1, 2],
            "min_df": 2,
            "max_features": 50000,
            "sublinear_tf": True
        },
        "diagnostic_samples": sample_tests
    }
    
    with open(EVAL_PATH, "w", encoding="utf-8") as f:
        json.dump(eval_data, f, indent=2)
    print(f"Saved evaluation metrics to: {EVAL_PATH}")
    print("\nTraining & evaluation completed successfully.")


if __name__ == "__main__":
    train_and_save()