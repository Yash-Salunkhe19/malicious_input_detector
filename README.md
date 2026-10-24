# Hybrid Malicious Input Detection System
> **Using Regular Expressions, Deterministic Finite Automata (DFA), Context-Free Grammar (CFG), and Machine Learning**

---

## 1. Project Overview & DSACT Syllabus Mapping

This project is a hybrid cybersecurity input validation and threat classification system developed in alignment with the **Discrete Structures and Automata Theory (DSACT)** engineering syllabus:

| Unit | Syllabus Domain | Project Implementation & Module |
| :--- | :--- | :--- |
| **Unit III** | **Formal Language Theory & Finite Automata** | **Stage 2: Formal DFA Engine** (`backend/stage2_rule.py`)<br>&bull; Mathematical 5-tuple $M = (Q, \Sigma, \delta, q_0, F)$<br>&bull; Interactive state transition visualizer &amp; step-by-step trace logging<br>&bull; Canonical DFAs for SQL Comments (`--`, `/*...*/`), Script Tags, Traversal (`../`), and Tautologies |
| **Unit IV** | **Regular Expressions & Regular Languages** | **Stage 1: Pre-compiled Rule Catalog** (`backend/stage1_rule.py`)<br>&bull; Compiled regular expressions for SQLi, XSS, Path Traversal, and OS Command Injection<br>&bull; Categorized signature matching with precise boundary anchoring<br>&bull; Interactive Regular Expression Playground with live match spans |
| **Unit V** | **Context-Free Grammar (CFG) & Parsing** | **Stage 3: CFG Lexer & Recursive Descent Parser** (`backend/stage3_cfg.py`)<br>&bull; Formal 4-tuple grammar $G = (V, \Sigma, R, S)$ for SQL statements and injection fragments<br>&bull; Ordered tokenization and syntax derivation logging<br>&bull; Recognizes unauthorized clauses (`UNION SELECT`, boolean tautologies) |
| **Applied ML** | **Statistical Classification & Probability** | **Stage 4: Calibrated Logistic Regression + TF-IDF** (`backend/train_model.py`)<br>&bull; Stratified train/test evaluation (95.98% accuracy, 0.9570 F1, 0.30% False Positive Rate)<br>&bull; Solves the legacy single-character zero-vector misclassification bug |

---

## 2. Multi-Stage Hybrid Architecture

```
[ Incoming User Input / API Query Parameter ]
                     │
                     ▼
       ┌───────────────────────────┐
       │   Stage 1: Regular Expr   │  ──► Detects canonical attack signatures
       └─────────────┬─────────────┘
                     │
                     ▼
       ┌───────────────────────────┐
       │     Stage 2: Formal DFA   │  ──► Formal state machine scan over alphabet Σ
       └─────────────┬─────────────┘
                     │
                     ▼
       ┌───────────────────────────┐
       │     Stage 3: Formal CFG   │  ──► Tokenizes stream & parses grammar derivations
       └─────────────┬─────────────┘
                     │
                     ▼
       ┌───────────────────────────┐
       │    Stage 4: Scikit-Learn  │  ──► Calibrated ML probability & text generalization
       └─────────────┬─────────────┘
                     │
                     ▼
       ┌───────────────────────────┐
       │  Hybrid Explainability    │  ──► Differentiates Deterministic Rule Matches
       │     Decision Engine       │      from ML Statistical Anomalies
       └───────────────────────────┘
```

### Decision Logic:
1. **Deterministic Rule Match (High Risk)**:
   If any formal grammar or automata stage triggers (Regex, DFA, or CFG), the input is verified **Malicious** with high confidence and matched rule references.
2. **ML Statistical Finding (Medium Risk)**:
   If no deterministic rule triggers but the ML model identifies anomalous statistical similarity to malicious payloads, the input is flagged as an **ML Statistical Finding**.
3. **Safe (No Threat Detected)**:
   If all deterministic stages pass and the ML probability is low, the input is marked **Safe**.

---

## 3. Investigation & Resolution of the `'7'` Misclassification Bug

### Root Cause Analysis:
In the legacy implementation:
1. The scikit-learn `TfidfVectorizer` used the default token pattern `r"(?u)\b\w\w+\b"`, which drops all single-character tokens (like `'7'`, `'1'`, `'x'`).
2. Inputs like `'7'` produced an **all-zero feature vector** ($\vec{x} = \mathbf{0}$).
3. In Multinomial Naive Bayes, an all-zero vector provides zero likelihood evidence ($\sum x_i \log p_{ci} = 0$), so the prediction collapses entirely to the **class prior probability**:
   $$\log P(C_1) = \log\left(\frac{77750}{148326}\right) = -0.6459 \quad > \quad \log P(C_0) = \log\left(\frac{70576}{148326}\right) = -0.7427$$
   Because the dataset had slightly more class 1 samples than class 0, **any unseen single character or unknown word was automatically predicted as Malicious**!
4. Furthermore, preprocessing (`clean_text`) was executed in `train_model.py` but was completely missing from `backend/pipeline.py` and `backend/model.py` during runtime inference.

### Resolution:
1. **Shared Preprocessor (`backend/preprocessor.py`)**: Guarantees identical text normalization (case folding, whitespace collapsing, unicode NFKC) between training and inference.
2. **Calibrated Logistic Regression with Class Weights**:
   Linear models learn an explicit bias intercept ($\beta_0 \approx -2.95$). An input with no malicious features evaluates to a negative log-odds ($z \le -2.95$), resulting in $P(\text{Malicious}) \approx 4.8\%$ (**95.2% Normal Confidence**).
3. **Deduplication**: Cleaned queries are deduplicated prior to train-test splitting to eliminate data leakage.

### Benchmark Evaluation Results:

| Metric | MultinomialNB (Baseline) | LogisticRegression (Selected) |
| :--- | :--- | :--- |
| **Accuracy** | 91.79% | **95.98%** |
| **F1-Score (Class 1)** | 0.9107 | **0.9570** |
| **Precision (Class 1)** | 96.84% | **99.65%** |
| **Recall (Class 1)** | 85.95% | **92.06%** |
| **False Positive Rate** | 2.67% (376 FPs) | **0.30% (43 FPs)** |
| **Input `'7'` Output** | Falsely flagged Malicious | **Correctly classified Safe ($P=4.8\%$)** |
| **Input `'hello world'`** | 0.1732 | **0.0232 (Safe)** |
| **Input `'admin\' OR 1=1 --'`**| 0.9868 (Malicious) | **0.8780 (Malicious)** |

*(Full metrics saved in `backend/model_evaluation.json`)*

---

## 4. API Endpoints Reference

The FastAPI backend exposes the following endpoints (interactive OpenAPI docs at `http://127.0.0.1:8000/docs`):

### Core Detection
- `GET /`: Serves the interactive frontend web dashboard.
- `GET /health`: System readiness status and module states.
- `POST /predict`: Main 4-stage hybrid detection endpoint.
  ```json
  // Request
  { "text": "SELECT * FROM users WHERE id = '1' OR '1'='1'" }
  
  // Response
  {
    "input": "...",
    "result": {
      "result": "Malicious",
      "risk_level": "High",
      "finding_type": "Deterministic Rule Match",
      "explanation": "...",
      "stages": { "regex": true, "dfa": true, "cfg": true, "ml": true },
      "stage_details": { ... }
    }
  }
  ```
- `POST /scan-url`: URL component parser and query parameter analyzer.
  ```json
  // Request
  { "url": "https://api.example.com/search?category=books&q=%27%20OR%201%3D1" }
  ```
- `GET /history`: Privacy-preserving scan history from in-memory circular buffer.

### DSACT Syllabus Endpoints
- `GET /syllabus/dfa`: List formal DFA specifications (states $Q$, alphabet $\Sigma$, transition tables $\delta$, start state $q_0$, accept states $F$).
- `POST /syllabus/dfa/trace`: Returns step-by-step state transition log for any string.
- `GET /syllabus/regex`: List pre-compiled regular expression security rules.
- `POST /syllabus/regex/test`: Test custom regular expressions with length and safety guards.
- `GET /syllabus/cfg`: Returns formal Context-Free Grammar productions ($G = (V, \Sigma, R, S)$).
- `POST /syllabus/cfg/parse`: Tokenizes and parses input expressions, outputting formal derivation trees.
- `GET /syllabus/examples`: Curated educational test cases for project defense demonstrations.

---

## 5. Getting Started & Running

### Prerequisites
- Python 3.10+ (tested on Python 3.14)
- Virtual environment with dependencies

### Installation
```powershell
# 1. Activate virtual environment
.venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt
```

### Running the System
You can launch both the backend server and frontend dashboard using the included batch script:
```powershell
.\run.bat
```
Or start manually:
```powershell
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```
- **Web Dashboard**: [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
- **Swagger Documentation**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

### Retraining the Model
To reproduce the ML benchmark evaluation and update serialized models:
```powershell
python -m backend.train_model
```

### Running Automated Tests
Execute the complete automated test suite (37 tests):
```powershell
python -m pytest tests/test_backend.py -v
```

---

## 6. Limitations & Technical Notes

1. **Static Analysis Scope**: Static scanning evaluates syntax and statistical patterns. It does not replace runtime parameterized queries (prepared statements), context-aware output encoding, or database privilege restrictions.
2. **Educational CFG Scope**: The CFG parser models canonical SQL injection clauses and boolean tautologies. It does not implement full ANSI-SQL grammar with nested dialect-specific functions.
3. **ML Scope**: The machine learning model is trained on a representative dataset of web queries and injection attacks; novel zero-day obfuscations are primarily captured by the deterministic rule and automata layers.
