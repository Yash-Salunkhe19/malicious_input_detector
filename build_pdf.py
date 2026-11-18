"""
Generates publication-quality PDF documentation for Malicious Input Detector
using Microsoft Edge headless renderer.
"""

import os
import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
HTML_PATH = BASE_DIR / "documentation_print.html"
PDF_PATH = BASE_DIR / "Malicious_Input_Detector_Documentation.pdf"

EDGE_PATH = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
if not os.path.exists(EDGE_PATH):
    EDGE_PATH = r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"

html_content = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Malicious Input Detector - Complete Documentation</title>
<style>
  @page {
    size: A4 portrait;
    margin: 18mm 16mm 20mm 16mm;
    @bottom-right {
      content: "Page " counter(page) " of " counter(pages);
      font-family: 'Segoe UI', sans-serif;
      font-size: 8pt;
      color: #64748b;
    }
  }

  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    color: #1e293b;
    line-height: 1.55;
    font-size: 10pt;
    margin: 0;
    padding: 0;
    background: #ffffff;
  }

  .cover-card {
    background: linear-gradient(135deg, #0b0f19 0%, #172033 100%);
    color: #ffffff;
    border-radius: 12px;
    padding: 28px 32px;
    margin-bottom: 24px;
    border-left: 6px solid #f97316;
  }

  .badge-tag {
    display: inline-block;
    background: rgba(249, 115, 22, 0.2);
    border: 1px solid #f97316;
    color: #fdba74;
    padding: 3px 10px;
    border-radius: 9999px;
    font-size: 8pt;
    font-weight: 600;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    margin-bottom: 12px;
  }

  h1.project-title {
    font-size: 22pt;
    margin: 0 0 8px 0;
    font-weight: 800;
    letter-spacing: -0.02em;
    color: #ffffff;
  }

  p.project-subtitle {
    font-size: 11pt;
    color: #cbd5e1;
    margin: 0 0 16px 0;
    max-width: 650px;
  }

  .meta-grid {
    display: flex;
    gap: 24px;
    border-top: 1px solid rgba(255, 255, 255, 0.15);
    padding-top: 14px;
    font-size: 8.5pt;
    color: #94a3b8;
  }

  .meta-grid strong {
    color: #f1f5f9;
  }

  h2 {
    font-size: 14pt;
    color: #0f172a;
    border-bottom: 2px solid #e2e8f0;
    padding-bottom: 6px;
    margin-top: 24px;
    margin-bottom: 12px;
    page-break-after: avoid;
    display: flex;
    align-items: center;
    gap: 8px;
  }

  h2 .num {
    background: #ea580c;
    color: #ffffff;
    font-size: 9.5pt;
    font-weight: bold;
    width: 22px;
    height: 22px;
    border-radius: 6px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
  }

  h3 {
    font-size: 11.5pt;
    color: #1e293b;
    margin-top: 18px;
    margin-bottom: 8px;
    page-break-after: avoid;
  }

  p {
    margin-top: 0;
    margin-bottom: 10px;
    text-align: justify;
  }

  table {
    width: 100%;
    border-collapse: collapse;
    margin: 12px 0 16px 0;
    font-size: 9pt;
    page-break-inside: avoid;
  }

  th {
    background: #0f172a;
    color: #ffffff;
    font-weight: 600;
    text-align: left;
    padding: 8px 10px;
    border: 1px solid #0f172a;
  }

  td {
    padding: 7px 10px;
    border: 1px solid #cbd5e1;
    vertical-align: top;
  }

  tr:nth-child(even) td {
    background: #f8fafc;
  }

  .formula-card {
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-left: 4px solid #ea580c;
    border-radius: 6px;
    padding: 10px 14px;
    margin: 12px 0;
    font-family: 'Cambria Math', 'Times New Roman', serif;
    font-size: 10pt;
    page-break-inside: avoid;
  }

  .formula-card .title {
    font-family: -apple-system, BlinkMacSystemFont, sans-serif;
    font-size: 8.5pt;
    font-weight: 700;
    color: #ea580c;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: 4px;
  }

  .formula-math {
    font-size: 11pt;
    color: #0f172a;
    line-height: 1.6;
    margin: 4px 0;
  }

  code, pre {
    font-family: 'Courier New', Courier, monospace;
    font-size: 8.5pt;
  }

  pre {
    background: #0b0f19;
    color: #e2e8f0;
    padding: 10px 14px;
    border-radius: 6px;
    overflow-x: hidden;
    white-space: pre-wrap;
    border: 1px solid #334155;
    margin: 10px 0;
    page-break-inside: avoid;
  }

  .inline-code {
    background: #f1f5f9;
    color: #ea580c;
    padding: 2px 5px;
    border-radius: 4px;
    border: 1px solid #e2e8f0;
    font-size: 8.5pt;
  }

  .stat-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 10px;
    margin: 14px 0;
    page-break-inside: avoid;
  }

  .stat-box {
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-top: 3px solid #ea580c;
    border-radius: 6px;
    padding: 10px;
    text-align: center;
  }

  .stat-box .val {
    font-size: 16pt;
    font-weight: 800;
    color: #0f172a;
    line-height: 1.1;
  }

  .stat-box .lbl {
    font-size: 7.5pt;
    text-transform: uppercase;
    color: #64748b;
    font-weight: 600;
    margin-top: 4px;
  }

  .callout-box {
    background: #eff6ff;
    border-left: 4px solid #3b82f6;
    border-radius: 4px;
    padding: 10px 14px;
    margin: 12px 0;
    font-size: 9pt;
    color: #1e3a8a;
    page-break-inside: avoid;
  }

  .callout-box strong {
    color: #1d4ed8;
  }

  .success-box {
    background: #ecfdf5;
    border-left: 4px solid #10b981;
    border-radius: 4px;
    padding: 10px 14px;
    margin: 12px 0;
    font-size: 9pt;
    color: #064e3b;
    page-break-inside: avoid;
  }

  .page-break {
    page-break-before: always;
  }
</style>
</head>
<body>

<div class="cover-card">
  <div class="badge-tag">Academic & Technical Reference Document</div>
  <h1 class="project-title">Malicious Input Detector</h1>
  <p class="project-subtitle">
    An Explainable Web Injection Defense System Integrating Discrete Structures & Automata Theory (DSACT) with Statistical Machine Learning.
  </p>
  <div class="meta-grid">
    <div><strong>Domain:</strong> Web Application Security / Cyber Defense</div>
    <div><strong>Theoretical Basis:</strong> Chomsky Hierarchy (Type 3 & Type 2)</div>
    <div><strong>Inference Engine:</strong> TF-IDF + Calibrated Logistic Regression</div>
    <div><strong>Accuracy:</strong> 95.98% (27,487 Held-Out Samples)</div>
  </div>
</div>

<h2><span class="num">1</span> Project Overview & Problem Formulation</h2>
<p>
  Web injection attacks remain the primary attack vector against enterprise software applications (OWASP Top 10: Injection). Attackers embed control syntax inside legitimate application inputs (forms, API parameters, headers, and query strings) to subvert downstream parsers:
</p>
<ul>
  <li><strong>SQL Injection (SQLi):</strong> Manipulates database query semantics through boolean tautologies (<code>' OR 1=1 --</code>), union projections, and syntax terminations.</li>
  <li><strong>Cross-Site Scripting (XSS):</strong> Embeds executable client-side JavaScript (<code>&lt;script&gt;</code>, <code>onerror=</code>) executed in victim user sessions.</li>
  <li><strong>Path Traversal / Local File Inclusion:</strong> Employs directory escape markers (<code>../</code> or <code>..\\</code>) to read sensitive system configuration files.</li>
  <li><strong>OS Command Chaining:</strong> Exploits shell metacharacters (<code>;</code>, <code>|</code>, <code>&amp;&amp;</code>) to spawn unauthorized operating system commands.</li>
</ul>

<div class="callout-box">
  <strong>The Academic Dilemma Solved by this Project:</strong>
  Pure black-box Machine Learning classifiers suffer from lack of interpretability and false positives on out-of-vocabulary inputs (such as harmless single digits like <code>7</code>). Pure rule-based firewalls (WAFs) fail to generalize to novel variations. This project introduces a <strong>4-stage hybrid architecture</strong> delivering deterministic mathematical proofs for known syntax violations alongside calibrated statistical generalization.
</div>

<h2><span class="num">2</span> Discrete Structures & Automata Foundations</h2>
<p>
  The architecture rigorously maps to the <strong>Chomsky Hierarchy of Formal Languages</strong>:
</p>

<table>
  <thead>
    <tr>
      <th>Chomsky Language Type</th>
      <th>Theoretical Automaton</th>
      <th>Project Pipeline Stage</th>
      <th>Algorithmic Function</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Type 3: Regular Language</strong></td>
      <td>Deterministic Finite Automaton (DFA) / Kleene Regex</td>
      <td><strong>Stage 1:</strong> Regex Rules<br><strong>Stage 2:</strong> Formal DFA State Machines</td>
      <td>Linear-time $O(N)$ string matching for exact lexical patterns and attack tokens.</td>
    </tr>
    <tr>
      <td><strong>Type 2: Context-Free Language</strong></td>
      <td>Pushdown Automaton (PDA) / Recursive Grammar Parser</td>
      <td><strong>Stage 3:</strong> Context-Free Grammar (CFG)</td>
      <td>Parses nested boolean conditions, clauses, and recursive query injection structures.</td>
    </tr>
    <tr>
      <td><strong>Statistical Language Model</strong></td>
      <td>Vector Space Model + Hyperplane Classifier</td>
      <td><strong>Stage 4:</strong> TF-IDF + Logistic Regression</td>
      <td>Computes n-gram probabilities to catch novel zero-day payload variations.</td>
    </tr>
  </tbody>
</table>

<h2><span class="num">3</span> Stage-by-Stage Mathematical Formulations</h2>

<h3>Stage 1: Regular Expressions & Pattern Languages (Chomsky Type 3)</h3>
<p>
  A regular language $L(R)$ over alphabet $\Sigma$ is closed under concatenation ($L_1 L_2$), union ($L_1 \cup L_2$), and Kleene star closure ($L^* = \bigcup_{i=0}^\infty L^i$). The engine utilizes boundary-anchored regular expressions to eliminate false positives on common English text:
</p>
<div class="formula-card">
  <div class="title">Representative Regex Definitions (backend/stage1_rule.py)</div>
  <div class="formula-math">
    <strong>SQLi Tautology:</strong> <code>(?i)(?:'|")?\s*\bOR\b\s+(?:(?:\d+\s*=\s*\d+)|(?:'[^']*'\s*=\s*'[^']*'))</code><br>
    <strong>XSS Script Tag:</strong> <code>(?i)&lt;\s*script\b[^&gt;]*&gt;(.*?)&lt;\s*/\s*script\s*&gt;|&lt;\s*script\b[^&gt;]*&gt;</code><br>
    <strong>Path Traversal:</strong> <code>(?:\.\.[/\\])+</code>
  </div>
</div>

<h3>Stage 2: Deterministic Finite Automata (DFA)</h3>
<p>
  Formally, each DFA is defined as a 5-tuple $M = (Q, \Sigma, \delta, q_0, F)$ where $Q$ is the finite state set, $\Sigma$ is the alphabet, $\delta: Q \times \Sigma \to Q$ is the transition function, $q_0$ is the start state, and $F \subseteq Q$ is the set of accepting states.
</p>
<div class="formula-card">
  <div class="title">Formal DFA State Transition Formula</div>
  <div class="formula-math">
    Extended transition function $\hat{\delta}: Q \times \Sigma^* \to Q$ defined inductively:<br>
    $\hat{\delta}(q, \epsilon) = q$<br>
    $\hat{\delta}(q, wa) = \delta(\hat{\delta}(q, w), a) \quad \text{for } w \in \Sigma^*, a \in \Sigma$<br>
    Language Accepted: $L(M) = \{ w \in \Sigma^* \mid \hat{\delta}(q_0, w) \in F \}$
  </div>
</div>
<p>Four canonical automata are implemented in <code>backend/stage2_rule.py</code>:</p>
<ol>
  <li><strong>SQL Comment Automaton (<code>DFA_SQL_COMMENT</code>):</strong> Detects <code>--</code> and <code>/*...*/</code>. Transitions: $\delta(q_0, '-') = q_{\text{dash1}}$, $\delta(q_{\text{dash1}}, '-') = q_{\text{accept}}$ (Absorbing).</li>
  <li><strong>XSS Script Automaton (<code>DFA_SCRIPT_TAG</code>):</strong> Recognizes opening sequence <code>&lt;</code> $\to$ <code>s</code> $\to$ <code>c</code> $\to$ <code>r</code> $\to$ <code>i</code> $\to$ <code>p</code> $\to$ <code>t</code>.</li>
  <li><strong>Path Traversal Automaton (<code>DFA_PATH_TRAVERSAL</code>):</strong> Recognizes <code>.</code> $\to$ <code>.</code> $\to$ <code>/</code> or <code>\</code>.</li>
  <li><strong>SQL OR-Tautology Automaton (<code>DFA_SQL_OR</code>):</strong> Evaluates injection transitions into equality states.</li>
</ol>

<div class="page-break"></div>

<h3>Stage 3: Context-Free Grammar (CFG) Parsing (Chomsky Type 2)</h3>
<p>
  Formally defined as a 4-tuple $G = (V, \Sigma, R, S)$ where $V$ represents syntactic variables, $\Sigma$ represents terminals, $R$ is production rules ($A \to \alpha$), and $S$ is the start symbol. Implemented via recursive descent in <code>backend/stage3_cfg.py</code>:
</p>
<pre>
S                ::= STATEMENT | INJECTION_CLAUSE
STATEMENT        ::= SELECT_STMT | UNION_STMT
SELECT_STMT      ::= "SELECT" PROJECTION "FROM" TABLE [ WHERE_CLAUSE ]
UNION_STMT       ::= "UNION" [ "ALL" ] SELECT_STMT
INJECTION_CLAUSE ::= TAUTOLOGY | UNION_STMT | STACKED_STMT
TAUTOLOGY        ::= "OR" BOOL_EXPR | "AND" BOOL_EXPR
BOOL_EXPR        ::= LITERAL OP LITERAL
WHERE_CLAUSE     ::= "WHERE" CONDITION
CONDITION        ::= BOOL_EXPR | IDENT OP LITERAL | CONDITION LOGICAL_OP CONDITION
STACKED_STMT     ::= ";" ( "DROP" | "DELETE" | "UPDATE" | "INSERT" ) IDENT
</pre>

<h3>Stage 4: Machine Learning & Statistical NLP</h3>
<p>
  Uses a shared canonical preprocessor (NFKC unicode normalization, whitespace collapsing) combined with word and character n-gram TF-IDF vectorization:
</p>

<div class="formula-card">
  <div class="title">Sublinear TF-IDF & Logistic Regression Formulas</div>
  <div class="formula-math">
    <strong>Sublinear Term Frequency:</strong><br>
    $\text{TF}(t, d) = \begin{cases} 1 + \ln(\text{count}(t, d)) & \text{if } \text{count}(t, d) > 0 \\ 0 & \text{otherwise} \end{cases}$<br><br>
    <strong>Smoothed Inverse Document Frequency:</strong><br>
    $\text{IDF}(t) = \ln\left(\frac{1 + N}{1 + \text{DF}(t)}\right) + 1 \quad (N = 137,434)$<br><br>
    <strong>Linear Logit & Sigmoid Posterior Probability:</strong><br>
    $z = w^T x + b = \sum_{j=1}^m w_j x_j + b$<br>
    $P(Y = \text{Malicious} \mid x) = \sigma(z) = \frac{1}{1 + e^{-z}}$
  </div>
</div>

<div class="success-box">
  <strong>Proof: Standalone Numbers (e.g. <code>7</code>) are Mathematically Guaranteed Safe</strong><br>
  The token pattern <code>r'(?u)\b[a-zA-Z_]\w*\b'</code> extracts 0 alphanumeric tokens for input <code>"7"</code>. The feature vector evaluates to zero ($x = \mathbf{0}$). Thus:
  $$z = w^T \mathbf{0} + b = b \approx -2.66$$
  $$P(\text{Malicious} \mid x = \mathbf{0}) = \frac{1}{1 + e^{2.66}} \approx 0.065 \ (6.5\%) < 50\% \implies \mathbf{SAFE} \ (93.5\% \text{ normal confidence})$$
</div>

<h2><span class="num">4</span> Hybrid Decision Logic & Arbitration Formula</h2>
<p>
  The pipeline coordinates deterministic rule execution with probabilistic learning using a priority arbitration policy:
</p>
<div class="formula-card">
  <div class="title">Pipeline Arbitration Equation</div>
  <div class="formula-math">
    $\text{DeterministicMatch}(x) = S_1(x) \lor S_2(x) \lor S_3(x)$<br><br>
    $\text{Verdict}(x) = \begin{cases}
    \mathbf{MALICIOUS} \text{ (High Risk)}, & \text{if } \text{DeterministicMatch}(x) = \text{True} \\
    \mathbf{MALICIOUS} \text{ (Statistical Anomaly)}, & \text{if } \neg\text{DeterministicMatch}(x) \land P_{\text{ML}}(\text{Malicious} \mid x) > 0.50 \\
    \mathbf{SAFE} \text{ (Clean)}, & \text{otherwise}
    \end{cases}$
  </div>
</div>

<h2><span class="num">5</span> Empirical Evaluation & Model Metrics</h2>
<p>
  Evaluated on <strong>27,487 held-out validation samples</strong> from a balanced corpus of <strong>137,434 queries</strong>:
</p>

<div class="stat-grid">
  <div class="stat-box">
    <div class="val">95.98%</div>
    <div class="lbl">Accuracy</div>
  </div>
  <div class="stat-box">
    <div class="val">99.65%</div>
    <div class="lbl">Attack Precision</div>
  </div>
  <div class="stat-box">
    <div class="val">92.06%</div>
    <div class="lbl">Attack Recall</div>
  </div>
  <div class="stat-box">
    <div class="val">0.30%</div>
    <div class="lbl">False Positive Rate</div>
  </div>
</div>

<table>
  <thead>
    <tr>
      <th>Metric</th>
      <th>Formula</th>
      <th>Logistic Regression (Selected)</th>
      <th>MultinomialNB (Baseline)</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Accuracy</strong></td>
      <td>$(TP + TN) / (TP + TN + FP + FN)$</td>
      <td><strong>95.98%</strong></td>
      <td>91.79%</td>
    </tr>
    <tr>
      <td><strong>Precision (Malicious)</strong></td>
      <td>$TP / (TP + FP)$</td>
      <td><strong>99.65%</strong></td>
      <td>96.84%</td>
    </tr>
    <tr>
      <td><strong>Recall (Malicious)</strong></td>
      <td>$TP / (TP + FN)$</td>
      <td><strong>92.06%</strong></td>
      <td>85.95%</td>
    </tr>
    <tr>
      <td><strong>F1-Score</strong></td>
      <td>$2 \times (P \times R) / (P + R)$</td>
      <td><strong>95.70%</strong></td>
      <td>91.07%</td>
    </tr>
    <tr>
      <td><strong>False Positive Rate (FPR)</strong></td>
      <td>$FP / (FP + TN)$</td>
      <td><strong>0.30%</strong></td>
      <td>2.67%</td>
    </tr>
    <tr>
      <td><strong>Inference Time</strong></td>
      <td>Wall-clock latency per scan</td>
      <td><strong>&lt; 15 ms</strong></td>
      <td>&lt; 20 ms</td>
    </tr>
  </tbody>
</table>

<div class="formula-card">
  <div class="title">Test Partition Confusion Matrix (N = 27,487 queries)</div>
  <div class="formula-math">
    True Negatives ($TN$): <strong>14,060</strong> &nbsp;|&nbsp; False Positives ($FP$): <strong>43</strong><br>
    False Negatives ($FN$): <strong>1,063</strong> &nbsp;|&nbsp; True Positives ($TP$): <strong>12,321</strong>
  </div>
</div>

<h2><span class="num">6</span> System Architecture & Security Posture</h2>
<p>
  The system is organized into modular tiers ensuring enterprise security and academic clarity:
</p>
<ul>
  <li><strong>FastAPI Core (<code>backend/main.py</code>):</strong> RESTful API exposing <code>/scan</code>, <code>/scan-api</code>, <code>/overview/stats</code>, <code>/history</code>, and <code>/ml/metrics</code>.</li>
  <li><strong>SQLite Persistence (<code>backend/database.py</code>):</strong> Stores scanning telemetry locally in <code>detection_history.db</code> with indexed timestamps and outcomes.</li>
  <li><strong>Static Safety Guarantee:</strong> Pure lexical and structural inspection. No external network connections or database executions are dispatched, eliminating SSRF or execution risks.</li>
  <li><strong>Cybersecurity SaaS Interface (<code>frontend/frontend.html</code>):</strong> Responsive dashboard with interactive DFA playback, token oscilloscope, and rule explainability cards.</li>
</ul>

</body>
</html>
"""

HTML_PATH.write_text(html_content, encoding="utf-8")
print(f"Wrote printable HTML to: {HTML_PATH}")

cmd = [
    EDGE_PATH,
    "--headless",
    "--disable-gpu",
    "--no-pdf-header-footer",
    f"--print-to-pdf={PDF_PATH}",
    str(HTML_PATH)
]

print("Rendering PDF with Microsoft Edge headless...")
res = subprocess.run(cmd, capture_output=True, text=True)
if res.returncode == 0 and PDF_PATH.exists():
    print(f"SUCCESS: PDF generated successfully at: {PDF_PATH} ({PDF_PATH.stat().st_size} bytes)")
else:
    print(f"FAILED: {res.stderr}")
