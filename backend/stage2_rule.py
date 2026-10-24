"""
STAGE 2 - DETERMINISTIC FINITE AUTOMATA (DFA) DETECTION
======================================================
Discrete Structures concept:
Finite Automata and Formal Languages (Unit III)

A Deterministic Finite Automaton (DFA) is formally defined as a 5-tuple:
    M = (Q, Σ, δ, q0, F)
where:
    - Q  : Finite set of states
    - Σ  : Finite input alphabet
    - δ  : Transition function (δ: Q × Σ → Q)
    - q0 : Initial state (q0 ∈ Q)
    - F  : Set of accepting / final states (F ⊆ Q)

This module implements:
1. Formal DFA execution engine with transition tracking and full execution trace.
2. Canonical DFAs for malicious sub-languages:
    - DFA_SQL_COMMENT: Recognizes SQL comment sequences ('--' and '/*...*/')
    - DFA_SCRIPT_TAG: Recognizes HTML '<script' tag opening
    - DFA_PATH_TRAVERSAL: Recognizes directory traversal sequences ('../' and '..\\')
    - DFA_SQL_TAUTOLOGY: Recognizes SQL quote-or-tautology structures
"""

from typing import Dict, List, Any, Optional, Set, Tuple


class FormalDFA:
    """
    Formal Deterministic Finite Automaton (Q, Σ, δ, q0, F).
    """

    def __init__(
        self,
        name: str,
        category: str,
        description: str,
        states: List[str],
        alphabet_description: str,
        start_state: str,
        accept_states: List[str],
        transitions: Dict[str, Dict[str, str]],
        default_transition: Optional[str] = None
    ):
        self.name = name
        self.category = category
        self.description = description
        self.states = states
        self.alphabet_description = alphabet_description
        self.start_state = start_state
        self.accept_states = set(accept_states)
        self.transitions = transitions
        self.default_transition = default_transition

    def step(self, current_state: str, char: str) -> str:
        """
        Compute δ(current_state, char).
        Case-insensitive matching for alphabetical transitions.
        """
        state_rules = self.transitions.get(current_state, {})
        
        # Exact character match
        if char in state_rules:
            return state_rules[char]
        
        # Lowercase match
        lower_char = char.lower()
        if lower_char in state_rules:
            return state_rules[lower_char]
            
        # Class matches
        if char.isdigit() and "[digit]" in state_rules:
            return state_rules["[digit]"]
        if char.isalpha() and "[alpha]" in state_rules:
            return state_rules["[alpha]"]
        if char.isspace() and "[space]" in state_rules:
            return state_rules["[space]"]
        if "[any]" in state_rules:
            return state_rules["[any]"]

        # Default fallback (loop or reset)
        return self.default_transition if self.default_transition is not None else self.start_state

    def scan(self, text: str) -> Dict[str, Any]:
        """
        Run the DFA across the input string in scanning mode.
        Returns whether an accepting state was reached, along with the full state trace.
        """
        current_state = self.start_state
        trace: List[Dict[str, Any]] = [
            {
                "step": 0,
                "input_char": None,
                "from_state": None,
                "to_state": current_state,
                "is_accepting": current_state in self.accept_states
            }
        ]

        accepted = False
        accepting_step = None
        matched_subseq = ""

        for idx, ch in enumerate(text):
            next_state = self.step(current_state, ch)
            is_acc = next_state in self.accept_states
            
            trace.append({
                "step": idx + 1,
                "input_char": ch,
                "from_state": current_state,
                "to_state": next_state,
                "is_accepting": is_acc
            })

            current_state = next_state
            
            if is_acc and not accepted:
                accepted = True
                accepting_step = idx + 1

        return {
            "accepted": accepted,
            "dfa_name": self.name,
            "category": self.category,
            "description": self.description,
            "final_state": current_state,
            "accepting_step": accepting_step,
            "trace_summary": trace[:50],  # first 50 steps for inspection
            "total_steps": len(trace) - 1
        }

    def to_dict(self) -> Dict[str, Any]:
        """Export DFA formal specification for UI visualization."""
        return {
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "states": self.states,
            "start_state": self.start_state,
            "accept_states": list(self.accept_states),
            "alphabet": self.alphabet_description,
            "transitions": self.transitions
        }


# ====================================================================
# CANONICAL DFA DEFINITIONS
# ====================================================================

# 1. SQL Line & Block Comment DFA
# Detects `--` or `/* ... */`
DFA_SQL_COMMENT = FormalDFA(
    name="SQL Comment DFA",
    category="SQL Injection",
    description="Recognizes SQL comment syntax (-- or /*...*/) used to truncate query logic.",
    states=["q0", "q_dash1", "q_accept_dash", "q_slash", "q_in_comment", "q_star", "q_accept_block"],
    alphabet_description="{ '-', '/', '*', whitespace, all other characters }",
    start_state="q0",
    accept_states=["q_accept_dash", "q_accept_block"],
    default_transition="q0",
    transitions={
        "q0": {"-": "q_dash1", "/": "q_slash", "[any]": "q0"},
        "q_dash1": {"-": "q_accept_dash", "[any]": "q0"},
        "q_accept_dash": {"[any]": "q_accept_dash"},  # absorbing accept state
        "q_slash": {"*": "q_in_comment", "[any]": "q0"},
        "q_in_comment": {"*": "q_star", "[any]": "q_in_comment"},
        "q_star": {"/": "q_accept_block", "*": "q_star", "[any]": "q_in_comment"},
        "q_accept_block": {"[any]": "q_accept_block"}  # absorbing accept state
    }
)

# 2. XSS Script Tag DFA
# Detects `<script`
DFA_SCRIPT_TAG = FormalDFA(
    name="HTML Script Tag DFA",
    category="Cross-Site Scripting (XSS)",
    description="Recognizes the opening tag sequence '<script' regardless of surrounding context.",
    states=["q0", "q_lt", "q_s", "q_c", "q_r", "q_i", "q_p", "q_accept"],
    alphabet_description="{ '<', 's', 'c', 'r', 'i', 'p', 't' (case-insensitive), other chars }",
    start_state="q0",
    accept_states=["q_accept"],
    default_transition="q0",
    transitions={
        "q0": {"<": "q_lt", "[any]": "q0"},
        "q_lt": {"s": "q_s", "<": "q_lt", "[space]": "q_lt", "[any]": "q0"},
        "q_s": {"c": "q_c", "<": "q_lt", "[any]": "q0"},
        "q_c": {"r": "q_r", "<": "q_lt", "[any]": "q0"},
        "q_r": {"i": "q_i", "<": "q_lt", "[any]": "q0"},
        "q_i": {"p": "q_p", "<": "q_lt", "[any]": "q0"},
        "q_p": {"t": "q_accept", "<": "q_lt", "[any]": "q0"},
        "q_accept": {"[any]": "q_accept"}  # absorbing accept state
    }
)

# 3. Path Traversal DFA
# Detects `../` or `..\`
DFA_PATH_TRAVERSAL = FormalDFA(
    name="Path Traversal DFA",
    category="Path Traversal",
    description="Recognizes directory escape patterns ('../' or '..\\') across character streams.",
    states=["q0", "q_dot1", "q_dot2", "q_accept"],
    alphabet_description="{ '.', '/', '\\', other characters }",
    start_state="q0",
    accept_states=["q_accept"],
    default_transition="q0",
    transitions={
        "q0": {".": "q_dot1", "[any]": "q0"},
        "q_dot1": {".": "q_dot2", "[any]": "q0"},
        "q_dot2": {"/": "q_accept", "\\": "q_accept", ".": "q_dot2", "[any]": "q0"},
        "q_accept": {"[any]": "q_accept"}
    }
)

# 4. SQL OR-Tautology DFA
# Detects `OR` followed by a numeric equality (e.g., OR 1=1 or ' OR 1=1)
DFA_SQL_OR = FormalDFA(
    name="SQL OR-Tautology DFA",
    category="SQL Injection",
    description="Recognizes SQL 'OR' clause injection chained into tautological comparison.",
    states=["q0", "q_quote", "q_o", "q_r", "q_space", "q_digit1", "q_eq", "q_accept"],
    alphabet_description="{ ''', 'o', 'r', ' ', '=', digits, other characters }",
    start_state="q0",
    accept_states=["q_accept"],
    default_transition="q0",
    transitions={
        "q0": {"'": "q_quote", "o": "q_o", "[any]": "q0"},
        "q_quote": {"o": "q_o", "[space]": "q_quote", "[any]": "q0"},
        "q_o": {"r": "q_r", "[any]": "q0"},
        "q_r": {"[space]": "q_space", "'": "q_space", "[any]": "q0"},
        "q_space": {"[space]": "q_space", "[digit]": "q_digit1", "'": "q_space", "[any]": "q0"},
        "q_digit1": {"=": "q_eq", "'": "q_digit1", "[space]": "q_digit1", "[any]": "q0"},
        "q_eq": {"[digit]": "q_accept", "[space]": "q_eq", "'": "q_eq", "[any]": "q0"},
        "q_accept": {"[any]": "q_accept"}
    }
)

SYSTEM_DFAS = [
    DFA_SQL_COMMENT,
    DFA_SCRIPT_TAG,
    DFA_PATH_TRAVERSAL,
    DFA_SQL_OR
]


def check_dfa(text: str) -> Dict[str, Any]:
    """
    Stage 2:
    Execute all formal DFAs across the input string.

    Returns:
        dict with:
            matched (bool)
            matches (list of triggered DFA result dicts)
            primary_trace (trace of the first triggered DFA, or of DFA_SQL_COMMENT)
    """
    if not isinstance(text, str) or not text.strip():
        return {
            "matched": False,
            "matches": [],
            "count": 0,
            "primary_trace": None
        }

    matches = []
    primary_trace = None

    for dfa in SYSTEM_DFAS:
        scan_res = dfa.scan(text)
        if scan_res["accepted"]:
            matches.append({
                "dfa_name": dfa.name,
                "category": dfa.category,
                "description": dfa.description,
                "accepting_step": scan_res["accepting_step"],
                "final_state": scan_res["final_state"]
            })
            if primary_trace is None:
                primary_trace = scan_res

    # If none accepted, provide trace from the first DFA for visualization demonstration
    if primary_trace is None:
        primary_trace = DFA_SQL_COMMENT.scan(text)

    return {
        "matched": len(matches) > 0,
        "matches": matches,
        "count": len(matches),
        "primary_trace": primary_trace
    }


def get_all_dfas() -> List[Dict[str, Any]]:
    """Return all DFA definitions for UI visualization."""
    return [dfa.to_dict() for dfa in SYSTEM_DFAS]


def trace_single_dfa(dfa_name: str, text: str) -> Dict[str, Any]:
    """Execute a specific DFA and return complete step-by-step trace."""
    target_dfa = next((d for d in SYSTEM_DFAS if d.name == dfa_name), DFA_SQL_COMMENT)
    return target_dfa.scan(text)