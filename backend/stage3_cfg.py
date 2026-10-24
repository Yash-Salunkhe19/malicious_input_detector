"""
STAGE 3 - CONTEXT-FREE GRAMMAR (CFG) DETECTION & PARSER
======================================================
Discrete Structures concept:
Context-Free Grammar (CFG), Derivations, and Parsing (Unit V)

Formally, a Context-Free Grammar is a 4-tuple:
    G = (V, Σ, R, S)
where:
    - V : Finite set of non-terminal variables
    - Σ : Finite set of terminal symbols (disjoint from V)
    - R : Production rules of the form A -> α, where A ∈ V and α ∈ (V ∪ Σ)*
    - S : Start symbol (S ∈ V)

Scope and Documented Grammar:
This grammar models structured SQL statements and malicious SQL injection fragments:
    S           -> STATEMENT | INJECTION_CLAUSE
    STATEMENT   -> SELECT_STMT | UNION_STMT
    SELECT_STMT -> "SELECT" PROJECTION "FROM" TABLE [ WHERE_CLAUSE ]
    UNION_STMT  -> "UNION" [ "ALL" ] SELECT_STMT
    INJECTION_CLAUSE -> TAUTOLOGY | UNION_STMT | STACKED_STMT
    TAUTOLOGY   -> "OR" BOOL_EXPR | "AND" BOOL_EXPR
    BOOL_EXPR   -> LITERAL OP LITERAL
    WHERE_CLAUSE-> "WHERE" CONDITION
    CONDITION   -> BOOL_EXPR | IDENT OP LITERAL | CONDITION LOGICAL_OP CONDITION
    STACKED_STMT-> ";" ( "DROP" | "DELETE" | "UPDATE" | "INSERT" ) IDENT

Limitations:
This grammar models a strict subset of SQL expressions. Real database systems
support extensive proprietary dialects, comments, and nesting that exceed
a compact educational CFG.
"""

import re
from typing import Dict, List, Any, Optional, Tuple


# Terminal token types
TOKEN_SPECIFICATION = [
    ("SELECT",      r"\bSELECT\b"),
    ("FROM",        r"\bFROM\b"),
    ("WHERE",       r"\bWHERE\b"),
    ("UNION",       r"\bUNION\b"),
    ("ALL",         r"\bALL\b"),
    ("OR",          r"\bOR\b"),
    ("AND",         r"\bAND\b"),
    ("DROP",        r"\bDROP\b"),
    ("DELETE",      r"\bDELETE\b"),
    ("UPDATE",      r"\bUPDATE\b"),
    ("INSERT",      r"\bINSERT\b"),
    ("TABLE",       r"\bTABLE\b"),
    ("OP",          r"(=|!=|<>|<=|>=|<|>)"),
    ("SEMICOLON",   r";"),
    ("COMMA",       r","),
    ("LPAREN",      r"\("),
    ("RPAREN",      r"\)"),
    ("NUMBER",      r"\b\d+\b"),
    ("STRING",      r"'(?:''|[^'])*'|\"(?:\"\"|[^\"])*\""),
    ("STAR",        r"\*"),
    ("IDENT",       r"\b[a-zA-Z_][a-zA-Z0-9_]*\b"),
    ("COMMENT",     r"--[^\n]*|/\*.*?\*/"),
    ("SKIP",        r"[ \t\r\n]+"),
    ("MISC",        r"."),
]

TOKEN_REGEX = "|".join(f"(?P<{pair[0]}>{pair[1]})" for pair in TOKEN_SPECIFICATION)
COMPILED_TOKEN_REGEX = re.compile(TOKEN_REGEX, re.IGNORECASE)


class Token:
    def __init__(self, token_type: str, value: str, position: int):
        self.type = token_type
        self.value = value
        self.position = position

    def __repr__(self):
        return f"Token({self.type}, {self.value!r})"


def tokenize(text: str) -> List[Token]:
    """Tokenize the input character stream into terminal tokens."""
    tokens = []
    for mo in COMPILED_TOKEN_REGEX.finditer(text):
        kind = mo.lastgroup
        val = mo.group()
        if kind == "SKIP" or kind == "COMMENT":
            continue
        elif kind == "MISC":
            # Keep meaningful punctuation, ignore stray harmless symbols
            if val in ("'", "\"", ";", "=", "<", ">", "-"):
                tokens.append(Token(kind, val, mo.start()))
        else:
            tokens.append(Token(kind, val, mo.start()))
    return tokens


class CFGParser:
    """
    Recursive descent parser that records derivation steps and parse trees
    for the formal SQL / Injection Grammar.
    """

    def __init__(self, tokens: List[Token]):
        self.tokens = tokens
        self.pos = 0
        self.derivations: List[str] = []
        self.detected_structures: List[Dict[str, Any]] = []

    def current_token(self) -> Optional[Token]:
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return None

    def match(self, expected_type: str) -> Optional[Token]:
        tok = self.current_token()
        if tok and (tok.type.upper() == expected_type.upper() or tok.value.upper() == expected_type.upper()):
            self.pos += 1
            return tok
        return None

    def parse(self) -> Dict[str, Any]:
        """
        Attempt to parse the token stream against the grammar.
        Scans for valid complete statements or embedded injection clauses.
        """
        self.derivations.append("S -> STATEMENT | INJECTION_CLAUSE")

        # Check for injection clauses anywhere in the token stream
        while self.pos < len(self.tokens):
            start_pos = self.pos
            clause = self.parse_injection_clause()
            if clause:
                self.detected_structures.append(clause)
                continue
            
            stmt = self.parse_select_statement()
            if stmt:
                self.detected_structures.append(stmt)
                continue

            self.pos += 1

        is_malicious = any(
            struct.get("is_injection", False) for struct in self.detected_structures
        )

        return {
            "parsed": len(self.detected_structures) > 0,
            "is_malicious": is_malicious,
            "detected_structures": self.detected_structures,
            "derivations": self.derivations[:20],
            "tokens": [f"{t.type}:{t.value}" for t in self.tokens[:30]],
            "grammar_info": {
                "start_symbol": "S",
                "variables": ["S", "STATEMENT", "SELECT_STMT", "UNION_STMT", "INJECTION_CLAUSE", "TAUTOLOGY", "BOOL_EXPR"],
                "terminals": ["SELECT", "FROM", "WHERE", "UNION", "ALL", "OR", "AND", "OP", "NUMBER", "STRING", "IDENT"]
            }
        }

    def parse_injection_clause(self) -> Optional[Dict[str, Any]]:
        """
        Parses INJECTION_CLAUSE -> TAUTOLOGY | UNION_STMT
        """
        saved = self.pos

        # 1. Tautology: OR/AND expr OP expr
        tok = self.current_token()
        if tok and tok.type in ("OR", "AND"):
            op_tok = tok
            self.pos += 1
            self.derivations.append(f"INJECTION_CLAUSE -> {op_tok.type} BOOL_EXPR")
            
            left = self.parse_literal_or_ident()
            if left:
                cmp_op = self.match("OP") or (self.current_token() and self.current_token().value == "=" and self.match("MISC"))
                if cmp_op:
                    right = self.parse_literal_or_ident()
                    if right:
                        # Check tautology equality (e.g. 1=1 or 'a'='a')
                        is_taut = (left.value.strip("'\"") == right.value.strip("'\""))
                        self.derivations.append(f"BOOL_EXPR -> {left.value} {cmp_op.value} {right.value}")
                        return {
                            "type": "SQL_TAUTOLOGY",
                            "is_injection": True,
                            "operator": op_tok.value,
                            "left": left.value,
                            "comparator": cmp_op.value,
                            "right": right.value,
                            "is_always_true": is_taut,
                            "explanation": f"Injected boolean condition '{op_tok.value} {left.value}{cmp_op.value}{right.value}' that forces query logic to evaluate true."
                        }

        # 2. UNION SELECT: UNION [ALL] SELECT ...
        self.pos = saved
        if self.match("UNION"):
            self.derivations.append("INJECTION_CLAUSE -> UNION_STMT")
            self.match("ALL")
            if self.match("SELECT"):
                self.derivations.append("UNION_STMT -> UNION [ALL] SELECT PROJECTION FROM TABLE")
                return {
                    "type": "SQL_UNION_INJECTION",
                    "is_injection": True,
                    "explanation": "Injected UNION SELECT clause attempting unauthorized table cross-querying."
                }

        self.pos = saved
        return None

    def parse_select_statement(self) -> Optional[Dict[str, Any]]:
        """
        Parses SELECT_STMT -> SELECT PROJECTION FROM TABLE [WHERE CONDITION]
        """
        saved = self.pos
        if not self.match("SELECT"):
            self.pos = saved
            return None

        self.derivations.append("STATEMENT -> SELECT_STMT")
        # Projection: STAR, IDENT, or literals
        proj = self.match("STAR") or self.match("IDENT") or self.match("NUMBER") or self.match("STRING")
        if not proj:
            self.pos = saved
            return None

        # Optional comma separated
        while self.match("COMMA"):
            self.match("IDENT") or self.match("STAR") or self.match("NUMBER")

        if not self.match("FROM"):
            self.pos = saved
            return None

        table = self.match("IDENT")
        if not table:
            self.pos = saved
            return None

        self.derivations.append(f"SELECT_STMT -> SELECT {proj.value} FROM {table.value}")

        # Optional WHERE
        where_clause = None
        if self.match("WHERE"):
            self.derivations.append("SELECT_STMT -> ... WHERE CONDITION")
            where_clause = "WHERE"

        return {
            "type": "SQL_SELECT_QUERY",
            "is_injection": True, # A raw SQL SELECT inside an arbitrary web input parameter is suspicious
            "table": table.value,
            "explanation": f"Full structured SQL query selecting from table '{table.value}'."
        }

    def parse_literal_or_ident(self) -> Optional[Token]:
        return (
            self.match("NUMBER") or
            self.match("STRING") or
            self.match("IDENT") or
            self.match("STAR")
        )


def check_cfg(text: str) -> Dict[str, Any]:
    """
    Stage 3:
    Parse input with the Context-Free Grammar.
    
    Returns:
        dict with:
            matched (bool)
            is_malicious (bool)
            structures (list of detected grammar structures)
            derivations (list of derivation steps)
            limitations (explanation of CFG coverage)
    """
    if not isinstance(text, str) or not text.strip():
        return {
            "matched": False,
            "is_malicious": False,
            "structures": [],
            "derivations": [],
            "limitations": "Empty input provided."
        }

    tokens = tokenize(text)
    parser = CFGParser(tokens)
    result = parser.parse()

    return {
        "matched": result["is_malicious"],
        "is_malicious": result["is_malicious"],
        "structures": result["detected_structures"],
        "derivations": result["derivations"],
        "tokens": result["tokens"],
        "grammar_info": result["grammar_info"],
        "limitations": (
            "CFG parsing evaluates formal syntax structure against documented production rules. "
            "It recognizes canonical query and injection clauses (UNION SELECT, OR tautologies, "
            "stacked queries) but cannot execute semantic or database-specific dialect validation."
        )
    }


def get_cfg_grammar_definition() -> Dict[str, Any]:
    """Export CFG grammar production rules for the UI explorer."""
    return {
        "title": "SQL and Injection Context-Free Grammar G = (V, Σ, R, S)",
        "start_symbol": "S",
        "variables": [
            "S",
            "STATEMENT",
            "SELECT_STMT",
            "UNION_STMT",
            "INJECTION_CLAUSE",
            "TAUTOLOGY",
            "BOOL_EXPR",
            "WHERE_CLAUSE",
            "CONDITION"
        ],
        "terminals": [
            "SELECT", "FROM", "WHERE", "UNION", "ALL",
            "OR", "AND", "DROP", "DELETE", "UPDATE", "INSERT",
            "NUMBER", "STRING", "IDENT", "OP", ";", ",", "*"
        ],
        "productions": [
            {"lhs": "S", "rhs": ["STATEMENT", "INJECTION_CLAUSE"]},
            {"lhs": "STATEMENT", "rhs": ["SELECT_STMT", "UNION_STMT"]},
            {"lhs": "SELECT_STMT", "rhs": ["SELECT PROJECTION FROM TABLE [WHERE_CLAUSE]"]},
            {"lhs": "UNION_STMT", "rhs": ["UNION [ALL] SELECT_STMT"]},
            {"lhs": "INJECTION_CLAUSE", "rhs": ["TAUTOLOGY", "UNION_STMT", "STACKED_STMT"]},
            {"lhs": "TAUTOLOGY", "rhs": ["OR BOOL_EXPR", "AND BOOL_EXPR"]},
            {"lhs": "BOOL_EXPR", "rhs": ["LITERAL OP LITERAL", "IDENT OP LITERAL"]},
            {"lhs": "WHERE_CLAUSE", "rhs": ["WHERE CONDITION"]},
            {"lhs": "STACKED_STMT", "rhs": ["; DROP TABLE IDENT", "; DELETE FROM IDENT"]}
        ],
        "notes": "Used in Unit V: Context-Free Grammar, derivation trees, and syntax analysis."
    }