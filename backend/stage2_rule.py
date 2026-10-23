"""
STAGE 2 - DFA BASED DETECTION

Discrete Structures concept:
Finite Automata / DFA (Unit III)
"""


def check_dfa(text):
    """
    DFA-based malicious input detection.

    Returns:
        True  -> malicious pattern accepted by DFA
        False -> no malicious pattern accepted
    """

    if not isinstance(text, str):
        return False

    text = text.lower()

    # =====================================================
    # DFA 1: UNION SELECT
    # =====================================================

    target = "union"

    for start in range(len(text)):

        state = 0

        for i in range(start, len(text)):

            if state < len(target) and text[i] == target[state]:

                state += 1

                # Final state
                if state == len(target):

                    # Check whether SELECT appears after UNION
                    remaining = text[i + 1:]

                    if "select" in remaining:
                        return True

                    break

            else:
                break

    # =====================================================
    # DFA 2: SCRIPT TAG
    # =====================================================

    target = "<script"

    for start in range(len(text)):

        state = 0

        for i in range(start, len(text)):

            if state < len(target) and text[i] == target[state]:

                state += 1

                if state == len(target):
                    return True

            else:
                break

    # =====================================================
    # DFA 3: COMMAND INJECTION
    # =====================================================

    dangerous_commands = [
        "ls",
        "dir",
        "cat",
        "whoami",
        "pwd",
        "ipconfig"
    ]

    for command in dangerous_commands:

        # Example: ;ls
        if ";" + command in text:
            return True

        # Example: |ls
        if "|" + command in text:
            return True

        # Example: &&ls
        if "&&" + command in text:
            return True

    # =====================================================
    # DFA 4: OR 1=1
    # =====================================================

    target = "or"

    for start in range(len(text)):

        state = 0

        for i in range(start, len(text)):

            if state < len(target) and text[i] == target[state]:

                state += 1

                if state == len(target):

                    remaining = text[i + 1:]

                    if "1=1" in remaining.replace(" ", ""):
                        return True

                    break

            else:
                break

    return False