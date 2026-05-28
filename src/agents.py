def _parse_json(text: str):
    text = re.sub(r"```[a-zA-Z]*\n?", "", text).replace("```", "").strip()

    match = re.search(r"(\[.*\]|\{.*\})", text, re.DOTALL)

    if match:
        text = match.group(1)

    try:
        return json.loads(text)

    except Exception:
        try:
            text = re.sub(r'(?<!\\)"\s*\+\s*([^"]+?)\s*\+\s*"', r"'\g<0>'", text)
            text = re.sub(r":\s*NaN", ': null', text)
            text = text.replace("\n", " ")

            clean_text = (
                text.replace("null", "None")
                .replace("true", "True")
                .replace("false", "False")
            )

            return ast.literal_eval(clean_text)

        except Exception:
            try:
                fixed = re.sub(r'("code_snippet"\s*:\s*)"([^"]*)"', lambda m: m.group(1) + json.dumps(m.group(2)), text)
                return json.loads(fixed)

            except Exception:
                raise ValueError("Falha irreparável no parse do JSON/Dict")


def _safe_int(value, default=0):
    try:
        if value is None:
            return default

        return int(float(value))

    except Exception:
        return default


def _safe_float(value, default=0.0):
    try:
        if value is None:
            return default

        value = float(value)

        if value > 1:
            value = value / 100

        return max(0.0, min(value, 1.0))

    except Exception:
        return default


def _safe_str(value, default="Unknown"):
    try:
        if value is None:
            return default

        return str(value).strip()

    except Exception:
        return default


def _normalize_level(value, default="MEDIUM"):
    if value is None:
        return default

    value = str(value).upper().strip()

    if value in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        return value

    if value in ["1", "2"]:
        return "LOW"

    if value in ["3", "4", "5", "6"]:
        return "MEDIUM"

    if value in ["7", "8", "9", "10"]:
        return "HIGH"

    return default


def _sanitize_vulnerability(item):
    return {
        "type": _safe_str(item.get("type"), "Unknown"),
        "severity": _normalize_level(item.get("severity"), "MEDIUM"),
        "line_number": _safe_int(item.get("line_number"), 0),
        "description": _safe_str(item.get("description"), "Unknown"),
        "code_snippet": _safe_str(item.get("code_snippet"), ""),
        "confidence": _safe_float(item.get("confidence"), 0.8),
        "is_false_positive": bool(item.get("is_false_positive", False)),
    }


def _sanitize_attack_vector(item):
    return {
        "attack_type": _safe_str(item.get("attack_type"), "Unknown"),
        "line_number": _safe_int(item.get("line_number"), 0),
        "description": _safe_str(item.get("description"), "Unknown"),
        "exploitability": _normalize_level(item.get("exploitability"), "MEDIUM"),
        "payload_example": _safe_str(item.get("payload_example"), ""),
        "impact": _safe_str(item.get("impact"), "Unknown"),
    }