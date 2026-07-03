"""Detector de linguagem de programação.

Identifica a linguagem baseado na extensão do arquivo e,
quando ambíguo, por heurísticas de conteúdo.
"""

from pathlib import Path
from typing import Optional


# Mapeamento extensão → linguagem
EXTENSION_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".cs": "csharp",
    ".csx": "csharp",
}

# Linguagens suportadas
SUPPORTED_LANGUAGES = {"python", "javascript", "typescript", "java", "csharp"}


def detect_language(file_path: str) -> str:
    """Detecta a linguagem de um arquivo.

    Args:
        file_path: Caminho para o arquivo fonte.

    Returns:
        Nome da linguagem (python, javascript, typescript, java, csharp).

    Raises:
        ValueError: Se a linguagem não puder ser determinada.
    """
    path = Path(file_path)
    ext = path.suffix.lower()

    # 1. Tenta por extensão
    if ext in EXTENSION_MAP:
        return EXTENSION_MAP[ext]

    # 2. Tenta por heurística de conteúdo
    if path.exists():
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            detected = _detect_by_content(content)
            if detected:
                return detected
        except (OSError, UnicodeDecodeError):
            pass

    raise ValueError(
        f"Tipo de arquivo não suportado: '{file_path}' (extensão: '{ext}'). "
        f"Linguagens suportadas: {', '.join(sorted(SUPPORTED_LANGUAGES))}"
    )


def _detect_by_content(content: str) -> Optional[str]:
    """Detecta linguagem analisando as primeiras 100 linhas do conteúdo."""
    lines = content.splitlines()[:100]
    text = "\n".join(lines)

    # Python indicators
    python_score = 0
    if "def " in text or "class " in text:
        python_score += 1
    if "import " in text and ("from " in text or "import os" in text or "import sys" in text):
        python_score += 1
    if "self." in text or "self," in text:
        python_score += 1
    if "print(" in text or "__init__" in text:
        python_score += 1

    # Java indicators
    java_score = 0
    if "public class " in text or "private class " in text:
        java_score += 2
    if "public static void main" in text:
        java_score += 2
    if "import java." in text or "import javax." in text:
        java_score += 2
    if "System.out." in text:
        java_score += 1

    # C# indicators
    csharp_score = 0
    if "using System" in text or "namespace " in text:
        csharp_score += 2
    if "public class " in text and ("using " in text):
        csharp_score += 1
    if "Console.Write" in text or "static void Main" in text:
        csharp_score += 1
    if "[Attribute]" in text or "async Task" in text:
        csharp_score += 1

    # JavaScript/TypeScript indicators
    js_score = 0
    if "const " in text or "let " in text or "var " in text:
        js_score += 1
    if "function " in text or "=>" in text:
        js_score += 1
    if "require(" in text or "module.exports" in text:
        js_score += 1
    if "console.log" in text:
        js_score += 1

    ts_score = js_score  # TypeScript herda de JS
    if ": string" in text or ": number" in text or ": boolean" in text:
        ts_score += 2
    if "interface " in text or "type " in text:
        ts_score += 1
    if "import {" in text and "from '" in text:
        ts_score += 1

    # Determina vencedor
    scores = {
        "python": python_score,
        "java": java_score,
        "csharp": csharp_score,
        "typescript": ts_score,
        "javascript": js_score,
    }

    max_score = max(scores.values())
    if max_score < 2:
        return None  # Confiança insuficiente

    # Desempate: TypeScript > JavaScript (superset)
    winners = [lang for lang, score in scores.items() if score == max_score]
    if "typescript" in winners:
        return "typescript"
    return winners[0]


def get_language_tools(language: str) -> dict:
    """Retorna ferramentas de análise recomendadas por linguagem."""
    tools_map = {
        "python": {
            "sast": ["trivy", "bandit"],
            "needs_compilation": False,
            "docker_image": None,
        },
        "javascript": {
            "sast": ["trivy", "semgrep"],
            "needs_compilation": False,
            "docker_image": None,
        },
        "typescript": {
            "sast": ["trivy", "semgrep"],
            "needs_compilation": False,
            "docker_image": None,
        },
        "java": {
            "sast": ["trivy", "semgrep"],
            "needs_compilation": True,
            "docker_image": "eclipse-temurin:17-jdk",
        },
        "csharp": {
            "sast": ["trivy", "semgrep"],
            "needs_compilation": True,
            "docker_image": "mcr.microsoft.com/dotnet/sdk:8.0",
        },
    }
    return tools_map.get(language, tools_map["python"])
