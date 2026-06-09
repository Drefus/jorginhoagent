# JorginhoAgent

Pipeline de análise de segurança de código multi-linguagem com múltiplos agentes, LLM e ferramentas SAST via Docker.

## Linguagens Suportadas

| Linguagem | Extensões | Ferramentas SAST | Compilação |
|-----------|-----------|-----------------|------------|
| Python | `.py` | Trivy + Bandit | Não |
| JavaScript | `.js`, `.jsx`, `.mjs` | Trivy + Semgrep | Não |
| TypeScript | `.ts`, `.tsx` | Trivy + Semgrep | Não |
| Java | `.java` | Trivy + Semgrep | Sim (Docker JDK) |
| C# | `.cs`, `.csx` | Trivy + Semgrep | Sim (Docker .NET SDK) |

## Pré-requisitos

- Python 3.11+
- Docker (Trivy, Bandit e Semgrep rodam em containers)
- Chave de API do servidor Ollama da disciplina

## Instalação

```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

Configure o `.env` na raiz do projeto:

```env
LLM_PROVIDER=ollama
LLM_MODEL=llama3.2:3b
LLM_API_KEY=sua_chave_aqui
OLLAMA_BASE_URL=https://ollama.futurelab.dcc.ufmg.br
OLLAMA_API_KEY=sua_chave_aqui
LLM_TEMPERATURE=0.7
LLM_MAX_TOKENS=4096
BANDIT_LEVEL=high
DEBUG=False
JORGINHO_DASHBOARD=false
```

## Uso

```powershell
# Analisar arquivo (detecta linguagem automaticamente)
python main.py caminho/para/arquivo.py
python main.py caminho/para/arquivo.js
python main.py caminho/para/Arquivo.java
python main.py caminho/para/Arquivo.cs

# Com dashboard HTML
python main.py arquivo.py --dashboard

# Demo embutida (sem argumentos)
python main.py
```

### Dashboard HTML

O dashboard gera um arquivo HTML estático self-contained com:
- Gauge colorido de Risk Score
- Gráfico de barras por severidade
- Gráfico de pizza por tipo de vulnerabilidade
- Lista detalhada de vulnerabilidades com CWE/OWASP
- Blocos de código vulnerável + correção sugerida
- Seção Red Team

Ativação:
```powershell
# Via flag
python main.py arquivo.py --dashboard

# Via variável de ambiente
set JORGINHO_DASHBOARD=true
python main.py arquivo.py
```

O HTML é salvo como `<nome_arquivo>_dashboard.html` e pode ser aberto diretamente no navegador.

### Via Docker

```powershell
# Build
docker build -t jorginhoagent .

# Analisar arquivo (monta o diretório atual)
docker run --rm --env-file .env -v "${PWD}:/app" jorginhoagent arquivo.py

# Com dashboard
docker run --rm --env-file .env -v "${PWD}:/app" jorginhoagent arquivo.js --dashboard
```

## Arquitetura

```
                    ┌────────────────┐
                    │  Código Fonte  │
                    └───────┬────────┘
                            │
                   ┌────────▼────────┐
                   │ Language Detect  │
                   │ + Compilation    │
                   └────────┬────────┘
                            │
              ┌─────────────┼─────────────┐
              ▼                           ▼
┌──────────────────────┐    ┌──────────────────────┐
│  Analisador Estático │    │     Red Team Agent   │
│  Python: Trivy+Bandit│    │     (LLM + Heurís.) │
│  JS/TS/Java/C#:      │    │                      │
│  Trivy + Semgrep     │    │                      │
└──────────┬───────────┘    └──────────┬───────────┘
           │                           │
           └─────────────┬─────────────┘
                         ▼
           ┌──────────────────────────┐
           │   Avaliador Central      │
           │   (LLM ReAct Agent)      │
           │   Confirma + prioriza    │
           └────────────┬─────────────┘
                        ▼
           ┌──────────────────────────┐
           │   Fix Generator          │
           │   Templates + LLM        │
           │   Código corrigido       │
           └────────────┬─────────────┘
                        ▼
           ┌──────────────────────────┐
           │   Relatório Final        │
           │   Markdown + HTML Dashboard│
           └──────────────────────────┘
```

### Fluxo de execução

1. **Detecção de linguagem** — identifica o tipo de código por extensão ou heurísticas de conteúdo
2. **Compilação** (se necessário) — Java e C# são compilados via Docker antes da análise
3. **Análise paralela** (`asyncio.gather`):
   - **Analisador Estático** — Trivy (dependências/secrets) + Bandit (Python) ou Semgrep (JS/TS/Java/C#)
   - **Red Team Agent** — heurísticas + LLM identificam vetores de ataque
4. **Avaliador Central** — confirma vulnerabilidades, elimina falsos positivos
5. **Fix Generator** — gera correções com templates (8 categorias) + LLM
6. **Relatório** — Markdown + HTML Dashboard (se `--dashboard`)

## Estrutura do projeto

```
jorginhoagent/
├── main.py                    # Entrypoint com argparse
├── src/
│   ├── orchestrator.py        # Pipeline com 4 agentes em paralelo
│   ├── agents.py              # StaticAnalyzerAgent, RedTeamAgent, ContextEvaluator, FixGenerator
│   ├── static_analyzer.py     # Trivy + Bandit + Semgrep via Docker
│   ├── language_detector.py   # Detecção automática de linguagem
│   ├── compilation_manager.py # Compilação Java/C# via Docker
│   ├── fix_generator.py       # Templates de correção + LLM
│   ├── dashboard.py           # Gerador de HTML dashboard estático
│   ├── toolkit.py             # LangChain client, LangGraph, ReportGenerator
│   ├── config/
│   │   └── settings.py        # Pydantic settings (lê .env)
│   └── models/
│       └── schemas.py         # Vulnerability, FixSuggestion, SecurityReport
├── files_to_test/             # Casos de teste por linguagem
│   ├── vuln_project/          # Python com dependências vulneráveis
│   ├── vuln_javascript.js     # JS vulnerável
│   ├── VulnJava.java          # Java vulnerável
│   └── VulnCsharp.cs          # C# vulnerável
├── Dockerfile                 # Imagem com Trivy + Bandit
├── requirements.txt
└── .env                       # Configurações (não commitado)
```

## Integração com LLMs

| Provider | Modelos | Configuração |
|----------|---------|-------------|
| Ollama (proxy disciplina) | llama3.2:3b, deepseek-r1:8b, mixtral:8x7b | `LLM_PROVIDER=ollama` |
| OpenAI | gpt-4o-mini, gpt-4 | `LLM_PROVIDER=openai` |
| Anthropic | claude-3-sonnet | `LLM_PROVIDER=anthropic` |

## Vulnerabilidades detectadas

- SQL Injection (CWE-89)
- OS Command Injection (CWE-78)
- Code Injection / eval (CWE-95)
- Insecure Deserialization (CWE-502)
- Weak Cryptography (CWE-327)
- Hardcoded Credentials (CWE-798)
- Path Traversal (CWE-22)
- SSRF (CWE-918)
- Cross-site Scripting (CWE-79)
- Missing Authentication (CWE-306)

## Resultado

Após execução, são gerados:
- `<nome>_security_report.md` — relatório Markdown completo
- `<nome>_dashboard.html` — dashboard visual (com `--dashboard`)

## Licença

MIT License
