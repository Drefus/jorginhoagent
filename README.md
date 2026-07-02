# JorginhoAgent

Pipeline de análise de segurança de código multi-linguagem com múltiplos agentes, LLM e ferramentas SAST (Semgrep + Bandit).

## Linguagens Suportadas

| Linguagem | Extensões | Ferramentas SAST |
|-----------|-----------|-----------------|
| Python | `.py` | Semgrep + Bandit |
| JavaScript | `.js`, `.jsx`, `.mjs` | Semgrep |
| TypeScript | `.ts`, `.tsx` | Semgrep |
| Java | `.java` | Semgrep |
| C# | `.cs`, `.csx` | Semgrep |

## Pré-requisitos

- Python 3.11+
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

Gera um arquivo HTML estático self-contained com:
- Gauge colorido de Risk Score (verde/amarelo/vermelho)
- Gráfico de barras por severidade (CRITICAL, HIGH, MEDIUM, LOW)
- Gráfico de pizza por tipo de vulnerabilidade
- Lista detalhada de vulnerabilidades com CWE/OWASP
- Blocos de código vulnerável + correção sugerida
- Seção Red Team com vetores de ataque

Ativação:
```powershell
# Via flag
python main.py arquivo.py --dashboard

# Via variável de ambiente
set JORGINHO_DASHBOARD=true
python main.py arquivo.py
```

O HTML é salvo como `<nome_arquivo>_dashboard.html` e pode ser aberto diretamente no navegador sem servidor.

## Arquitetura

```
                    ┌────────────────┐
                    │  Código Fonte  │
                    └───────┬────────┘
                            │
                   ┌────────▼────────┐
                   │ Language Detect  │
                   └────────┬────────┘
                            │
              ┌─────────────┼─────────────┐
              ▼                           ▼
┌──────────────────────┐    ┌──────────────────────┐
│  Analisador Estático │    │     Red Team Agent   │
│  Semgrep (todos)     │    │     (LLM + Heurís.) │
│  + Bandit (Python)   │    │                      │
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
           │   Markdown + Dashboard   │
           └──────────────────────────┘
```

### Fluxo de execução

1. **Detecção de linguagem** — identifica por extensão ou heurísticas de conteúdo
2. **Análise paralela** (`asyncio.gather`):
   - **Analisador Estático** — Semgrep (todas as linguagens) + Bandit (Python)
   - **Red Team Agent** — heurísticas + LLM identificam vetores de ataque
3. **Avaliador Central** — confirma vulnerabilidades, elimina falsos positivos
4. **Fix Generator** — gera correções com templates (8 categorias) + LLM
5. **Relatório** — Markdown + HTML Dashboard (se `--dashboard`)

## Estrutura do projeto

```
jorginhoagent/
├── main.py                    # Entrypoint com argparse
├── src/
│   ├── orchestrator.py        # Pipeline com 4 agentes em paralelo
│   ├── agents.py              # StaticAnalyzerAgent, RedTeamAgent, ContextEvaluator, FixGenerator
│   ├── static_analyzer.py     # Semgrep + Bandit (binários locais via pip)
│   ├── language_detector.py   # Detecção automática de linguagem
│   ├── compilation_manager.py # Compilação Java/C# via Docker (quando necessário)
│   ├── fix_generator.py       # Templates de correção + LLM
│   ├── dashboard.py           # Gerador de HTML dashboard estático
│   ├── toolkit.py             # LangChain client, LangGraph, ReportGenerator
│   ├── config/
│   │   └── settings.py        # Pydantic settings (lê .env)
│   └── models/
│       └── schemas.py         # Vulnerability, FixSuggestion, SecurityReport
├── files_to_test/             # Casos de teste por linguagem
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

## Resultado

Após execução, são gerados:
- `<nome>_security_report.md` — relatório Markdown
- `<nome>_dashboard.html` — dashboard visual (com `--dashboard`)

## Integração com GitHub (Fluxo Automático)

Para integrar o `JorginhoAgent` ao fluxo de desenvolvimento e garantir que ele analise automaticamente os Pull Requests (PRs), siga estes passos:

### 1. Configuração do Webhook
O agente utiliza eventos de Webhook para saber exatamente quando um PR foi criado ou atualizado.

1.  **Exponha seu servidor**: Como o servidor roda localmente, use uma ferramenta de túnel (como `ngrok` ou `localtunnel`) para expor sua porta 8000:
    ```bash
    ngrok http 8000
    ```
2.  **Configure no GitHub**:
    - Vá ao seu repositório no GitHub > **Settings** > **Webhooks** > **Add webhook**.
    - Em **Payload URL**, cole a URL gerada pelo ngrok (ex: `https://xyz.ngrok.io/webhook`).
    - Em **Content type**, selecione `application/json`.
    - Em **Which events would you like to trigger this webhook?**, selecione **"Let me select individual events"** e marque apenas **"Pull requests"**.
    - Salve o webhook.

### 2. Variáveis de Ambiente Necessárias
No seu arquivo `.env`, certifique-se de configurar as permissões corretas para a API:

```env
GITHUB_TOKEN=ghp_xxxxxxxxxxxx  # Crie um PAT com escopo 'repo'
GITHUB_REPO_OWNER=seu-usuario
GITHUB_REPO_NAME=seu-repositorio-alvo
```
Além disso, lembre-se de configurar `ENABLE_GITHUB_INTEGRATION` para `true`

### 3. Execução do Servidor Webhook
O sistema já possui um servidor FastAPI preparado para escutar os eventos do GitHub. Com o ambiente virtual ativado, inicie-o na raiz do projeto:

---
```bash
uvicorn webhook_server:app --port 8000
```

> **Nota:** Certifique-se de renomear o ficheiro ` .env.example ` para ` .env ` e preencher as suas credenciais antes de iniciar o servidor.

## Licença

MIT License