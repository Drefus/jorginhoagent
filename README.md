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



## Integração com GitHub com Webhooks (Fluxo Automático)

O JorginhoAgent pode atuar como um revisor de código autônomo, analisando automaticamente qualquer Pull Request (PR) aberto no seu repositório e postando um relatório de segurança diretamente nos comentários.

Siga o passo a passo abaixo para configurar essa "ponte" entre o seu ambiente local e o GitHub:

### Passo 1: Configuração do `.env`

Na raiz do projeto, crie ou edite o arquivo `.env` para incluir as variáveis do seu servidor LLM e as credenciais do GitHub.

1. Gere um **Personal Access Token (PAT)** no GitHub:
   - Vá em *Settings > Developer Settings > Personal access tokens > Tokens (classic)*.
   - Clique em *Generate new token*.
   - Marque a permissão **`repo`** (Full control of private repositories).
   - Copie o token gerado (começa com `ghp_`).

2. Preencha o arquivo `.env`:

```env
# Configurações do LLM (Exemplo usando infraestrutura da disciplina)
GITHUB_TOKEN=ghp_xxxxxxxxxxxx
LLM_PROVIDER=provedor_escolhido
OLLAMA_BASE_URL=link_base

GITHUB_REPO_OWNER=seu_usuario
GITHUB_REPO_NAME=nome_do_repositorio

ENABLE_GITHUB_INTEGRATION=true

```

### Passo 2: Subindo o Servidor Webhook

Para que o GitHub consiga avisar o agente sobre novos PRs, é necessário subir uma API local. Abra um terminal na pasta do projeto, ative o ambiente virtual e rode o Uvicorn:

```bash
# Ative o ambiente virtual (se ainda não estiver ativo)
source venv/bin/activate  # Linux/Mac
# ou venv\Scripts\activate # Windows

# Inicie o servidor
uvicorn webhook_server:app --port 8000 --reload
```
*O servidor ficará escutando na porta 8000 da sua máquina.*

### Passo 3: Criando o Túnel Público com Ngrok

Como o GitHub não consegue acessar o `localhost` diretamente, use o **Ngrok** para criar uma URL pública temporária e segura.

Abra um **segundo terminal** (mantenha o servidor rodando no primeiro) e digite:

```bash
ngrok http 8000
```
*Copie a URL pública gerada que o Ngrok vai exibir no terminal (Exemplo: `https://abcd-1234.ngrok-free.app`).*

### Passo 4: Configurando o Webhook no Repositório do GitHub

Agora é necessário que o repositório dispare eventos para o agente.

1. Acesse a página do seu repositório no GitHub.
2. Vá em **Settings** > **Webhooks** > **Add webhook**.
3. **Payload URL:** Cole a URL gerada pelo Ngrok e adicione `/webhook` no final.
   *(Exemplo: `https://abcd-1234.ngrok-free.app/webhook`)*
4. **Content type:** Mude para `application/json`.
5. Em "Which events would you like to trigger this webhook?", selecione **Let me select individual events**.
6. Desmarque "Pushes" e marque **apenas a caixa "Pull requests"**.
7. Clique em **Add webhook**.

### Passo 5: Funcionamento

Com o servidor rodando, o Ngrok ativo e o Webhook configurado:

1. Crie uma nova branch no seu repositório.
3. Faça o commit, envie para o repositório e **abra um Pull Request**.

Assim que o PR for aberto, o terminal do  Servidor Webhook mostrará os logs de download do diff e o processamento paralelo dos agentes. 
Em seguida, o Agente fará um **comentário automático no seu PR** com o relatório detalhado de segurança!



## Licença

MIT License