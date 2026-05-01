# 🔒 JorginhoAgent - Multi-Agent Code Security Analysis System

Um agente multiagente baseado em LLMs para análise automática de código com foco em segurança, detectando vulnerabilidades, avaliando contexto e gerando correções práticas.

## 📋 Visão Geral

JorginhoAgent é um sistema de análise de código que combina três agentes especializados:

1. **Agente 1 - Analisador Estático**: Detecta vulnerabilidades conhecidas usando Bandit e técnicas de análise sintática/semântica
2. **Agente 2 - Avaliador de Contexto**: Analisa o contexto do código para reduzir falsos positivos e reclassificar severidade
3. **Agente 3 - Gerador de Correções**: Sugere correções práticas com exemplos de código e explicações

O sistema é orquestrado usando **LangGraph** para coordenar o fluxo entre agentes e é integrado com **LLMs** (OpenAI/Anthropic) para análise contextual aprimorada.

## 🚀 Quickstart

### Instalação

```bash
# Clone o repositório
git clone https://github.com/seu-repo/jorginhoagent.git
cd jorginhoagent

# Crie um virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Instale as dependências
pip install -r requirements.txt

# Para desenvolvimento
pip install -r requirements-dev.txt
```

### Configuração

```bash
# Copie o arquivo de exemplo de configuração
cp .env.example .env

# Edite .env com suas credenciais
# REQUIRED:
# - LLM_API_KEY (OpenAI ou Anthropic)
# - LLM_MODEL (gpt-4, claude-3-opus, etc.)

# OPTIONAL:
# - GITHUB_TOKEN (para integração com GitHub)
# - HUGGINGFACE_API_KEY (para embeddings)
```

### Uso Básico

```python
import asyncio
from src.graph.orchestrator import AgentOrchestrator
from src.tools.report_generator import ReportGenerator

async def main():
    # Criar orquestrador
    orchestrator = AgentOrchestrator()
    
    # Código para analisar
    code = '''
def login(username, password):
    query = f"SELECT * FROM users WHERE username='{username}'"
    return db.execute(query)
'''
    
    # Executar análise
    report = await orchestrator.process_code(code, "app.py")
    
    # Gerar relatório
    markdown = ReportGenerator.generate_markdown_report(report)
    print(markdown)

asyncio.run(main())
```

## 📁 Estrutura do Projeto

```
jorginhoagent/
├── src/
│   ├── agents/               # Implementação dos 3 agentes
│   │   ├── static_analyzer.py
│   │   ├── context_evaluator.py
│   │   └── fix_generator.py
│   ├── tools/                # Ferramentas auxiliares
│   │   ├── static_analysis.py        # Wrapper Bandit
│   │   ├── vulnerability_db.py       # Base de dados CWE/OWASP
│   │   ├── code_embedding.py         # CodeBERT embeddings
│   │   ├── github_integration.py     # API GitHub
│   │   └── report_generator.py       # Geração de relatórios
│   ├── models/               # Schemas Pydantic
│   │   └── schemas.py
│   ├── rag/                  # RAG (futuro)
│   ├── graph/                # Orquestração LangGraph
│   │   └── orchestrator.py
│   ├── config/               # Configuração
│   │   └── settings.py
│   └── main.py               # Ponto de entrada
├── tests/                    # Testes
├── notebooks/                # Jupyter notebooks
├── data/                     # Dados e datasets
├── requirements.txt
├── requirements-dev.txt
└── README.md
```

## 🔍 Exemplos de Uso

### Exemplo 1: Analisar um arquivo Python

```python
from pathlib import Path
from src.graph.orchestrator import AgentOrchestrator
import asyncio

async def analyze_file(file_path):
    orchestrator = AgentOrchestrator()
    code = Path(file_path).read_text()
    report = await orchestrator.process_code(code, file_path)
    return report

# Uso
report = asyncio.run(analyze_file("app.py"))
print(f"Risk Score: {report.overall_risk_score}")
print(f"Vulnerabilities: {report.total_vulnerabilities}")
```

### Exemplo 2: Integração com GitHub

```python
from src.tools.github_integration import GitHubIntegration
from src.graph.orchestrator import AgentOrchestrator

# Fetch PR
github = GitHubIntegration(token="seu_token")
pr_content = github.get_pr_content("owner", "repo", 123)

# Analisar
orchestrator = AgentOrchestrator()
report = await orchestrator.process_code(pr_content, "pr_changes.py", pr_id="123")

# Post resultado no PR
from src.tools.report_generator import ReportGenerator
comment = ReportGenerator.generate_github_comment(report)
github.post_comment("owner", "repo", 123, comment)
```

### Exemplo 3: Gerar diferentes tipos de relatório

```python
from src.tools.report_generator import ReportGenerator

# Markdown (para GitHub, documentação)
markdown = ReportGenerator.generate_markdown_report(report)

# Comentário GitHub (conciso)
gh_comment = ReportGenerator.generate_github_comment(report)

# JSON (para processamento automatizado)
json_report = ReportGenerator.generate_json_report(report)
```

## 🧪 Testes

```bash
# Executar todos os testes
pytest

# Com cobertura
pytest --cov=src tests/

# Testes específicos
pytest tests/test_tools.py -v

# Testes async
pytest tests/test_integration.py -v
```

## 🏗️ Arquitetura

### Pipeline de Análise

```
┌─────────────────────────────────────┐
│   Código Fonte                      │
└────────────┬────────────────────────┘
             │
             ▼
┌─────────────────────────────────────┐
│  Agente 1: Análise Estática         │
│  - Executa Bandit                   │
│  - Identifica padrões inseguros     │
│  - Enriquece com CWE/OWASP         │
└────────────┬────────────────────────┘
             │
             ▼
┌─────────────────────────────────────┐
│  Agente 2: Avaliação de Contexto   │
│  - Analisa fluxo de dados           │
│  - Verifica validações              │
│  - Reduz falsos positivos           │
│  - Reclassifica severidade          │
└────────────┬────────────────────────┘
             │
             ▼
┌─────────────────────────────────────┐
│  Agente 3: Gerador de Correções    │
│  - Sugere fixes práticos            │
│  - Gera código corrigido            │
│  - Explica mudanças                 │
│  - Referencia CWE/OWASP            │
└────────────┬────────────────────────┘
             │
             ▼
┌─────────────────────────────────────┐
│   Relatório de Segurança            │
│   - Markdown                        │
│   - GitHub Comment                  │
│   - JSON                            │
└─────────────────────────────────────┘
```

### Integração com LLMs

O sistema suporta múltiplos provedores de LLM:

- **OpenAI** (GPT-4, GPT-3.5-turbo)
- **Anthropic** (Claude 3 Opus, Sonnet)

Configure em `.env`:

```
LLM_PROVIDER=openai
LLM_MODEL=gpt-4
LLM_API_KEY=sk-...
```

## 📊 Métricas de Avaliação

O sistema calcula:

- **Taxa de Falsos Positivos**: Vulnerabilidades confirmadas vs detectadas
- **Precisão de Detecção**: Vulnerabilidades reais detectadas
- **Tempo de Análise**: Duração total do pipeline
- **Qualidade das Explicações**: BLEU/ROUGE scores (futuro)
- **Risk Score**: Agregação ponderada de severidades (0-100)

## 🔐 Vulnerabilidades Suportadas

### OWASP Top 10 (2021)

- **A01: Broken Access Control** - Missing authentication, CSRF
- **A02: Cryptographic Failures** - Weak hashing, encryption
- **A03: Injection** - SQL injection, OS command injection, XSS
- **A04: Insecure Design** - Missing security requirements
- **A07: Identification and Authentication Failures** - Weak auth

### CWE Common Top 25

- CWE-89 SQL Injection
- CWE-79 Cross-site Scripting (XSS)
- CWE-78 OS Command Injection
- CWE-327 Weak Cryptography
- CWE-200 Sensitive Data Exposure
- E mais...

## 🛠️ Desenvolvimento

### Adicionar novo tipo de vulnerabilidade

1. Adicione à base de dados em `src/tools/vulnerability_db.py`:

```python
"NEW_VULN_TYPE": {
    "cwe_id": "CWE-XXX",
    "cwe_name": "...",
    "owasp": "A0X:2021",
    "description": "...",
    "remediation": "...",
}
```

2. Adicione detector no agente apropriado

3. Adicione fix template em `src/agents/fix_generator.py`

### Estender com RAG

O sistema está preparado para RAG (Retrieval-Augmented Generation):

```python
from src.rag.vulnerability_rag import VulnerabilityRAG

rag = VulnerabilityRAG()
similar_vulns = rag.retrieve_similar("SQL injection in login form", top_k=5)
```

## 📚 Datasets Utilizados

- **CVEfixes**: Exemplos reais de vulnerabilidades e patches
- **CodeXGLUE**: Padrões de código seguro e inseguro
- **OWASP WebGoat**: Exercícios de segurança

## 🚦 Status do Projeto

### ✅ Implementado

- [x] Estrutura base do projeto
- [x] Agente 1: Análise Estática
- [x] Agente 2: Avaliador de Contexto
- [x] Agente 3: Gerador de Correções
- [x] Orquestrador LangGraph
- [x] Suporte LLM (OpenAI/Anthropic)
- [x] Geração de relatórios (Markdown/GitHub/JSON)
- [x] Base de dados de vulnerabilidades (CWE/OWASP)
- [x] Testes básicos

### 🚧 Em Progresso

- [ ] Integração completa com GitHub API
- [ ] RAG para embeddings de código
- [ ] Webhooks para monitoramento automático de PRs
- [ ] Dashboard web para visualização de resultados
- [ ] Integração com CI/CD

### 📋 Futuro

- [ ] Suporte a múltiplas linguagens (JavaScript, Java, C#)
- [ ] Análise de dependências e vulnerabilidades conhecidas
- [ ] Integração com ferramentas SAST existentes
- [ ] Análise de segurança dinâmica
- [ ] Machine learning para priorização de vulnerabilidades

## 📄 Licença

MIT License

## 👥 Contribuindo

Contribuições são bem-vindas! Por favor:

1. Faça fork do projeto
2. Crie uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

## 📞 Suporte

Para dúvidas ou issues:
- Abra uma issue no GitHub
- Consulte a [documentação completa](./docs)

---

**Desenvolvido com ❤️ pelo time de segurança de software**
