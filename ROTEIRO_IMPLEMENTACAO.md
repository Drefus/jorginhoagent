# Roteiro de Implementação - Agente Multiagente de Revisão de Código com Foco em Segurança

## 1. Estrutura do Projeto

```
jorginhoagent/
├── src/
│   ├── agents/
│   │   ├── __init__.py
│   │   ├── static_analyzer.py          # Agente 1: Analisador Estático
│   │   ├── context_evaluator.py        # Agente 2: Avaliador de Contexto
│   │   └── fix_generator.py            # Agente 3: Gerador de Correções
│   ├── tools/
│   │   ├── __init__.py
│   │   ├── static_analysis.py          # Wrapper para Bandit
│   │   ├── vulnerability_db.py         # Consulta bases de vulnerabilidades (CWE, OWASP)
│   │   ├── code_embedding.py           # CodeBERT/CodeLlama embeddings
│   │   ├── github_integration.py       # GitHub API
│   │   └── report_generator.py         # Geração de relatórios
│   ├── models/
│   │   ├── __init__.py
│   │   └── schemas.py                  # Pydantic schemas para estruturação de dados
│   ├── rag/
│   │   ├── __init__.py
│   │   ├── vulnerability_rag.py        # RAG para vulnerabilidades
│   │   └── code_rag.py                 # RAG para contexto de código
│   ├── graph/
│   │   ├── __init__.py
│   │   └── orchestrator.py             # Orquestração LangGraph dos agentes
│   ├── config/
│   │   ├── __init__.py
│   │   └── settings.py                 # Configurações (API keys, modelos)
│   └── main.py                         # Ponto de entrada
├── tests/
│   ├── __init__.py
│   ├── test_agents.py
│   ├── test_tools.py
│   ├── test_integration.py
│   └── fixtures/
│       └── sample_code.py              # Amostras de código para teste
├── data/
│   ├── datasets/
│   │   ├── cvefixes/                   # CVEfixes Dataset
│   │   ├── codexglue/                  # CodeXGLUE Dataset
│   │   └── webgoat/                    # OWASP WebGoat
│   └── embeddings/                     # Cache de embeddings
├── notebooks/
│   ├── 01_exploration.ipynb            # Exploração de datasets
│   ├── 02_rag_evaluation.ipynb         # Avaliação RAG
│   └── 03_agent_testing.ipynb          # Testes dos agentes
├── requirements.txt
├── requirements-dev.txt
├── .env.example
├── .gitignore
├── docker-compose.yml                  # Para dependências (PostgreSQL, Redis)
└── README.md
```

## 2. Fases de Implementação

### **Fase 1: Setup e Infraestrutura (Semana 1-2)**

#### 1.1 Configuração do Ambiente
- [ ] Criar repositório Git e estrutura base
- [ ] Configurar Python virtual environment (Python 3.10+)
- [ ] Instalar dependências core:
  ```bash
  pip install langchain langgraph langsmith
  pip install huggingface-transformers torch
  pip install pydantic python-dotenv
  pip install pytest pytest-cov
  ```
- [ ] Configurar Docker Compose para dependências (se necessário)
- [ ] Criar arquivo `.env` com variáveis:
  - `GITHUB_TOKEN`
  - `LLM_API_KEY` (OpenAI/Anthropic/etc)
  - `HUGGINGFACE_API_KEY`

#### 1.2 Estrutura de Dados
- [ ] Definir Pydantic schemas em `models/schemas.py`:
  ```python
  class Vulnerability:
      type: str
      severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
      line_number: int
      description: str
      cwe_id: Optional[str]
      owasp_category: Optional[str]
      
  class CodeAnalysisResult:
      file_path: str
      vulnerabilities: List[Vulnerability]
      
  class SecurityReport:
      pr_id: str
      timestamp: datetime
      analyzed_files: List[CodeAnalysisResult]
      recommendations: List[str]
      risk_score: float
  ```

- [ ] Configurar logging estruturado com `logging` module

---

### **Fase 2: Ferramentas Base (Semana 2-3)**

#### 2.1 Análise Estática (`tools/static_analysis.py`)
- [ ] Wrapper para Bandit:
  ```bash
  pip install bandit
  ```
- [ ] Função para executar Bandit em código Python
- [ ] Parser de resultados Bandit para schema próprio
- [ ] Testes unitários

#### 2.2 Integração com Bases de Vulnerabilidades (`tools/vulnerability_db.py`)
- [ ] Carregar dados CWE (JSON/API)
- [ ] Carregar dados OWASP Top 10
- [ ] Criar função de lookup por tipo de vulnerabilidade
- [ ] Cache em memória ou banco de dados (Redis opcional)

#### 2.3 Embeddings de Código (`tools/code_embedding.py`)
- [ ] Instalar CodeBERT ou CodeLlama:
  ```bash
  pip install sentence-transformers  # Para CodeBERT
  # ou usar Hugging Face CodeLlama
  ```
- [ ] Função para gerar embeddings de snippets de código
- [ ] Cache de embeddings em arquivo ou banco de dados
- [ ] Testes com exemplos de código vulnerável

#### 2.4 GitHub Integration (`tools/github_integration.py`)
- [ ] Instalar PyGithub:
  ```bash
  pip install PyGithub
  ```
- [ ] Funções para:
  - Listar PRs
  - Fetch code diffs
  - Post comentários
  - Fetch issue details
- [ ] Testes com mock de GitHub API

---

### **Fase 3: RAG (Retrieval-Augmented Generation) (Semana 3-4)**

#### 3.1 Vulnerability RAG (`rag/vulnerability_rag.py`)
- [ ] Instalar LlamaIndex:
  ```bash
  pip install llama-index llama-index-embeddings-huggingface
  ```
- [ ] Criar documento store com descrições de vulnerabilidades
- [ ] Indexar CWE, OWASP, CVEfixes com embeddings
- [ ] Implementar retriever para encontrar vulnerabilidades similares
- [ ] Testes de retrieval accuracy

#### 3.2 Code Context RAG (`rag/code_rag.py`)
- [ ] Indexar amostras do CodeXGLUE dataset
- [ ] Implementar retriever para encontrar padrões de código similares
- [ ] Testes com exemplos reais

---

### **Fase 4: Agentes LLM (Semana 4-6)**

#### 4.1 Agent 1 - Static Analyzer (`agents/static_analyzer.py`)
```python
class StaticAnalyzerAgent:
    def __init__(self, llm_model: str = "gpt-4"):
        self.llm = initialize_llm(llm_model)
        self.bandit_tool = BanditAnalyzer()
        self.vuln_db = VulnerabilityDB()
    
    async def analyze(self, code: str) -> List[Vulnerability]:
        """
        1. Executar Bandit
        2. LLM enriquece com contexto
        3. Retorna vulnerabilidades com descrições
        """
        pass
```

- [ ] Instalar LangChain para agentes:
  ```bash
  pip install langchain-openai  # ou outro provider
  ```
- [ ] Definir prompt system para análise estática
- [ ] Integrar com Bandit via tool calling
- [ ] Testes com código contendo vulnerabilidades conhecidas

#### 4.2 Agent 2 - Context Evaluator (`agents/context_evaluator.py`)
```python
class ContextEvaluatorAgent:
    def __init__(self, llm_model: str = "gpt-4"):
        self.llm = initialize_llm(llm_model)
        self.code_rag = CodeRAG()
        self.vulnerability_rag = VulnerabilityRAG()
    
    async def evaluate(self, 
                      code: str, 
                      vulnerabilities: List[Vulnerability]
                     ) -> List[Vulnerability]:
        """
        1. Analisar fluxo de dados
        2. RAG para padrões similares
        3. Verificar validações
        4. Confirmar/descartar alertas
        5. Reclassificar severidade
        """
        pass
```

- [ ] Definir prompt para análise contextual
- [ ] Integrar RAG para buscar padrões similares
- [ ] Implementar data flow analysis
- [ ] Testes com false positives

#### 4.3 Agent 3 - Fix Generator (`agents/fix_generator.py`)
```python
class FixGeneratorAgent:
    def __init__(self, llm_model: str = "gpt-4"):
        self.llm = initialize_llm(llm_model)
        self.code_rag = CodeRAG()
    
    async def generate_fixes(self, 
                            code: str,
                            vulnerabilities: List[Vulnerability]
                           ) -> List[SecurityReport]:
        """
        1. Para cada vulnerabilidade:
           - RAG para encontrar padrões de correção
           - Gerar código corrigido
           - Explicar mudanças
        2. Priorizar por severidade
        3. Gerar relatório final
        """
        pass
```

- [ ] Definir prompt para geração de código
- [ ] Integrar RAG para exemplos de correção
- [ ] Validar código gerado (syntax check)
- [ ] Formatar relatório com CWE/OWASP references
- [ ] Testes com vulnerabilidades variadas

---

### **Fase 5: Orquestração LangGraph (Semana 6-7)**

#### 5.1 Orchestrator (`graph/orchestrator.py`)
```python
from langgraph.graph import StateGraph

class AgentOrchestrator:
    def __init__(self):
        self.graph = StateGraph(AgentState)
        self._build_graph()
    
    def _build_graph(self):
        # Nó 1: Static Analyzer
        self.graph.add_node("static_analysis", self.static_analyzer_node)
        
        # Nó 2: Context Evaluator
        self.graph.add_node("context_evaluation", self.context_evaluator_node)
        
        # Nó 3: Fix Generator
        self.graph.add_node("fix_generation", self.fix_generator_node)
        
        # Fluxo: Static → Context → Fix
        self.graph.add_edge("static_analysis", "context_evaluation")
        self.graph.add_edge("context_evaluation", "fix_generation")
        self.graph.set_entry_point("static_analysis")
        self.graph.set_finish_point("fix_generation")
        
        self.compiled = self.graph.compile()
    
    async def process_pr(self, pr_code: str) -> SecurityReport:
        """Executar pipeline completo"""
        pass
```

- [ ] Definir Estado compartilhado entre agentes
- [ ] Implementar nós do grafo
- [ ] Configurar edge conditions (routing)
- [ ] Testes de fluxo completo

---

### **Fase 6: Integração com GitHub (Semana 7)**

#### 6.1 GitHub Bot (`tools/github_integration.py`)
- [ ] Webhook listener para novos PRs
- [ ] Fetch code changes
- [ ] Executar pipeline de análise
- [ ] Post comentário automático com resultados
- [ ] Suportar re-análise via comando (e.g., `@bot analyze`)

#### 6.2 Report Generator (`tools/report_generator.py`)
- [ ] Formatador de saída para GitHub Markdown
- [ ] Incluir severidade com emojis/cores
- [ ] Links para CWE/OWASP
- [ ] Sugestões de correção inline

---

### **Fase 7: Avaliação e Ajustes (Semana 8)**

#### 7.1 Métricas
- [ ] Implementar cálculo de:
  - Taxa de falsos positivos
  - Precisão de detecção
  - Tempo de análise
  - Qualidade das explicações (BLEU/ROUGE scores)

#### 7.2 Testes Comparativos
- [ ] Só Bandit (baseline)
- [ ] LLM isolado
- [ ] Arquitetura multiagente
- [ ] Registrar métricas para cada abordagem

#### 7.3 Datasets de Teste
- [ ] Download e preparação:
  - CVEfixes Dataset (exemplos reais de patches)
  - CodeXGLUE (código Python de exemplo)
  - OWASP WebGoat (vulnerabilidades conhecidas)

---

## 3. Componentes Principais por Fase

| Fase | Componentes | Status | Dependências |
|------|------------|--------|--------------|
| 1 | Setup, estrutura, schemas | ⏳ | Poetry/pip |
| 2 | Bandit, CWE/OWASP, CodeBERT | ⏳ | huggingface, bandit |
| 3 | LlamaIndex RAG | ⏳ | llama-index |
| 4 | 3 Agentes LLM | ⏳ | langchain, openai |
| 5 | LangGraph orchestration | ⏳ | langgraph |
| 6 | GitHub bot + webhooks | ⏳ | fastapi, pydantic |
| 7 | Testes e métricas | ⏳ | pytest, datasets |

---

## 4. Dependências Principais

```
# Core
langchain>=0.1.0
langgraph>=0.1.0
langchain-openai>=0.0.1  # ou outro LLM provider
pydantic>=2.0.0

# LLMs e Embeddings
huggingface-transformers>=4.30.0
sentence-transformers>=2.2.0
torch>=2.0.0

# Análise Estática
bandit>=1.7.5

# RAG
llama-index>=0.9.0
llama-index-embeddings-huggingface>=0.1.0

# GitHub
PyGithub>=2.1.0

# Utils
python-dotenv>=1.0.0
python-dateutil>=2.8.0

# Testing
pytest>=7.0.0
pytest-asyncio>=0.21.0
pytest-cov>=4.0.0
```

---

## 5. Marcos de Entrega

### MVP (Semana 4)
- ✅ Agente 1: Análise estática + LLM
- ✅ Agente 2: Avaliador de contexto (básico)
- ✅ Relatório em texto

### Beta (Semana 6)
- ✅ Todos os 3 agentes
- ✅ LangGraph orchestration
- ✅ RAG funcional

### Produção (Semana 8)
- ✅ GitHub integration
- ✅ Testes comparativos
- ✅ Documentação completa

---

## 6. Checklist de Implementação

### Semana 1-2: Infraestrutura
- [ ] Repo configurado
- [ ] Ambiente Python pronto
- [ ] Schemas Pydantic definidos
- [ ] Logging configurado
- [ ] Testes skeleton criados

### Semana 2-3: Ferramentas
- [ ] Bandit wrapper funcional
- [ ] CWE/OWASP loaded
- [ ] CodeBERT embeddings working
- [ ] GitHub API wrapper ready

### Semana 3-4: RAG
- [ ] Vulnerability RAG indexado
- [ ] Code RAG indexado
- [ ] Retrieval tests passing

### Semana 4-6: Agentes
- [ ] Agent 1 base ready
- [ ] Agent 2 base ready
- [ ] Agent 3 base ready
- [ ] Cada agente com testes

### Semana 6-7: Orquestração
- [ ] LangGraph graph defined
- [ ] State management working
- [ ] End-to-end pipeline ready
- [ ] GitHub bot listening

### Semana 7-8: Produção
- [ ] Métricas implementadas
- [ ] Datasets de teste carregados
- [ ] Comparação static vs LLM vs multiagent
- [ ] Documentação finalizada

---

## 7. Considerações de Desenvolvimento

### Performance
- Cache agressivo de embeddings
- Reuse de LLM connections
- Batch processing de múltiplos PRs
- Async/await em todo lugar

### Segurança
- Validar código gerado antes de sugerir
- Sanitizar entrada do GitHub
- Rate limit na API do GitHub
- Audit logs de todas as sugestões

### Explicabilidade
- Justificar cada detecção
- Referenciar padrões similares (RAG)
- CWE/OWASP IDs obrigatórios
- Chain of thought visible

---

## 8. Próximos Passos

1. **Hoje**: Revisar e validar este roteiro com o time
2. **Amanhã**: Criar tickets/issues para cada tarefa
3. **Semana 1**: Começar Fase 1 - Setup

