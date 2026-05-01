# JorginhoAgent - Quick Start Guide

## 📦 Installation

```bash
# 1. Clone repository
git clone <repo-url>
cd jorginhoagent

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
# Edit .env with your API keys
```

## ⚙️ Configuration

Create a `.env` file with:

```
# Required
LLM_PROVIDER=openai
LLM_MODEL=gpt-4
LLM_API_KEY=sk-xxx

# Optional
GITHUB_TOKEN=ghp_xxx
HUGGINGFACE_API_KEY=hf_xxx
```

## 🚀 Quick Test

```bash
# Run example analysis
python examples.py

# Run tests
pytest tests/ -v

# Run with specific file
python -m src.main path/to/file.py
```

## 📝 Basic Usage

```python
import asyncio
from src.graph.orchestrator import AgentOrchestrator

async def main():
    orchestrator = AgentOrchestrator()
    
    code = "SELECT * FROM users WHERE id={user_id}"
    report = await orchestrator.process_code(code, "app.py")
    
    print(f"Risk Score: {report.overall_risk_score}")
    print(f"Vulnerabilities: {report.total_vulnerabilities}")

asyncio.run(main())
```

## 🔗 Integration with GitHub

```bash
# Set GitHub token
export GITHUB_TOKEN=your_token

# Analyze PR
python -c "
from src.tools.github_integration import GitHubIntegration
from src.graph.orchestrator import AgentOrchestrator

github = GitHubIntegration()
code = github.get_pr_content('owner', 'repo', 123)
report = orchestrator.process_code(code)
"
```

## 📊 Generate Reports

```python
from src.tools.report_generator import ReportGenerator

# Markdown
markdown = ReportGenerator.generate_markdown_report(report)
print(markdown)

# GitHub comment
comment = ReportGenerator.generate_github_comment(report)
print(comment)

# JSON
json_str = ReportGenerator.generate_json_report(report)
```

## 🧪 Run Tests

```bash
# All tests
pytest

# With coverage
pytest --cov=src tests/

# Specific test file
pytest tests/test_tools.py -v

# Async tests
pytest tests/test_integration.py -v
```

## 📚 Documentation

- Full README: [README.md](README.md)
- Implementation Plan: [ROTEIRO_IMPLEMENTACAO.md](ROTEIRO_IMPLEMENTACAO.md)
- Examples: [examples.py](examples.py)

## 🐛 Troubleshooting

### Bandit not installed
```bash
pip install bandit
```

### LLM API errors
- Check API key in `.env`
- Verify API quotas
- Check internet connection

### Import errors
```bash
pip install -e .
```

## 📞 Need Help?

- Check examples.py for usage patterns
- Review test files for test cases
- See README.md for detailed documentation

## 🎯 Next Steps

1. ✅ Configure your LLM provider
2. ✅ Run examples.py to test setup
3. ✅ Analyze your own code
4. ✅ Integrate with your CI/CD pipeline
