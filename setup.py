from pathlib import Path

from setuptools import find_packages, setup

# Read README
long_description = Path("README.md").read_text(encoding="utf-8")

setup(
    name="jorginhoagent",
    version="0.1.0",
    description="Multi-Agent Code Security Analysis System using LLMs",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="JorginhoAgent Team",
    author_email="team@jorginhoagent.dev",
    url="https://github.com/seu-repo/jorginhoagent",
    license="MIT",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "langchain>=0.1.0",
        "langgraph>=0.1.0",
        "langsmith>=0.0.50",
        "langchain-openai>=0.0.1",
        "langchain-anthropic>=0.1.0",
        "huggingface-transformers>=4.30.0",
        "sentence-transformers>=2.2.0",
        "torch>=2.0.0",
        "bandit>=1.7.5",
        "PyGithub>=2.1.0",
        "pydantic>=2.0.0",
        "pydantic-settings>=2.0.0",
        "python-dotenv>=1.0.0",
        "loguru>=0.7.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "isort>=5.12.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Networking :: Monitoring",
    ],
    keywords="security code-analysis vulnerability detection llm ai agents",
    entry_points={
        "console_scripts": [
            "jorginhoagent=src.main:main",
        ],
    },
)
