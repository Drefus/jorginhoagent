import os
from dotenv import load_dotenv

load_dotenv() 

from fastapi import FastAPI, Request, BackgroundTasks
from src.graph.orchestrator import AgentOrchestrator
from src.tools.report_generator import ReportGenerator
from src.tools.github_integration import GitHubIntegration

app = FastAPI(title="JorginhoAgent GitHub Webhook")

async def processar_pr_background(owner: str, repo_name: str, pr_number: int, pr_url: str):
    """Processa o PR usando as ferramentas do grupo e posta o resultado."""
    print(f"Iniciando análise do PR #{pr_number} em {repo_name}...")

    token = os.getenv("GITHUB_TOKEN")
    
    if not token:
        print("ERRO: Token não encontrado no ambiente!")
        return

    gh_integration = GitHubIntegration(token=token)

    # coleta o Diff do PR
    diff_conteudo = gh_integration.get_pr_content(owner, repo_name, pr_number)

    if not diff_conteudo:
        print("Nenhum código para analisar ou erro ao buscar o diff.")
        return

    # inicializa o orquestrador do LangGraph
    orchestrator = AgentOrchestrator()

    # executa a análise enviando as alterações do PR
    report = await orchestrator.process_code(
        code=diff_conteudo,
        file_path="Pull_Request_Diff", # identificador genérico para o diff completo
        pr_id=str(pr_number),
        pr_url=pr_url
    )

    if report:
        # gera o comentário formatado
        gh_comment = ReportGenerator.generate_github_comment(report)

        # posta o comentário geral no PR
        sucesso = gh_integration.post_comment(owner, repo_name, pr_number, gh_comment)

        if sucesso:
            print(f"Análise concluída e comentada no PR #{pr_number}!")
        else:
            print("Falha ao postar o comentário no GitHub.")

@app.post("/webhook")
async def github_webhook(request: Request, background_tasks: BackgroundTasks):
    """Recebe o payload do GitHub e despacha a tarefa de análise."""
    payload = await request.json()

    # Verifica se eh uma ação válida de PR (abertura ou novos commits)
    if "pull_request" in payload and payload.get("action") in ["opened", "synchronize"]:
        
        # gitHub retorna o nome completo no formato "dono/repositorio"
        repo_full = payload["repository"]["full_name"] 
        owner = repo_full.split("/")[0]
        repo_name = repo_full.split("/")[1]
        
        pr_number = payload["pull_request"]["number"]
        pr_url = payload["pull_request"]["html_url"]

        # add a tarefa pesada de IA para rodar em segundo plano
        background_tasks.add_task(processar_pr_background, owner, repo_name, pr_number, pr_url)

        return {"status": "Processamento iniciado", "pr": pr_number}

    return {"status": "Ignorado", "motivo": "Ação não é de abertura ou sincronização de PR."}