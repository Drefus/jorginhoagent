"""GitHub API integration."""

from typing import List, Optional

try:
    from github import Github, PullRequest
except ImportError:
    print("PyGithub not installed. Install with: pip install PyGithub")
    Github = None
    PullRequest = None

from src.config.settings import get_settings


class GitHubIntegration:
    """Integration with GitHub API for PR analysis."""

    def __init__(self, token: Optional[str] = None):
        if Github is None:
            raise ImportError("PyGithub not installed")

        self.settings = get_settings()
        token = token or self.settings.github_token
        
        if not token:
            raise ValueError("GitHub token not provided")

        # Use o formato de autenticação de Token explícito da biblioteca
        from github import Auth
        auth = Auth.Token(token)
        
        # Conecte-se explicitamente à base URL da API
        self.github = Github(auth=auth, base_url="https://api.github.com")
        
        print("DEBUG: GitHub client inicializado com Auth.Token e base_url.")

    def get_pr_files(self, owner: str, repo: str, pr_number: int) -> dict:
        """Get files changed in a pull request.

        Args:
            owner: Repository owner
            repo: Repository name
            pr_number: Pull request number

        Returns:
            Dictionary with file paths and their changes
        """
        try:
            repo_obj = self.github.get_repo(f"{owner}/{repo}")            
            pr = repo_obj.get_pull(pr_number)

            files_data = {}
            for file in pr.get_files():
                files_data[file.filename] = {
                    "patch": file.patch,
                    "status": file.status,
                    "additions": file.additions,
                    "deletions": file.deletions,
                }
            return files_data
        except Exception as e:
            print(f"Error fetching PR files: {e}")
            return {}

    def get_pr_content(self, owner: str, repo: str, pr_number: int) -> str:
        """Get full diff of a pull request using direct requests."""
        import requests
        import os
        
        token = os.getenv("GITHUB_TOKEN")
        
        print(f"DEBUG: Token lido tem {len(str(token))} caracteres. Começa com: {str(token)[:6]}")
        
        if not token:
            print("ERRO: GITHUB_TOKEN vazio!")
            return ""
        
        
        if not token:
            print("ERRO: GITHUB_TOKEN não encontrado no arquivo .env!")
            return ""
        
        # URL da API do GitHub para os arquivos do PR
        url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/files"
        
        # O cabeçalho de autenticação usa o token dinâmico
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        try:
            response = requests.get(url, headers=headers)
            
            if response.status_code != 200:
                print(f"DEBUG ERRO: Status {response.status_code} - {response.text}")
                return ""
            
            files = response.json()
            
            diff_content = ""
            for file in files:
                patch = file.get("patch", "")
                if patch:
                    diff_content += f"\n--- {file.get('filename')}\n"
                    diff_content += patch
            
            return diff_content
            
        except Exception as e:
            print(f"Error fetching PR content: {e}")
            return ""

    def post_comment(
        self, owner: str, repo: str, pr_number: int, comment: str
    ) -> bool:
        """Post a comment on a pull request.

        Args:
            owner: Repository owner
            repo: Repository name
            pr_number: Pull request number
            comment: Comment text

        Returns:
            True if successful, False otherwise
        """
        try:
            repo_obj = self.github.get_repo(f"{owner}/{repo}")
            pr = repo_obj.get_pull(pr_number)
            pr.create_issue_comment(comment)
            return True
        except Exception as e:
            print(f"Error posting comment: {e}")
            return False

    def post_review_comment(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        file_path: str,
        line_number: int,
        comment: str,
    ) -> bool:
        """Post an inline comment on a specific line in a PR.

        Args:
            owner: Repository owner
            repo: Repository name
            pr_number: Pull request number
            file_path: File path to comment on
            line_number: Line number in the file
            comment: Comment text

        Returns:
            True if successful, False otherwise
        """
        try:
            repo_obj = self.github.get_repo(f"{owner}/{repo}")
            pr = repo_obj.get_pull(pr_number)

            # Note: This creates a review comment, not a standard comment
            pr.create_review_comment(
                body=comment, commit_id=pr.head.sha, path=file_path, line=line_number
            )
            return True
        except Exception as e:
            print(f"Error posting review comment: {e}")
            return False

    def request_review(
        self, owner: str, repo: str, pr_number: int, reviewers: List[str]
    ) -> bool:
        """Request reviewers on a pull request.

        Args:
            owner: Repository owner
            repo: Repository name
            pr_number: Pull request number
            reviewers: List of reviewer usernames

        Returns:
            True if successful, False otherwise
        """
        try:
            repo_obj = self.github.get_repo(f"{owner}/{repo}")
            pr = repo_obj.get_pull(pr_number)
            pr.create_review_request(reviewers=reviewers)
            return True
        except Exception as e:
            print(f"Error requesting review: {e}")
            return False

    def get_pr_info(self, owner: str, repo: str, pr_number: int) -> dict:
        """Get information about a pull request.

        Args:
            owner: Repository owner
            repo: Repository name
            pr_number: Pull request number

        Returns:
            Dictionary with PR information
        """
        try:
            repo_obj = self.github.get_repo(f"{owner}/{repo}")
            pr = repo_obj.get_pull(pr_number)

            return {
                "number": pr.number,
                "title": pr.title,
                "body": pr.body,
                "state": pr.state,
                "author": pr.user.login,
                "created_at": pr.created_at,
                "updated_at": pr.updated_at,
                "base_branch": pr.base.ref,
                "head_branch": pr.head.ref,
                "changed_files": pr.changed_files,
                "additions": pr.additions,
                "deletions": pr.deletions,
            }
        except Exception as e:
            print(f"Error getting PR info: {e}")
            return {}


# Global instance
_github_instance = None


def get_github_integration() -> Optional[GitHubIntegration]:
    """Get global GitHub integration instance."""
    global _github_instance
    if _github_instance is None:
        try:
            _github_instance = GitHubIntegration()
        except (ImportError, ValueError):
            return None
    return _github_instance
