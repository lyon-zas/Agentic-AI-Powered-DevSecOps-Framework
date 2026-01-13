"""
GitHub API Client for creating branches, commits, and pull requests.
"""
from typing import Dict, List, Optional
from github import Github, GithubException
from datetime import datetime
import os


class GitHubClient:
    """Wrapper for GitHub API operations."""
    
    def __init__(self, token: Optional[str] = None):
        """
        Initialize GitHub client.
        
        Args:
            token: GitHub personal access token. If None, reads from GITHUB_TOKEN env var.
        """
        self.token = token or os.getenv('GITHUB_TOKEN')
        if not self.token:
            raise ValueError("GitHub token is required. Set GITHUB_TOKEN environment variable.")
        
        self.github = Github(self.token)
    
    def get_repo(self, repo_name: str):
        """
        Get repository object.
        
        Args:
            repo_name: Repository name in format 'owner/repo'
        
        Returns:
            Repository object
        """
        try:
            return self.github.get_repo(repo_name)
        except GithubException as e:
            raise ValueError(f"Failed to get repository {repo_name}: {e}")
    
    def create_branch(self, repo_name: str, base_branch: str, new_branch: str) -> Dict:
        """
        Create a new branch from base branch.
        
        Args:
            repo_name: Repository name in format 'owner/repo'
            base_branch: Name of the base branch (e.g., 'main')
            new_branch: Name of the new branch to create
        
        Returns:
            Dictionary with branch info
        """
        try:
            repo = self.get_repo(repo_name)
            
            # Get the base branch reference
            base_ref = repo.get_git_ref(f"heads/{base_branch}")
            base_sha = base_ref.object.sha
            
            # Create new branch
            new_ref = repo.create_git_ref(
                ref=f"refs/heads/{new_branch}",
                sha=base_sha
            )
            
            return {
                "success": True,
                "branch_name": new_branch,
                "sha": base_sha,
                "ref": new_ref.ref
            }
        except GithubException as e:
            return {
                "success": False,
                "error": str(e),
                "message": f"Failed to create branch {new_branch}: {e}"
            }
    
    def commit_files(
        self,
        repo_name: str,
        branch: str,
        files: Dict[str, str],
        commit_message: str
    ) -> Dict:
        """
        Commit multiple files to a branch.
        
        Args:
            repo_name: Repository name in format 'owner/repo'
            branch: Branch name to commit to
            files: Dictionary of file_path -> file_content
            commit_message: Commit message
        
        Returns:
            Dictionary with commit info
        """
        try:
            from github import InputGitTreeElement
            
            repo = self.get_repo(repo_name)
            
            # Get the branch reference
            ref = repo.get_git_ref(f"heads/{branch}")
            base_commit = repo.get_git_commit(ref.object.sha)
            base_tree = base_commit.tree
            
            # Create tree elements using InputGitTreeElement
            tree_elements = []
            for file_path, content in files.items():
                tree_elements.append(InputGitTreeElement(
                    path=file_path,
                    mode="100644",
                    type="blob",
                    content=content
                ))
            
            # Create new tree based on base tree
            new_tree = repo.create_git_tree(tree_elements, base_tree)
            
            # Create commit
            commit = repo.create_git_commit(
                message=commit_message,
                tree=new_tree,
                parents=[base_commit]
            )
            
            # Update reference
            ref.edit(commit.sha)
            
            return {
                "success": True,
                "commit_sha": commit.sha,
                "commit_message": commit_message,
                "files_committed": list(files.keys())
            }
        except GithubException as e:
            return {
                "success": False,
                "error": str(e.data) if hasattr(e, 'data') else str(e),
                "message": f"Failed to commit files: {e}"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "message": f"Failed to commit files: {e}"
            }
    
    def create_pull_request(
        self,
        repo_name: str,
        title: str,
        body: str,
        head_branch: str,
        base_branch: str = "main",
        labels: Optional[List[str]] = None
    ) -> Dict:
        """
        Create a pull request.
        
        Args:
            repo_name: Repository name in format 'owner/repo'
            title: PR title
            body: PR description
            head_branch: Source branch (with changes)
            base_branch: Target branch (default: 'main')
            labels: Optional list of label names to add
        
        Returns:
            Dictionary with PR info including URL
        """
        try:
            repo = self.get_repo(repo_name)
            
            # Create PR
            pr = repo.create_pull(
                title=title,
                body=body,
                head=head_branch,
                base=base_branch
            )
            
            # Add labels if provided
            if labels:
                try:
                    pr.add_to_labels(*labels)
                except GithubException:
                    # Labels might not exist, ignore error
                    pass
            
            return {
                "success": True,
                "pr_number": pr.number,
                "pr_url": pr.html_url,
                "pr_title": pr.title,
                "head_branch": head_branch,
                "base_branch": base_branch
            }
        except GithubException as e:
            error_msg = str(e)
            error_data = getattr(e, 'data', {})
            status = getattr(e, 'status', 'unknown')
            
            # Provide helpful message for 403 errors
            if status == 403:
                error_msg = (
                    f"403 Forbidden: {error_data.get('message', 'Access denied')}. "
                    "To fix: Go to Repository Settings → Actions → General → "
                    "'Workflow permissions' → Enable 'Allow GitHub Actions to create and approve pull requests'"
                )
            
            return {
                "success": False,
                "error": f"{status}: {error_data.get('message', error_msg)}",
                "message": error_msg
            }
    
    def create_branch_and_commit(
        self,
        repo_name: str,
        files: Dict[str, str],
        branch_name: str,
        commit_message: str,
        base_branch: str = "main"
    ) -> Dict:
        """
        Helper method to create a branch and commit files in one go.
        
        Args:
            repo_name: Repository name
            files: Files to commit
            branch_name: New branch name
            commit_message: Commit message
            base_branch: Base branch to branch from
        
        Returns:
            Combined result dictionary
        """
        # Create branch
        branch_result = self.create_branch(repo_name, base_branch, branch_name)
        if not branch_result["success"]:
            return branch_result
        
        # Commit files
        commit_result = self.commit_files(repo_name, branch_name, files, commit_message)
        if not commit_result["success"]:
            return commit_result
        
        return {
            "success": True,
            "branch": branch_result,
            "commit": commit_result
        }
