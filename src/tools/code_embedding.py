"""Code embedding utilities for RAG and similarity analysis."""

from typing import List, Optional

import numpy as np
from sentence_transformers import SentenceTransformer


class CodeEmbedder:
    """Generate embeddings for code snippets using CodeBERT."""

    def __init__(self, model_name: str = "microsoft/codebert-base"):
        """Initialize code embedder.

        Args:
            model_name: Hugging Face model identifier
        """
        self.model_name = model_name
        try:
            self.model = SentenceTransformer(model_name)
        except Exception as e:
            print(f"Warning: Could not load model {model_name}: {e}")
            print("Using default 'all-MiniLM-L6-v2' model instead")
            self.model = SentenceTransformer("all-MiniLM-L6-v2")

    def embed_code(self, code: str) -> np.ndarray:
        """Generate embedding for code snippet.

        Args:
            code: Code snippet to embed

        Returns:
            Embedding vector
        """
        return self.model.encode(code, convert_to_numpy=True)

    def embed_batch(self, code_snippets: List[str]) -> np.ndarray:
        """Generate embeddings for multiple code snippets.

        Args:
            code_snippets: List of code snippets

        Returns:
            Matrix of embeddings
        """
        return self.model.encode(code_snippets, convert_to_numpy=True)

    def similarity(self, code1: str, code2: str) -> float:
        """Calculate similarity between two code snippets.

        Args:
            code1: First code snippet
            code2: Second code snippet

        Returns:
            Similarity score (0-1)
        """
        embedding1 = self.embed_code(code1)
        embedding2 = self.embed_code(code2)
        return float(
            np.dot(embedding1, embedding2)
            / (np.linalg.norm(embedding1) * np.linalg.norm(embedding2))
        )

    def find_most_similar(
        self, query_code: str, code_snippets: List[str], top_k: int = 5
    ) -> List[tuple]:
        """Find most similar code snippets to a query.

        Args:
            query_code: Query code snippet
            code_snippets: List of code snippets to compare
            top_k: Number of top results to return

        Returns:
            List of tuples (similarity_score, code_snippet)
        """
        query_embedding = self.embed_code(query_code)
        similarities = []

        for code in code_snippets:
            code_embedding = self.embed_code(code)
            similarity = float(
                np.dot(query_embedding, code_embedding)
                / (np.linalg.norm(query_embedding) * np.linalg.norm(code_embedding))
            )
            similarities.append((similarity, code))

        # Sort by similarity descending
        similarities.sort(key=lambda x: x[0], reverse=True)
        return similarities[:top_k]


# Global instance
_embedder_instance = None


def get_code_embedder() -> CodeEmbedder:
    """Get global code embedder instance."""
    global _embedder_instance
    if _embedder_instance is None:
        _embedder_instance = CodeEmbedder()
    return _embedder_instance


if __name__ == "__main__":
    embedder = CodeEmbedder()

    # Test embedding
    code1 = """
    def query_users(user_id):
        query = f"SELECT * FROM users WHERE id={user_id}"
        return db.execute(query)
    """

    code2 = """
    def query_users_safe(user_id):
        query = "SELECT * FROM users WHERE id=?"
        return db.execute(query, (user_id,))
    """

    code3 = """
    def get_file(filename):
        os.system(f"cat {filename}")
    """

    # Test similarity
    sim_1_2 = embedder.similarity(code1, code2)
    sim_1_3 = embedder.similarity(code1, code3)

    print(f"Similarity between SQL codes: {sim_1_2:.4f}")
    print(f"Similarity between SQL and OS command: {sim_1_3:.4f}")

    # Test finding similar
    snippets = [code2, code3]
    similar = embedder.find_most_similar(code1, snippets, top_k=2)
    for score, snippet in similar:
        print(f"\nSimilarity: {score:.4f}")
        print(f"Code: {snippet[:50]}...")
