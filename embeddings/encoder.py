from sentence_transformers import SentenceTransformer

# Load lightweight 384-dimensional embedding model
encoder_model = SentenceTransformer("all-MiniLM-L6-v2")

def get_embedding(text: str) -> list[float]:
    """
    Converts input text into a 384-dimensional vector list.
    """
    embedding = encoder_model.encode(text)
    return embedding.tolist()