"""
ChromaDB Vector Index for MITRE ATLAS Techniques
Persona C - Nandu Suraj (The Analyst)

Builds and queries an offline persistent vector index of MITRE ATLAS techniques 
using ChromaDB and SentenceTransformer embeddings.
"""

import os
import chromadb
from typing import List, Dict, Optional
from embeddings.encoder import get_embedding
from intelligence.atlas_data import get_atlas_techniques, get_technique_by_id

# Persistence directory for ChromaDB
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CHROMA_DIR = os.path.join(BASE_DIR, "intelligence", "chroma_store")
COLLECTION_NAME = "mitre_atlas_techniques"

def get_chroma_client() -> chromadb.PersistentClient:
    """
    Returns a persistent ChromaDB client pointing to intelligence/chroma_store.
    """
    os.makedirs(CHROMA_DIR, exist_ok=True)
    return chromadb.PersistentClient(path=CHROMA_DIR)

def get_atlas_collection(client: Optional[chromadb.PersistentClient] = None):
    """
    Gets or creates the 'mitre_atlas_techniques' collection using cosine similarity.
    """
    if client is None:
        client = get_chroma_client()
    return client.get_or_create_collection(
        name=COLLECTION_NAME,
        metadata={"hnsw:space": "cosine"}
    )

def build_atlas_index(force_rebuild: bool = False) -> int:
    """
    Populates ChromaDB with MITRE ATLAS descriptions and attack patterns.
    Returns the total number of indexed vectors.
    """
    client = get_chroma_client()
    collection = get_atlas_collection(client)
    
    current_count = collection.count()
    if current_count > 0 and not force_rebuild:
        return current_count
        
    if force_rebuild and current_count > 0:
        client.delete_collection(COLLECTION_NAME)
        collection = get_atlas_collection(client)
        
    techniques = get_atlas_techniques()
    
    doc_ids = []
    documents = []
    metadatas = []
    embeddings = []
    
    for tech in techniques:
        tech_id = tech["id"]
        name = tech["name"]
        tactic = tech["tactic"]
        sensitivity = float(tech["sensitivity"])
        description = tech["description"]
        
        # 1. Index the canonical description
        desc_id = f"{tech_id}_desc"
        doc_ids.append(desc_id)
        desc_text = f"{name} ({tech_id}): {description}"
        documents.append(desc_text)
        metadatas.append({
            "technique_id": tech_id,
            "name": name,
            "tactic": tactic,
            "sensitivity": sensitivity,
            "entry_type": "description"
        })
        embeddings.append(get_embedding(desc_text))
        
        # 2. Index representative attack queries/payloads for high semantic fidelity
        for idx, ex_query in enumerate(tech.get("example_queries", [])):
            ex_id = f"{tech_id}_ex_{idx}"
            doc_ids.append(ex_id)
            documents.append(ex_query)
            metadatas.append({
                "technique_id": tech_id,
                "name": name,
                "tactic": tactic,
                "sensitivity": sensitivity,
                "entry_type": "example_query"
            })
            embeddings.append(get_embedding(ex_query))
            
    # Upsert in batch to ChromaDB
    collection.upsert(
        ids=doc_ids,
        documents=documents,
        metadatas=metadatas,
        embeddings=embeddings
    )
    
    return collection.count()

def match_atlas_technique(
    prompt: str,
    top_k: int = 3,
    distance_threshold: float = 0.58,
    query_embedding: Optional[List[float]] = None
) -> Dict:
    """
    Semantically searches the MITRE ATLAS index for closest attack pattern matches.

    Args:
        prompt: User message / suspicious query to classify.
        top_k: Number of candidate techniques to retrieve.
        distance_threshold: Maximum cosine distance to qualify as an attack match
                            (Distance 0.58 = Similarity 0.42).
        query_embedding: Optional precomputed embedding of `prompt`. The gateway
                         already embeds every message for drift scoring, so passing
                         it here avoids a redundant second encode on the hot path.

    Returns:
        Structured match dictionary with confidence and sensitivity scores.
    """
    collection = get_atlas_collection()

    # Check if index needs building
    if collection.count() == 0:
        build_atlas_index()

    query_emb = query_embedding if query_embedding else get_embedding(prompt)

    results = collection.query(
        query_embeddings=[query_emb],
        n_results=top_k,
        include=["metadatas", "distances", "documents"]
    )
    
    if not results or not results["ids"] or not results["ids"][0]:
        return {
            "matched": False,
            "attack_technique": None,
            "attack_confidence": 0.0,
            "sensitivity": 0.0,
            "tactic": None,
            "top_matches": []
        }
        
    ids = results["ids"][0]
    distances = results["distances"][0]
    metadatas = results["metadatas"][0]
    
    top_matches = []
    for i in range(len(ids)):
        dist = float(distances[i])
        # Cosine similarity confidence (1.0 - cosine_distance)
        conf = round(max(0.0, 1.0 - dist), 4)
        meta = metadatas[i]
        top_matches.append({
            "technique_id": meta["technique_id"],
            "name": meta["name"],
            "tactic": meta["tactic"],
            "sensitivity": meta["sensitivity"],
            "confidence": conf,
            "distance": round(dist, 4)
        })
        
    # Best candidate match
    best = top_matches[0]
    best_dist = best["distance"]
    best_conf = best["confidence"]
    
    is_attack_match = (best_dist <= distance_threshold)
    
    return {
        "matched": is_attack_match,
        "attack_technique": f"{best['technique_id']} - {best['name']}" if is_attack_match else None,
        "technique_id": best["technique_id"] if is_attack_match else None,
        "technique_name": best["name"] if is_attack_match else None,
        "attack_confidence": best_conf if is_attack_match else 0.0,
        "sensitivity": best["sensitivity"] if is_attack_match else 0.0,
        "tactic": best["tactic"] if is_attack_match else None,
        "best_raw_distance": best_dist,
        "top_matches": top_matches
    }
