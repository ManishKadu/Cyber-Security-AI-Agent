"""
rag/cve_knowledge_base.py - RAG-Powered Threat Intelligence
============================================================
Downloads CVE data, creates embeddings, stores in ChromaDB,
and retrieves relevant vulnerabilities using semantic search.

This is REAL RAG (Retrieval-Augmented Generation):
  1. INDEXING:  CVE descriptions → OpenAI embeddings → ChromaDB
  2. RETRIEVAL: User query → embedding → similarity search → top K results
  3. GENERATION: Retrieved CVEs + query → LLM → informed analysis
"""

import os
import json
import hashlib
import requests
from typing import Optional

# ---------------------------------------------------------------------------
# We use chromadb for vector storage + OpenAI for embeddings
# ChromaDB handles: storing vectors, similarity search, metadata filtering
# ---------------------------------------------------------------------------
try:
    import chromadb
    from chromadb.utils import embedding_functions
    CHROMA_AVAILABLE = True
except ImportError:
    CHROMA_AVAILABLE = False

from utils.display import print_agent_header, print_status, print_error, console


# ---------------------------------------------------------------------------
# Sample CVE data (used when NVD API is unavailable or for offline demo)
# In production, you'd download thousands from NVD API
# ---------------------------------------------------------------------------

SAMPLE_CVES = [
    {
        "id": "CVE-2024-31497",
        "description": "PuTTY 0.68 through 0.80 has a critical vulnerability in ECDSA signing with NIST P-521 keys. The bias in the ECDSA nonce generation allows an attacker to recover the private key after observing approximately 60 signatures. This affects any SSH server authentication using ECDSA P-521 keys.",
        "severity": "CRITICAL",
        "score": 9.8,
        "software": "putty, openssh, ssh",
        "attack_vector": "NETWORK",
        "published": "2024-04-15",
    },
    {
        "id": "CVE-2024-3094",
        "description": "Malicious code was discovered in the upstream tarballs of xz-utils starting from version 5.6.0. The backdoor manipulates the liblzma build process to produce a modified library used by sshd authentication. This results in unauthorized remote access through systemd-patched OpenSSH servers.",
        "severity": "CRITICAL",
        "score": 10.0,
        "software": "xz, xz-utils, liblzma, openssh, sshd, linux",
        "attack_vector": "NETWORK",
        "published": "2024-03-29",
    },
    {
        "id": "CVE-2024-21762",
        "description": "FortiOS SSL VPN out-of-bound write vulnerability allows remote unauthenticated attackers to execute arbitrary code or commands via specially crafted HTTP requests. Fortinet confirmed this vulnerability is being exploited in the wild.",
        "severity": "CRITICAL",
        "score": 9.6,
        "software": "fortios, fortinet, ssl vpn, firewall",
        "attack_vector": "NETWORK",
        "published": "2024-02-09",
    },
    {
        "id": "CVE-2023-44487",
        "description": "The HTTP/2 protocol allows a denial of service via rapid stream resets known as Rapid Reset Attack. This affects Apache HTTP Server, nginx, Go net/http, Node.js, and many other HTTP/2 implementations. Attackers can generate enormous server load with minimal bandwidth.",
        "severity": "HIGH",
        "score": 7.5,
        "software": "apache, nginx, http2, nodejs, golang, web server",
        "attack_vector": "NETWORK",
        "published": "2023-10-10",
    },
    {
        "id": "CVE-2023-38545",
        "description": "curl before version 8.4.0 has a heap-based buffer overflow in the SOCKS5 proxy handshake. If curl is asked to pass along a hostname to the SOCKS5 proxy that is longer than 255 bytes, it can overflow a heap-based buffer and potentially execute arbitrary code.",
        "severity": "HIGH",
        "score": 8.8,
        "software": "curl, libcurl, http client",
        "attack_vector": "NETWORK",
        "published": "2023-10-11",
    },
    {
        "id": "CVE-2023-4966",
        "description": "Citrix NetScaler ADC and Gateway sensitive information disclosure vulnerability known as Citrix Bleed. Allows unauthenticated attackers to leak session tokens from memory, enabling session hijacking and full unauthorized access.",
        "severity": "CRITICAL",
        "score": 9.4,
        "software": "citrix, netscaler, gateway, adc, load balancer",
        "attack_vector": "NETWORK",
        "published": "2023-10-10",
    },
    {
        "id": "CVE-2024-27198",
        "description": "JetBrains TeamCity authentication bypass vulnerability allows unauthenticated remote attackers to perform admin actions including creating admin accounts, modifying build configurations, and executing arbitrary code on the server.",
        "severity": "CRITICAL",
        "score": 9.8,
        "software": "teamcity, jetbrains, ci/cd, build server",
        "attack_vector": "NETWORK",
        "published": "2024-03-04",
    },
    {
        "id": "CVE-2024-1709",
        "description": "ConnectWise ScreenConnect authentication bypass vulnerability allows unauthenticated attackers to gain administrative access. Proof of concept exploits were quickly available and active exploitation was observed within hours of disclosure.",
        "severity": "CRITICAL",
        "score": 10.0,
        "software": "connectwise, screenconnect, remote access, rmm",
        "attack_vector": "NETWORK",
        "published": "2024-02-19",
    },
    {
        "id": "CVE-2023-20198",
        "description": "Cisco IOS XE web UI privilege escalation vulnerability allows unauthenticated remote attackers to create admin accounts. Combined with CVE-2023-20273, enables full device takeover of Cisco networking equipment.",
        "severity": "CRITICAL",
        "score": 10.0,
        "software": "cisco, ios xe, networking, router, switch",
        "attack_vector": "NETWORK",
        "published": "2023-10-16",
    },
    {
        "id": "CVE-2024-23897",
        "description": "Jenkins CLI arbitrary file read vulnerability allows unauthenticated attackers to read files on the Jenkins controller file system. This can be leveraged to achieve remote code execution through reading cryptographic secrets.",
        "severity": "CRITICAL",
        "score": 9.8,
        "software": "jenkins, ci/cd, build server, devops",
        "attack_vector": "NETWORK",
        "published": "2024-01-24",
    },
    {
        "id": "CVE-2023-46747",
        "description": "F5 BIG-IP unauthenticated remote code execution vulnerability through the Traffic Management User Interface. Allows attackers to bypass authentication and execute arbitrary system commands on affected BIG-IP systems.",
        "severity": "CRITICAL",
        "score": 9.8,
        "software": "f5, big-ip, load balancer, application delivery",
        "attack_vector": "NETWORK",
        "published": "2023-10-26",
    },
    {
        "id": "CVE-2024-0204",
        "description": "GoAnywhere MFT authentication bypass vulnerability allows unauthenticated remote attackers to create admin accounts via the administration portal, leading to full system compromise.",
        "severity": "CRITICAL",
        "score": 9.8,
        "software": "goanywhere, mft, file transfer, fortra",
        "attack_vector": "NETWORK",
        "published": "2024-01-22",
    },
    {
        "id": "CVE-2023-22515",
        "description": "Atlassian Confluence Data Center and Server privilege escalation vulnerability. Allows remote unauthenticated attackers to create administrator accounts and access Confluence instances. Actively exploited as a zero-day.",
        "severity": "CRITICAL",
        "score": 10.0,
        "software": "confluence, atlassian, wiki, collaboration",
        "attack_vector": "NETWORK",
        "published": "2023-10-04",
    },
    {
        "id": "CVE-2024-6387",
        "description": "OpenSSH server signal handler race condition vulnerability known as regreSSHion. A remote unauthenticated attacker can exploit this to execute arbitrary code as root on affected Linux systems running glibc-based sshd.",
        "severity": "HIGH",
        "score": 8.1,
        "software": "openssh, sshd, ssh, linux, glibc",
        "attack_vector": "NETWORK",
        "published": "2024-07-01",
    },
    {
        "id": "CVE-2024-4577",
        "description": "PHP CGI argument injection vulnerability affects Windows installations running in CGI mode. Allows remote unauthenticated attackers to execute arbitrary code by injecting arguments through specially crafted URLs.",
        "severity": "CRITICAL",
        "score": 9.8,
        "software": "php, cgi, windows, web server, apache",
        "attack_vector": "NETWORK",
        "published": "2024-06-06",
    },
]


class CVEKnowledgeBase:
    """
    RAG-powered CVE knowledge base using ChromaDB.

    Flow:
        1. index_cves()    → Store CVE embeddings in ChromaDB
        2. search()        → Semantic similarity search
        3. get_rag_context() → Format results for LLM prompt injection
    """

    def __init__(self, persist_dir: str = "./data/chroma_db"):
        """
        Initialize the knowledge base.

        Args:
            persist_dir: Where ChromaDB stores its data on disk
        """
        self.persist_dir = persist_dir

        if not CHROMA_AVAILABLE:
            print_error("ChromaDB not installed. Run: pip install chromadb")
            self.client = None
            self.collection = None
            return

        # Initialize ChromaDB with persistent storage
        # This means your embeddings survive between runs (no re-indexing!)
        self.client = chromadb.PersistentClient(path=persist_dir)

        # Choose embedding function based on available API key
        api_key = os.getenv("OPENAI_API_KEY")
        if api_key and api_key.startswith("sk-"):
            # Use OpenAI embeddings (1536 dimensions, best quality)
            self.embed_fn = embedding_functions.OpenAIEmbeddingFunction(
                api_key=api_key,
                model_name="text-embedding-3-small",  # $0.02 per 1M tokens — very cheap
            )
            self._embed_source = "OpenAI text-embedding-3-small"
        else:
            # Fallback: ChromaDB's default (runs locally, no API key needed)
            self.embed_fn = embedding_functions.DefaultEmbeddingFunction()
            self._embed_source = "ChromaDB default (local, no API key)"

        # Create or get the collection
        self.collection = self.client.get_or_create_collection(
            name="cve_knowledge_base",
            embedding_function=self.embed_fn,
            metadata={"description": "CVE vulnerability database for RAG"},
        )

    def index_cves(self, cves: list[dict] = None, force_reindex: bool = False) -> int:
        """
        Index CVE data into ChromaDB.

        This is the INDEXING step of RAG:
          CVE text → Embedding model → Vector → ChromaDB

        Args:
            cves: List of CVE dicts. Uses SAMPLE_CVES if None.
            force_reindex: If True, delete existing data and re-index.

        Returns:
            Number of CVEs indexed
        """
        if not self.collection:
            return 0

        if cves is None:
            cves = SAMPLE_CVES

        # Check if already indexed (skip expensive re-embedding)
        existing = self.collection.count()
        if existing > 0 and not force_reindex:
            print_status(f"Knowledge base already has {existing} CVEs indexed")
            print_status(f"Embedding model: {self._embed_source}")
            return existing

        if force_reindex and existing > 0:
            # Delete and recreate
            self.client.delete_collection("cve_knowledge_base")
            self.collection = self.client.get_or_create_collection(
                name="cve_knowledge_base",
                embedding_function=self.embed_fn,
            )

        console.print(f"  [bold]Indexing {len(cves)} CVEs into ChromaDB...[/bold]")
        console.print(f"  Embedding model: {self._embed_source}")

        # Prepare data for ChromaDB
        ids = []
        documents = []
        metadatas = []

        for cve in cves:
            cve_id = cve["id"]
            ids.append(cve_id)

            # The DOCUMENT is what gets embedded (converted to a vector)
            # We combine multiple fields for richer semantic search
            doc = (
                f"{cve['description']} "
                f"Software affected: {cve.get('software', 'unknown')}. "
                f"Severity: {cve.get('severity', 'unknown')}. "
                f"CVSS Score: {cve.get('score', 'N/A')}."
            )
            documents.append(doc)

            # METADATA is stored alongside but NOT embedded
            # Used for filtering (e.g., "only CRITICAL CVEs")
            metadatas.append({
                "severity": cve.get("severity", "UNKNOWN"),
                "score": float(cve.get("score", 0)),
                "software": cve.get("software", ""),
                "attack_vector": cve.get("attack_vector", ""),
                "published": cve.get("published", ""),
            })

        # Add to ChromaDB — this triggers the embedding API call
        self.collection.add(
            ids=ids,
            documents=documents,
            metadatas=metadatas,
        )

        print_status(f"Indexed {len(cves)} CVEs successfully")
        return len(cves)

    def search(self, query: str, top_k: int = 5, min_score: float = 0.0) -> list[dict]:
        """
        Semantic search for relevant CVEs.

        This is the RETRIEVAL step of RAG:
          Query → Embedding → Similarity search → Top K results

        The magic: "apache web server exploit" will find CVEs about
        HTTP/2 rapid reset, even though those exact words don't appear
        in the CVE description. Embeddings capture MEANING, not keywords.

        Args:
            query: Natural language search (e.g., "SSH vulnerabilities")
            top_k: How many results to return
            min_score: Minimum similarity threshold (0-1, higher = stricter)

        Returns:
            List of matching CVE dicts with similarity scores
        """
        if not self.collection or self.collection.count() == 0:
            return []

        # ChromaDB converts your query to an embedding and finds
        # the closest vectors in the database
        results = self.collection.query(
            query_texts=[query],
            n_results=min(top_k, self.collection.count()),
            include=["documents", "metadatas", "distances"],
        )

        # Format results
        matches = []
        for i in range(len(results["ids"][0])):
            # ChromaDB returns L2 distance — lower = more similar
            # Convert to a 0-1 similarity score for easier understanding
            distance = results["distances"][0][i]
            similarity = max(0, 1 - (distance / 2))  # rough conversion

            if similarity >= min_score:
                matches.append({
                    "cve_id": results["ids"][0][i],
                    "description": results["documents"][0][i],
                    "metadata": results["metadatas"][0][i],
                    "similarity_score": round(similarity, 3),
                })

        return matches

    def get_rag_context(self, software_stack: list[str], top_k: int = 5) -> str:
        """
        Get RAG context for LLM prompt augmentation.

        This is the AUGMENTATION step of RAG:
          Search results → Formatted text → Injected into LLM prompt

        Instead of the LLM hallucinating CVE numbers, it gets REAL data
        from our knowledge base, grounding its response in facts.

        Args:
            software_stack: List of software to check
            top_k: Max CVEs per software item

        Returns:
            Formatted string ready to inject into LLM prompt
        """
        all_results = []

        for software in software_stack:
            results = self.search(software, top_k=top_k)
            if results:
                all_results.append(f"\n### CVEs related to: {software}")
                for r in results:
                    meta = r["metadata"]
                    all_results.append(
                        f"- **{r['cve_id']}** (Score: {meta.get('score', 'N/A')}, "
                        f"Severity: {meta.get('severity', '?')}, "
                        f"Similarity: {r['similarity_score']:.1%})\n"
                        f"  {r['description'][:200]}..."
                    )

        if not all_results:
            return "No relevant CVEs found in knowledge base."

        return (
            "## Retrieved CVE Intelligence (from RAG knowledge base)\n"
            + "\n".join(all_results)
        )

    def get_stats(self) -> dict:
        """Get knowledge base statistics."""
        if not self.collection:
            return {"status": "unavailable", "count": 0}
        return {
            "status": "ready",
            "count": self.collection.count(),
            "embedding_model": self._embed_source,
            "persist_dir": self.persist_dir,
        }
