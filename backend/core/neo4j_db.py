"""
neo4j_db.py — Neo4j connection module for TraceShield X++
Handles driver lifecycle, query execution, and connection health checks.
"""

import os
from typing import List, Dict, Any

from neo4j import GraphDatabase
from dotenv import load_dotenv

load_dotenv()

_driver = None

_URI      = os.getenv("NEO4J_URI",      "bolt://localhost:7687")
_USER     = os.getenv("NEO4J_USER",     "neo4j")
_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")


def get_driver():
    """
    Return a singleton Neo4j driver instance.

    Returns:
        neo4j.Driver or None if connection fails.
    """
    global _driver
    if _driver is not None:
        return _driver
    try:
        _driver = GraphDatabase.driver(
            _URI,
            auth=(_USER, _PASSWORD),
            connection_timeout=3,
            max_connection_lifetime=60,
        )
        return _driver
    except Exception as e:
        print(f"[neo4j_db] WARNING: Could not create Neo4j driver: {e}")
        return None


def run_query(query: str, parameters: Dict = {}) -> List[Dict[str, Any]]:
    """
    Execute a Cypher query and return results as a list of dicts.

    Args:
        query:      Cypher query string.
        parameters: Optional query parameters.

    Returns:
        List of result records as dicts, or [] on failure.
    """
    driver = get_driver()
    if driver is None:
        print("[neo4j_db] WARNING: No driver available — skipping query.")
        return []
    try:
        with driver.session() as session:
            result = session.run(query, parameters)
            return [record.data() for record in result]
    except Exception as e:
        print(f"[neo4j_db] WARNING: Query failed: {e}")
        return []


def test_connection() -> bool:
    """
    Verify Neo4j connectivity by running a trivial query.

    Returns:
        True if connection succeeds, False otherwise.
    """
    try:
        result = run_query("RETURN 1 AS ok")
        return len(result) > 0
    except Exception as e:
        print(f"[neo4j_db] WARNING: Connection test failed: {e}")
        return False


def close_driver() -> None:
    """
    Close the Neo4j driver and release resources.
    """
    global _driver
    if _driver is not None:
        try:
            _driver.close()
        except Exception as e:
            print(f"[neo4j_db] WARNING: Error closing driver: {e}")
        finally:
            _driver = None
