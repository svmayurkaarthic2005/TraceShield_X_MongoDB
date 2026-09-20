from neo4j import GraphDatabase

d = GraphDatabase.driver("neo4j://127.0.0.1:7687", auth=("neo4j", "12345678"))
with d.session() as s:
    s.run("MATCH ()-[r:ATTACKED]->() WHERE r.reason IS NULL SET r.reason = 'combined_score'")
    s.run("MATCH ()-[r:BLOCKED]->() WHERE r.reason IS NULL SET r.reason = 'combined_score'")
    s.run("MATCH ()-[r:REDIRECTED_TO]->() WHERE r.reason IS NULL SET r.reason = 'combined_score'")
    s.run("MATCH ()-[r]->() WHERE r.timestamp IS NULL SET r.timestamp = '2026-01-01T00:00:00'")
    print("Patched legacy None values")
d.close()
