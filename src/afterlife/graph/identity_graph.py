"""Cross-source identity graph.

Links identities across systems by shared correlation keys (primarily email,
secondarily name) so that one human's footprint can be queried as a unit.

Built lazily from the SQLite store. Backed by NetworkX. Serves as the substrate
for cross-source rules like OFFBOARDED-OWNER and ORPHANED-GITHUB.

TODO Week 5: replace this module-level docstring with a real implementation.
Sketch:

    G = nx.MultiDiGraph()
    # nodes: identities (typed by source); credentials (typed by source + kind)
    # edges:
    #   identity -[owns]-> credential
    #   identity -[same_person_as]-> identity   (email match, name match, fuzzy)
    # queries:
    #   blast_radius(identity_id) -> all reachable credentials
    #   stale_components() -> connected components where every identity is deprovisioned
"""
