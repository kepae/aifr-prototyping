from rdflib import Graph
import semantic_aifr


def test_load_ontology():
    """Test loading the ontology from the package."""
    # Load the ontology
    g = semantic_aifr.load_ontology()

    # Basic validation
    assert isinstance(g, Graph)
    assert len(g) > 0

    # Check for key terms from AIFR ontology
    namespace = "https://example.org/aifr/"
    assert any(s for s in g.subjects() if str(s) == namespace)
    assert any(s for s in g.subjects() if str(s) == f"{namespace}FlawReport")

    # Serialize to different formats
    turtle = g.serialize(format="turtle")
    jsonld = g.serialize(format="json-ld")

    assert len(turtle) > 0
    assert len(jsonld) > 0


def test_create_flaw_report():
    """Test creating a flaw report and converting to different formats."""
    # Create a basic report
    report = semantic_aifr.create_flaw_report(
        reporter_id="tester@example.com",
        system_versions=["Test-Model-1.0"],
        description="Test flaw description",
        policy_violation="Violates test policy",
    )

    # Validate the report
    assert report.reporter_id == "tester@example.com"
    assert "Test-Model-1.0" in report.system_versions
    assert report.description == "Test flaw description"
    assert report.policy_violation == "Violates test policy"

    # Test conversion to JSON-LD
    # TODO: Test that JSON-LD is well-formed via RDFlib or some other tool
    jsonld = report.to_jsonld()
    assert isinstance(jsonld, dict)
    assert "@context" in jsonld
    assert jsonld["@type"] == "aifr:FlawReport"
    assert jsonld["reporter_id"] == "tester@example.com"

    # TODO: Expand these tests once vocabulary is more stable,
    # or find an automated way to write and assert them.
    # Test conversion to RDF
    graph = report.to_rdf()
    assert isinstance(graph, Graph)
    assert len(graph) > 0

    # Serialize to turtle
    turtle = graph.serialize(format="turtle")
    assert "tester@example.com" in turtle
    assert "Test-Model-1.0" in turtle


def test_serialization():
    """Test round-trip serialization (object -> RDF -> object)."""

    original = semantic_aifr.create_flaw_report(
        reporter_id="analyst@example.com",
        system_versions=["System-X-2.0", "System-Y-1.5"],
        description="Security vulnerability in parsing user input",
        policy_violation="Violates security guidelines",
        severity="High",
        prevalence="Low",
        impacts=["Security", "Privacy"],
        impacted_stakeholders=["Users", "Enterprise customers"],
        risk_source="Input validation"
    )
    
    graph = original.to_rdf()
    
    # Find the report URI
    report_uri = None
    for s in graph.subjects(None, None):
        if "/reports/" in str(s):
            report_uri = s
            break
    
    assert report_uri is not None
    
    # Reconstruct from RDF
    reconstructed = semantic_aifr.FlawReport.from_rdf(graph, report_uri)
    
    assert reconstructed.reporter_id == original.reporter_id
    assert reconstructed.system_versions == original.system_versions
    assert reconstructed.description == original.description
    assert reconstructed.policy_violation == original.policy_violation
    assert reconstructed.severity == original.severity
    assert reconstructed.prevalence == original.prevalence
    assert set(reconstructed.impacts or []) == set(original.impacts or [])
    assert set(reconstructed.impacted_stakeholders or []) == set(original.impacted_stakeholders or [])
    assert reconstructed.risk_source == original.risk_source
