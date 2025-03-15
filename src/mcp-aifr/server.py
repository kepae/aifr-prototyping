"""
MCP-AIFR Server: An MCP server for AI Flaw Reporting
"""

# TODO: Use Context to get concrete data from LLM/client?
# from mcp.server.fastmcp import FastMCP, Context
from mcp.server.fastmcp import FastMCP
from semantic_aifr import create_flaw_report, load_ontology

# Create server
mcp = FastMCP("AI Flaw Reporting", dependencies=["semantic-aifr"])

@mcp.tool()
def echo_tool(text: str) -> str:
    """Echo text for debugging that tool is connected correctly."""
    return text


@mcp.tool()
def create_flaw_report_jsonld(
    reporter_id: str,
    system_versions: list[str],
    description: str,
    policy_violation: str,
    severity: str = None,
    prevalence: str = None,
    impacts: list[str] = None,
    impacted_stakeholders: list[str] = None,
    risk_source: str = None,
) -> dict:
    """
    Create an AI flaw report and return it as JSON-LD.
    
    Args:
        reporter_id: ID of the person or entity reporting the flaw
        system_versions: List of affected system versions
        description: Detailed description of the flaw
        policy_violation: How this flaw violates policies
        severity: High/Medium/Low estimate of severity
        prevalence: How often the flaw might occur
        impacts: Areas impacted (privacy, bias, misinformation, etc)
        impacted_stakeholders: Who might be harmed if not addressed
        risk_source: Source of the risk (model, data, deployment, etc)
        
    Returns:
        A JSON-LD representation of the flaw report
    """
    report = create_flaw_report(
        reporter_id=reporter_id,
        system_versions=system_versions,
        description=description,
        policy_violation=policy_violation,
        severity=severity,
        prevalence=prevalence,
        impacts=impacts,
        impacted_stakeholders=impacted_stakeholders,
        risk_source=risk_source,
    )
    
    return report.to_jsonld()


@mcp.tool()
def create_rdf_flaw_report(
    reporter_id: str,
    system_versions: list[str],
    description: str,
    policy_violation: str,
    severity: str = None,
    prevalence: str = None,
    impacts: list[str] = None,
    impacted_stakeholders: list[str] = None,
    risk_source: str = None,
) -> str:
    """
    Create an AI flaw report and return it as RDF/Turtle.
    
    Args:
        reporter_id: ID of the person reporting the flaw
        system_versions: List of affected system versions
        description: Detailed description of the flaw
        policy_violation: How this flaw violates policies
        severity: High/Medium/Low estimate of severity
        prevalence: How often the flaw might occur
        impacts: Areas impacted (privacy, bias, misinformation, etc)
        impacted_stakeholders: Who might be harmed if not addressed
        risk_source: Source of the risk (model, data, deployment, etc)
        
    Returns:
        The flaw report serialized as RDF/Turtle
    """
    # Use the semantic-aifr package to create a flaw report
    report = create_flaw_report(
        reporter_id=reporter_id,
        system_versions=system_versions,
        description=description,
        policy_violation=policy_violation,
        severity=severity,
        prevalence=prevalence,
        impacts=impacts,
        impacted_stakeholders=impacted_stakeholders,
        risk_source=risk_source,
    )
    
    # Convert to RDF and serialize to Turtle format
    graph = report.to_rdf()
    return graph.serialize(format="turtle")


@mcp.resource("aifr://ontology")
def resource_aifr_ontology() -> str:
    """
    Resource for accessing the AIFR prototype ontology.
    
    Returns:
        The prototype AIFR ontology in Turtle format
    """
    # Load the ontology from the package
    g = load_ontology()
    
    # Serialize to Turtle format
    return g.serialize(format="turtle")


if __name__ == "__main__":
    mcp.run()