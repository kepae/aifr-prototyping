"""Main module for semantic-aifr package."""

import os
import importlib.resources as pkg_resources  # to directly read the .ttl file
from datetime import datetime
from enum import Enum
from typing import List, Optional, Union
from pydantic import BaseModel, Field
import uuid
from rdflib import Graph, Literal, Namespace, URIRef
from rdflib.namespace import RDF, RDFS, XSD


# Define the AIFR namespace
AIFR = Namespace("https://example.org/aifr/")

# Status enum based on the ontology
class ReportStatus(str, Enum):
    SUBMITTED = "Submitted"
    UNDER_INVESTIGATION = "Under Investigation"
    FIXED = "Fixed"
    WONT_FIX = "Won't Fix"


def load_ontology() -> Graph:
    """
    Load the AIFR ontology from the TTL file.
    """
    g = Graph()
    
    # Get the path to the ontology file
    try:
        with pkg_resources.files('semantic_aifr.prototype.ontology').joinpath('aifr.ttl').open('rb') as f:
            g.parse(file=f, format='turtle')
    except (AttributeError, ImportError):
        # Fallback for older Python versions
        ontology_path = os.path.join(
            os.path.dirname(__file__), 
            'prototype',
            'ontology', 
            'aifr.ttl'
        )
        g.parse(ontology_path, format='turtle')
    
    return g


class FlawReport(BaseModel):
    """Basic AI Flaw Report structure."""
    
    # TODO: More gracefully handle/specify required vs optional fields.
    report_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    reporter_id: str
    system_versions: List[str]
    status: ReportStatus = ReportStatus.SUBMITTED
    timestamp: datetime = Field(default_factory=datetime.now)
    description: str
    policy_violation: str
    
    # Optional fields from fig 3 in the AIFR paper
    severity: Optional[str] = None
    prevalence: Optional[str] = None
    impacts: Optional[List[str]] = None
    impacted_stakeholders: Optional[List[str]] = None
    risk_source: Optional[str] = None
    
    def to_jsonld(self) -> dict:
        """Convert the flaw report to JSON-LD format."""
        # Create a simple JSON-LD context
        context = {
            "@context": {
                "aifr": "https://example.org/aifr/",
                "xsd": "http://www.w3.org/2001/XMLSchema#",
                "report_id": "aifr:reportId",
                "reporter_id": "aifr:reporterId",
                "system_versions": "aifr:systemVersion",
                "status": "aifr:status",
                "timestamp": {"@id": "aifr:timestamp", "@type": "xsd:dateTime"},
                "description": "aifr:description",
                "policy_violation": "aifr:policyViolation",
                "severity": "aifr:severity",
                "prevalence": "aifr:prevalence",
                "impacts": "aifr:impact",
                "impacted_stakeholders": "aifr:impactedStakeholder",
                "risk_source": "aifr:riskSource"
            }
        }
        
        # Dump all self fields to dict.
        data = self.model_dump(exclude_none=True)
        if "timestamp" in data:
            data["timestamp"] = self.timestamp.isoformat()
        
        # Add type information
        data["@type"] = "aifr:FlawReport"
        # TODO: Temporary ID format, use better type other than string?
        # TODO: maybe not IRI?
        data["@id"] = f"https://example.org/aifr/reports/{self.report_id}"
        
        return {**context, **data}
    
    def to_rdf(self) -> Graph:
        """Convert the flaw report to RDF format."""
        g = Graph()
        
        # Bind namespaces
        g.bind("aifr", AIFR)
        g.bind("xsd", XSD)
        
        # Create URIRef for this report
        report_uri = URIRef(f"https://example.org/aifr/reports/{self.report_id}")
        
        # Add basic triples
        g.add((report_uri, RDF.type, AIFR.FlawReport))
        g.add((report_uri, AIFR.reportId, Literal(self.report_id)))
        g.add((report_uri, AIFR.reporterId, Literal(self.reporter_id)))
        
        for sys_ver in self.system_versions:
            g.add((report_uri, AIFR.systemVersion, Literal(sys_ver)))
            
        g.add((report_uri, AIFR.status, Literal(self.status.value)))
        g.add((report_uri, AIFR.timestamp, Literal(self.timestamp.isoformat(), datatype=XSD.dateTime)))
        g.add((report_uri, AIFR.description, Literal(self.description)))
        g.add((report_uri, AIFR.policyViolation, Literal(self.policy_violation)))
        
        # Add optional fields if present
        if self.severity:
            g.add((report_uri, AIFR.severity, Literal(self.severity)))
            
        if self.prevalence:
            g.add((report_uri, AIFR.prevalence, Literal(self.prevalence)))
            
        if self.impacts:
            for impact in self.impacts:
                g.add((report_uri, AIFR.impact, Literal(impact)))
                
        if self.impacted_stakeholders:
            for stakeholder in self.impacted_stakeholders:
                g.add((report_uri, AIFR.impactedStakeholder, Literal(stakeholder)))
                
        if self.risk_source:
            g.add((report_uri, AIFR.riskSource, Literal(self.risk_source)))
        
        return g
    
    @classmethod
    def from_rdf(cls, graph: Graph, uri: Union[str, URIRef]) -> 'FlawReport':
        """Create a FlawReport instance from RDF data."""
        if isinstance(uri, str):
            uri = URIRef(uri)
            
        # Extract data from the graph
        report_id = graph.value(uri, AIFR.reportId)
        reporter_id = graph.value(uri, AIFR.reporterId)
        status_value = graph.value(uri, AIFR.status)
        timestamp_str = graph.value(uri, AIFR.timestamp)
        description = graph.value(uri, AIFR.description)
        policy_violation = graph.value(uri, AIFR.policyViolation)
        
        # Get all system versions
        system_versions = [str(obj) for obj in graph.objects(uri, AIFR.systemVersion)]
        
        severity = graph.value(uri, AIFR.severity)
        prevalence = graph.value(uri, AIFR.prevalence)
        impacts = [str(obj) for obj in graph.objects(uri, AIFR.impact)]
        stakeholders = [str(obj) for obj in graph.objects(uri, AIFR.impactedStakeholder)]
        risk_source = graph.value(uri, AIFR.riskSource)
        
        # TODO: Better way to handle the mess of types and required fields?
        if report_id:
            report_id = str(report_id)
        if reporter_id:
            reporter_id = str(reporter_id)

        if status_value:
            status = ReportStatus(str(status_value))
        else:
            status = ReportStatus.SUBMITTED

        if timestamp_str:
            timestamp = datetime.fromisoformat(str(timestamp_str))
        else:
            timestamp = datetime.now()

        if description:
            description = str(description)
        else:
            description = ""

        if policy_violation:
            policy_violation = str(policy_violation)
        else:
            policy_violation = ""
            
        # Create and return instance
        return cls(
            report_id=report_id,
            reporter_id=reporter_id,
            system_versions=system_versions,
            status=status,
            timestamp=timestamp,
            description=description,
            policy_violation=policy_violation,
            severity=str(severity) if severity else None,
            prevalence=str(prevalence) if prevalence else None,
            impacts=impacts if impacts else None,
            impacted_stakeholders=stakeholders if stakeholders else None,
            risk_source=str(risk_source) if risk_source else None
        )


def create_flaw_report(
    reporter_id: str,
    system_versions: List[str],
    description: str,
    policy_violation: str,
    report_id: Optional[str] = None,
    severity: Optional[str] = None,
    prevalence: Optional[str] = None,
    impacts: Optional[List[str]] = None,
    impacted_stakeholders: Optional[List[str]] = None,
    risk_source: Optional[str] = None,
) -> FlawReport:
    """Helper function to create a flaw report. Creates a report_id if not provided."""
    if report_id is None:
        report_id = str(uuid.uuid4())
        
    return FlawReport(
        report_id=report_id,
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