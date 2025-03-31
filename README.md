# aifr-prototyping

This workspace contains two projects currently being prototyped.

1. The Semantic AI Flaw Reporting package, [semantic-aifr](/packages/semantic-aifr/).  
This package encapsulates a prototype ontology [(ontology/aifr.ttl)](/packages/semantic-aifr/src/semantic_aifr/prototype/ontology/aifr.ttl) for terms and relationships in AI flaw reporting, and exposes functions to create flaw reports and dump them to JSON-LD or RDF (Turtle).

1. A MCP (model context protocol) server app, [mcp-aifr](/src/mcp-aifr/), that uses the semantic-aifr package to  generate structured and semantic web-ready AI flaw reports.

To install and run, [uv](https://docs.astral.sh/uv/) is preferred.

```shell
uv venv  && \
    source .venv/bin/activate && \
    uv sync --all-packages  && \
    uv run pytest
```

To learn how to debug and install the MCP server for use by a client (such as Claude for Desktop), see the [Python SDK documentation](https://github.com/modelcontextprotocol/python-sdk).