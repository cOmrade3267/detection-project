"""detect — behavioral detection pipeline for Windows host telemetry.

Pipeline order: ingest -> normalize -> features -> (rules | model) ->
attack_map -> evaluate. See CLAUDE.md for the full design brief.
"""

__version__ = "0.0.1"
