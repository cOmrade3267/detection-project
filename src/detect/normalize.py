"""normalize: provider-specific events -> one common schema.

Why: Sysmon (EID 1/3/7/11/13/22) and Security (4688/4624) describe the same
real-world actions with different field names. A single schema lets rules and
features be written once. Normalization is also where we attach labels
(benign/malicious, technique_id) from the lab run log.

TODO: implement. No logic yet (scaffold).
"""
