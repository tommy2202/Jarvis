from __future__ import annotations

"""
Documentation-only "controls mapping".

This file contains constants that map:
- GDPR rights (data subject rights)
- to NIST Privacy Framework categories (PF)

These mappings are not used for enforcement (enforcement remains in capabilities/policy).
"""


GDPR_RIGHTS = {
    "ACCESS": "Art. 15 (Right of access)",
    "RECTIFICATION": "Art. 16 (Right to rectification)",
    "ERASURE": "Art. 17 (Right to erasure)",
    "RESTRICT_PROCESSING": "Art. 18 (Right to restriction of processing)",
    "DATA_PORTABILITY": "Art. 20 (Right to data portability)",
    "OBJECT": "Art. 21 (Right to object)",
    "AUTOMATED_DECISION_MAKING": "Art. 22 (Automated decision-making)",
}


# NIST Privacy Framework (high-level) categories (PF = Protecting privacy)
NIST_PF_CATEGORIES = {
    "ID.IM": "Inventory and Mapping",
    "GV.PO": "Policies, Processes, and Procedures",
    "CT.DP": "Data Processing",
    "CT.DM": "Data Management",
    "PR.PO": "Policies, Processes, and Procedures (Protection)",
}


# Minimal crosswalk for docs.
CONTROLS_MAPPING = {
    "ACCESS": ["ID.IM", "CT.DM"],
    "EXPORT": ["ID.IM", "CT.DM"],
    "DELETE": ["CT.DM", "GV.PO"],
    "RETENTION": ["CT.DM", "GV.PO"],
    "CONSENT": ["GV.PO", "CT.DP"],
}

