from __future__ import annotations

# These are intentionally phrased as "relevance/alignment" mappings.
# They are NOT legal determinations.
#
# The exact legal/benchmark references must be verified against authoritative
# current sources before the dissertation is finalised.

MAPPINGS = {
    "S3-001": {
        "gdpr": [{
            "reference": "GDPR Article 32",
            "rationale": "Relevant to technical and organisational security measures where personal data may be processed."
        }],
        "nis2": [{
            "reference": "NIS2 Article 21",
            "rationale": "Relevant to cybersecurity risk-management measures and protection of systems/data."
        }],
    },
    "S3-002": {
        "gdpr": [{
            "reference": "GDPR Article 32",
            "rationale": "Encryption can be a relevant technical security measure depending on processing risk."
        }],
        "nis2": [{
            "reference": "NIS2 Article 21",
            "rationale": "Cryptographic/security measures may be relevant to risk management."
        }],
    },
    "S3-003": {
        "gdpr": [{
            "reference": "GDPR Article 32",
            "rationale": "Versioning can support resilience/recovery depending on the defined threat and data-processing context."
        }],
        "nis2": [{
            "reference": "NIS2 Article 21",
            "rationale": "Resilience and recovery-related controls may be relevant to risk management."
        }],
    },
    "IAM-001": {
        "gdpr": [{
            "reference": "GDPR Article 32",
            "rationale": "Strong authentication is relevant to access protection."
        }],
        "nis2": [{
            "reference": "NIS2 Article 21",
            "rationale": "Access control and authentication are relevant cybersecurity risk-management measures."
        }],
    },
    "IAM-002": {
        "gdpr": [{
            "reference": "GDPR Article 32",
            "rationale": "Account security settings can contribute to protection against unauthorised access."
        }],
        "nis2": [{
            "reference": "NIS2 Article 21",
            "rationale": "Access-control measures are relevant to cybersecurity risk management."
        }],
    },
    "IAM-004": {
        "gdpr": [{
            "reference": "GDPR Article 32",
            "rationale": "Root account security is relevant to overall access protection and security of processing.",
        }],
        "nis2": [{
            "reference": "NIS2 Article 21",
            "rationale": "Strong authentication for the highest-privilege account is relevant to cybersecurity risk management.",
        }],
    },
    "IAM-003": {
        "gdpr": [{
            "reference": "GDPR Article 32",
            "rationale": "Least-privilege access is relevant to protection against unauthorised processing."
        }],
        "nis2": [{
            "reference": "NIS2 Article 21",
            "rationale": "Access-control and risk-management measures are relevant."
        }],
    },
    "EC2-001": {
        "gdpr": [{
            "reference": "GDPR Article 32",
            "rationale": "Network exposure is relevant to technical security of systems processing data."
        }],
        "nis2": [{
            "reference": "NIS2 Article 21",
            "rationale": "Network security and risk reduction are relevant cybersecurity measures."
        }],
    },
    "EC2-002": {
        "gdpr": [{
            "reference": "GDPR Article 32",
            "rationale": "Network exposure is relevant to technical security of systems processing data."
        }],
        "nis2": [{
            "reference": "NIS2 Article 21",
            "rationale": "Network security and risk reduction are relevant cybersecurity measures."
        }],
    },
    "CT-001": {
        "gdpr": [{
            "reference": "GDPR Article 32",
            "rationale": "Logging can support security monitoring, detection and investigation where appropriate."
        }],
        "nis2": [{
            "reference": "NIS2 Article 21",
            "rationale": "Logging/monitoring is relevant to cybersecurity risk management and incident preparedness."
        }],
    },
    "MON-001": {
        "gdpr": [{
            "reference": "GDPR Article 32",
            "rationale": "Security monitoring can contribute to ongoing security assurance."
        }],
        "nis2": [{
            "reference": "NIS2 Article 21",
            "rationale": "Monitoring and detection are relevant to cybersecurity risk management."
        }],
    },
}


def get_mapping(check_id: str) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    mapping = MAPPINGS.get(check_id, {})
    return mapping.get("gdpr", []), mapping.get("nis2", [])
