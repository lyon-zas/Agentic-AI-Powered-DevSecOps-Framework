"""
Benchmark Dataset Definitions and Ground Truth.

Provides dataset abstractions and ground truth for:
- OWASP WebGoat (Java)
- OWASP Benchmark (Java)
- DVWA (PHP)
- Juice Shop (JavaScript)
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from pathlib import Path
import json
import os


@dataclass
class KnownVulnerability:
    """A known vulnerability in a benchmark dataset."""
    file_path: str
    vulnerability_type: str
    cwe_id: str
    severity: str
    line_number: Optional[int] = None
    description: str = ""
    owasp_category: str = ""  # e.g., "A1:2021-Injection"


@dataclass 
class BenchmarkDataset:
    """Base class for benchmark datasets."""
    name: str
    description: str
    url: str
    language: str
    local_path: str = ""
    docker_command: str = ""
    vulnerabilities: List[KnownVulnerability] = field(default_factory=list)
    
    def is_available(self) -> bool:
        """Check if dataset is locally available."""
        if self.local_path:
            return os.path.exists(self.local_path)
        return False
    
    def get_scan_path(self) -> str:
        """Get path to scan."""
        return self.local_path
    
    def get_ground_truth(self) -> List[KnownVulnerability]:
        """Get list of known vulnerabilities."""
        return self.vulnerabilities
    
    def load_ground_truth(self, filepath: str):
        """Load ground truth from JSON file."""
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        self.vulnerabilities = [
            KnownVulnerability(**v) for v in data.get("vulnerabilities", [])
        ]
    
    def save_ground_truth(self, filepath: str):
        """Save ground truth to JSON file."""
        data = {
            "dataset": self.name,
            "vulnerabilities": [
                {
                    "file_path": v.file_path,
                    "vulnerability_type": v.vulnerability_type,
                    "cwe_id": v.cwe_id,
                    "severity": v.severity,
                    "line_number": v.line_number,
                    "description": v.description,
                    "owasp_category": v.owasp_category,
                }
                for v in self.vulnerabilities
            ]
        }
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)


class WebGoatDataset(BenchmarkDataset):
    """
    OWASP WebGoat - Deliberately insecure Java web application.
    
    Known vulnerability categories:
    - SQL Injection (A03:2021)
    - Cross-Site Scripting (A03:2021)
    - CSRF (A01:2021)
    - XXE (A05:2021)
    - SSRF (A10:2021)
    - Path Traversal (A01:2021)
    - Authentication Flaws (A07:2021)
    """
    
    def __init__(self, local_path: str = "evaluation/datasets/webgoat"):
        super().__init__(
            name="webgoat",
            description="OWASP WebGoat - Deliberately insecure Java web application",
            url="https://github.com/WebGoat/WebGoat",
            language="java",
            local_path=local_path,
            docker_command="docker run -it -p 127.0.0.1:8080:8080 -p 127.0.0.1:9090:9090 webgoat/webgoat",
        )
        self._init_known_vulnerabilities()
    
    def _init_known_vulnerabilities(self):
        """Initialize known WebGoat vulnerabilities."""
        # These are documented vulnerable patterns in WebGoat
        self.vulnerabilities = [
            # SQL Injection
            KnownVulnerability(
                file_path="src/main/java/org/owasp/webgoat/lessons/sqlinjection/",
                vulnerability_type="SQL_INJECTION",
                cwe_id="CWE-89",
                severity="critical",
                owasp_category="A03:2021-Injection",
                description="SQL injection in login and query endpoints",
            ),
            # XSS
            KnownVulnerability(
                file_path="src/main/java/org/owasp/webgoat/lessons/xss/",
                vulnerability_type="XSS",
                cwe_id="CWE-79",
                severity="high",
                owasp_category="A03:2021-Injection",
                description="Reflected and stored XSS vulnerabilities",
            ),
            # CSRF
            KnownVulnerability(
                file_path="src/main/java/org/owasp/webgoat/lessons/csrf/",
                vulnerability_type="CSRF",
                cwe_id="CWE-352",
                severity="medium",
                owasp_category="A01:2021-Broken Access Control",
                description="Cross-Site Request Forgery vulnerabilities",
            ),
            # XXE
            KnownVulnerability(
                file_path="src/main/java/org/owasp/webgoat/lessons/xxe/",
                vulnerability_type="XXE",
                cwe_id="CWE-611",
                severity="high",
                owasp_category="A05:2021-Security Misconfiguration",
                description="XML External Entity injection",
            ),
            # SSRF
            KnownVulnerability(
                file_path="src/main/java/org/owasp/webgoat/lessons/ssrf/",
                vulnerability_type="SSRF",
                cwe_id="CWE-918",
                severity="high",
                owasp_category="A10:2021-SSRF",
                description="Server-Side Request Forgery",
            ),
            # Path Traversal
            KnownVulnerability(
                file_path="src/main/java/org/owasp/webgoat/lessons/pathtraversal/",
                vulnerability_type="PATH_TRAVERSAL",
                cwe_id="CWE-22",
                severity="high",
                owasp_category="A01:2021-Broken Access Control",
                description="Path traversal / directory traversal",
            ),
            # JWT Issues
            KnownVulnerability(
                file_path="src/main/java/org/owasp/webgoat/lessons/jwt/",
                vulnerability_type="JWT_VULNERABILITY",
                cwe_id="CWE-347",
                severity="high",
                owasp_category="A07:2021-Identification and Authentication Failures",
                description="JWT signature verification bypass",
            ),
            # Insecure Deserialization
            KnownVulnerability(
                file_path="src/main/java/org/owasp/webgoat/lessons/deserialization/",
                vulnerability_type="INSECURE_DESERIALIZATION",
                cwe_id="CWE-502",
                severity="critical",
                owasp_category="A08:2021-Software and Data Integrity Failures",
                description="Insecure Java deserialization",
            ),
        ]


class OWASPBenchmarkDataset(BenchmarkDataset):
    """
    OWASP Benchmark - Standard test suite with 2,740 test cases.
    
    Provides industry-standard ground truth for SAST evaluation.
    """
    
    def __init__(self, local_path: str = "evaluation/datasets/benchmark"):
        super().__init__(
            name="owasp-benchmark",
            description="OWASP Benchmark Project - 2,740 test cases with known ground truth",
            url="https://github.com/OWASP-Benchmark/BenchmarkJava",
            language="java",
            local_path=local_path,
        )
    
    def load_expected_results(self, filepath: str):
        """Load expected results from OWASP Benchmark's expectedresults.csv."""
        # OWASP Benchmark provides expectedresults-X.Y.csv files
        # Format: test name, category, cwe, is_vulnerable (true/false)
        import csv
        
        vulnerabilities = []
        with open(filepath, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row.get('real vulnerability', '').lower() == 'true':
                    vulnerabilities.append(KnownVulnerability(
                        file_path=f"src/main/java/org/owasp/benchmark/testcode/{row.get('# test name', '')}.java",
                        vulnerability_type=row.get('category', ''),
                        cwe_id=f"CWE-{row.get('CWE', '')}",
                        severity="high",  # OWASP Benchmark doesn't provide severity
                        description=row.get('category', ''),
                    ))
        
        self.vulnerabilities = vulnerabilities


class DVWADataset(BenchmarkDataset):
    """
    Damn Vulnerable Web Application - PHP application with security levels.
    """
    
    def __init__(self, local_path: str = "evaluation/datasets/dvwa"):
        super().__init__(
            name="dvwa",
            description="Damn Vulnerable Web Application - PHP with security levels",
            url="https://github.com/digininja/DVWA",
            language="php",
            local_path=local_path,
            docker_command="docker run --rm -it -p 80:80 vulnerables/web-dvwa",
        )
        self._init_known_vulnerabilities()
    
    def _init_known_vulnerabilities(self):
        """Initialize known DVWA vulnerabilities."""
        self.vulnerabilities = [
            KnownVulnerability(
                file_path="vulnerabilities/sqli/",
                vulnerability_type="SQL_INJECTION",
                cwe_id="CWE-89",
                severity="critical",
                owasp_category="A03:2021-Injection",
            ),
            KnownVulnerability(
                file_path="vulnerabilities/xss_r/",
                vulnerability_type="XSS_REFLECTED",
                cwe_id="CWE-79",
                severity="high",
                owasp_category="A03:2021-Injection",
            ),
            KnownVulnerability(
                file_path="vulnerabilities/xss_s/",
                vulnerability_type="XSS_STORED",
                cwe_id="CWE-79",
                severity="high",
                owasp_category="A03:2021-Injection",
            ),
            KnownVulnerability(
                file_path="vulnerabilities/fi/",
                vulnerability_type="FILE_INCLUSION",
                cwe_id="CWE-98",
                severity="critical",
                owasp_category="A03:2021-Injection",
            ),
            KnownVulnerability(
                file_path="vulnerabilities/exec/",
                vulnerability_type="COMMAND_INJECTION",
                cwe_id="CWE-78",
                severity="critical",
                owasp_category="A03:2021-Injection",
            ),
            KnownVulnerability(
                file_path="vulnerabilities/csrf/",
                vulnerability_type="CSRF",
                cwe_id="CWE-352",
                severity="medium",
                owasp_category="A01:2021-Broken Access Control",
            ),
        ]


class JuiceShopDataset(BenchmarkDataset):
    """
    OWASP Juice Shop - Modern JavaScript application with 100+ challenges.
    """
    
    def __init__(self, local_path: str = "evaluation/datasets/juice-shop"):
        super().__init__(
            name="juice-shop",
            description="OWASP Juice Shop - 100+ security challenges",
            url="https://github.com/juice-shop/juice-shop",
            language="javascript",
            local_path=local_path,
            docker_command="docker run --rm -p 3000:3000 bkimminich/juice-shop",
        )
        self._init_known_vulnerabilities()
    
    def _init_known_vulnerabilities(self):
        """Initialize known Juice Shop vulnerabilities."""
        self.vulnerabilities = [
            KnownVulnerability(
                file_path="routes/",
                vulnerability_type="SQL_INJECTION",
                cwe_id="CWE-89",
                severity="critical",
                owasp_category="A03:2021-Injection",
            ),
            KnownVulnerability(
                file_path="routes/",
                vulnerability_type="XSS",
                cwe_id="CWE-79",
                severity="high",
                owasp_category="A03:2021-Injection",
            ),
            KnownVulnerability(
                file_path="routes/",
                vulnerability_type="BROKEN_ACCESS_CONTROL",
                cwe_id="CWE-639",
                severity="high",
                owasp_category="A01:2021-Broken Access Control",
            ),
            KnownVulnerability(
                file_path="lib/",
                vulnerability_type="CRYPTOGRAPHIC_FAILURE",
                cwe_id="CWE-327",
                severity="high",
                owasp_category="A02:2021-Cryptographic Failures",
            ),
        ]


# Registry of all available datasets
AVAILABLE_DATASETS = {
    "webgoat": WebGoatDataset,
    "owasp-benchmark": OWASPBenchmarkDataset,
    "dvwa": DVWADataset,
    "juice-shop": JuiceShopDataset,
}


def get_dataset(name: str, local_path: str = None) -> BenchmarkDataset:
    """
    Get a benchmark dataset by name.
    
    Args:
        name: Dataset name (webgoat, owasp-benchmark, dvwa, juice-shop)
        local_path: Optional custom local path
    
    Returns:
        BenchmarkDataset instance
    """
    if name not in AVAILABLE_DATASETS:
        raise ValueError(f"Unknown dataset: {name}. Available: {list(AVAILABLE_DATASETS.keys())}")
    
    dataset_class = AVAILABLE_DATASETS[name]
    if local_path:
        return dataset_class(local_path=local_path)
    return dataset_class()


def list_datasets() -> List[Dict[str, str]]:
    """List all available benchmark datasets."""
    return [
        {
            "name": name,
            "class": cls.__name__,
            "url": cls().url if hasattr(cls, "url") else "",
        }
        for name, cls in AVAILABLE_DATASETS.items()
    ]
