import pytest

from lib4vex.generator import VEXGenerator
from lib4sbom.data.vulnerability import Vulnerability

vextype = "cyclonedx"
vexgen = VEXGenerator(
    vex_type=vextype, 
)
vexgen.set_product(name="test", release="1.0.0")

# Create initial VEX
vulnerability = Vulnerability(validation=vextype)
vulnerabilities = []

# Specifiy vulnerability by product name/version
vulnerability.initialise()
vulnerability.set_id("CVE-2023-12345")
vulnerability.set_name("pyyaml")
vulnerability.set_release("6.0.1")
vulnerability.set_status("in_triage")
vulnerabilities.append(vulnerability.get_vulnerability())

# Specifiy vulnerability by PURL
vulnerability.initialise()
vulnerability.set_id("CVE-2024-1234")
vulnerability.set_value("purl", "pkg:pypi/defusedxml@0.7.1")
vulnerability.set_status("in_triage")
vulnerabilities.append(vulnerability.get_vulnerability())

# This vulnerability doesn't apply to the product as component not included in this version of the SBOM
vulnerability.initialise()
vulnerability.set_id("CVE-2024-0987")
vulnerability.set_name("Spring")
vulnerability.set_release("3.2.1")
vulnerability.set_status("in_triage")
vulnerabilities.append(vulnerability.get_vulnerability())

def test_cyclonedx_vex2json():
    vex = vexgen.generate_dict(vex_data=vulnerabilities)
    assert isinstance(vex, dict)
    assert len(vex["vulnerabilities"]) == 3