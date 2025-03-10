import xml.etree.ElementTree as ET
import os
import zipfile
import uuid
import logging
from lxml import etree

# Setup basic logging
logging.basicConfig(
    filename='logs/parser.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class BurpParser:
    def __init__(self, report_path):
        self.report_path = report_path
        self.issues = []

    def parse_burp_report(self):
        try:
            tree = ET.parse(self.report_path)
            root = tree.getroot()
            for issue in root.findall("./issue"):
                issue_data = {
                    'name': issue.findtext("name"),
                    'severity': issue.findtext("severity"),
                    'confidence': issue.findtext("confidence"),
                    'path': issue.findtext("path"),
                    'issueBackground': issue.findtext("issueBackground"),
                    'remediationBackground': issue.findtext("remediationBackground"),
                    'issueDetail': issue.findtext("issueDetail")
                }
                self.issues.append(issue_data)
            logging.info("Parsed %d issues from Burp report.", len(self.issues))
        except Exception as e:
            logging.error("Error while parsing Burp report: %s", str(e))

    def get_issues(self):
        return self.issues

class FortifyWriter:
    def __init__(self, issues):
        self.issues = issues
        self.output_path = 'output/fortify_result.fpr'

    def generate_fvdl(self):
        try:
            root = etree.Element("FVDL")
            vulnerabilities = etree.SubElement(root, "Vulnerabilities")
            for issue in self.issues:
                vuln = etree.SubElement(vulnerabilities, "Vulnerability")
                etree.SubElement(vuln, "ClassID").text = str(uuid.uuid4())
                etree.SubElement(vuln, "AnalyzerName").text = "Burp Suite"
                etree.SubElement(vuln, "Kingdom").text = "Input Validation"
                etree.SubElement(vuln, "Type").text = issue['name']
                etree.SubElement(vuln, "Subtype").text = issue['severity']
                etree.SubElement(vuln, "Abstract").text = issue['issueBackground']
                etree.SubElement(vuln, "Explanation").text = issue['issueDetail']
                etree.SubElement(vuln, "Recommendations").text = issue['remediationBackground']
            xml_bytes = etree.tostring(root, pretty_print=True, xml_declaration=True, encoding='UTF-8')
            with open("output/audit.fvdl", "wb") as file:
                file.write(xml_bytes)
            logging.info("Generated FVDL file successfully.")
        except Exception as e:
            logging.error("Error generating FVDL file: %s", str(e))

    def package_fpr(self):
        try:
            with zipfile.ZipFile(self.output_path, 'w') as fpr:
                fpr.write("output/audit.fvdl", "audit.fvdl")
            logging.info("Packaged FPR file successfully.")
        except Exception as e:
            logging.error("Error packaging FPR file: %s", str(e))

# Example usage
if __name__ == "__main__":
    parser = BurpParser("data/sample_burp_pro.xml")
    parser.parse_burp_report()
    issues = parser.get_issues()
    writer = FortifyWriter(issues)
    writer.generate_fvdl()
    writer.package_fpr()