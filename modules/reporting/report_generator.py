import json
import os
from datetime import datetime
from typing import Dict, Any, List
from pathlib import Path
from core.base_module import BaseModule

try:
    from jinja2 import Template
    JINJA_AVAILABLE = True
except ImportError:
    JINJA_AVAILABLE = False

try:
    from fpdf import FPDF
    FPDF_AVAILABLE = True
except ImportError:
    FPDF_AVAILABLE = False


class ReportGenerator(BaseModule):
    """Generate professional security assessment reports."""

    def __init__(self):
        super().__init__("Report Generator")

    def _generate_html_report(self, data: Dict, output_path: str) -> str:
        """Generate HTML report."""
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Security Assessment Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #1a1a2e; border-bottom: 3px solid #e94560; padding-bottom: 10px; }
        h2 { color: #16213e; margin-top: 30px; }
        h3 { color: #0f3460; }
        .summary-box { background: #f0f0f0; padding: 20px; border-radius: 8px; margin: 20px 0; }
        .critical { color: #ff0000; font-weight: bold; }
        .high { color: #ff6600; font-weight: bold; }
        .medium { color: #ffcc00; font-weight: bold; }
        .low { color: #00cc00; font-weight: bold; }
        .info { color: #0066cc; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #16213e; color: white; }
        tr:hover { background-color: #f5f5f5; }
        .vuln-card { border-left: 4px solid #e94560; padding: 15px; margin: 10px 0; background: #fff5f5; border-radius: 0 8px 8px 0; }
        .stat-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 20px 0; }
        .stat-card { background: linear-gradient(135deg, #16213e, #0f3460); color: white; padding: 20px; border-radius: 10px; text-align: center; }
        .stat-card .number { font-size: 2em; font-weight: bold; }
        .stat-card .label { font-size: 0.9em; opacity: 0.8; }
        .disclaimer { background: #fff3cd; border: 1px solid #ffc107; padding: 15px; border-radius: 8px; margin-top: 30px; }
        code { background: #e9ecef; padding: 2px 6px; border-radius: 3px; font-family: monospace; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Security Assessment Report</h1>
        <div class="summary-box">
            <strong>Target:</strong> {{ target }}<br>
            <strong>Date:</strong> {{ date }}<br>
            <strong>Scanner:</strong> CyberSec Toolkit v1.0<br>
            <strong>Assessment Type:</strong> {{ assessment_type }}
        </div>

        <h2>📊 Executive Summary</h2>
        <div class="stat-grid">
            <div class="stat-card" style="background: linear-gradient(135deg, #dc3545, #c82333);">
                <div class="number">{{ stats.critical }}</div>
                <div class="label">Critical</div>
            </div>
            <div class="stat-card" style="background: linear-gradient(135deg, #fd7e14, #e8690a);">
                <div class="number">{{ stats.high }}</div>
                <div class="label">High</div>
            </div>
            <div class="stat-card" style="background: linear-gradient(135deg, #ffc107, #e0a800);">
                <div class="number">{{ stats.medium }}</div>
                <div class="label">Medium</div>
            </div>
            <div class="stat-card" style="background: linear-gradient(135deg, #28a745, #218838);">
                <div class="number">{{ stats.low }}</div>
                <div class="label">Low</div>
            </div>
        </div>

        <h2>🔍 Vulnerability Details</h2>
        {% for vuln in vulnerabilities %}
        <div class="vuln-card">
            <h3>
                <span class="{{ vuln.severity|lower }}">
                    [{{ vuln.severity }}]
                </span>
                {{ vuln.type }}
            </h3>
            <p><strong>URL:</strong> <code>{{ vuln.url }}</code></p>
            <p><strong>Detail:</strong> {{ vuln.detail }}</p>
            {% if vuln.remediation %}
            <p><strong>Remediation:</strong> {{ vuln.remediation }}</p>
            {% endif %}
        </div>
        {% endfor %}

        <h2>📋 Scan Results</h2>
        {% for section_name, section_data in sections.items() %}
        <h3>{{ section_name }}</h3>
        <pre>{{ section_data | tojson(indent=2) }}</pre>
        {% endfor %}

        <div class="disclaimer">
            <strong>⚠️ Disclaimer:</strong>
            This report is generated for authorized security testing purposes only.
            Findings should be verified manually before remediation.
            False positives may exist.
        </div>

        <p style="text-align: center; color: #666; margin-top: 30px;">
            Generated by CyberSec Toolkit | {{ date }}
        </p>
    </div>
</body>
</html>
        """

        if JINJA_AVAILABLE:
            template = Template(html_template)
            html_content = template.render(**data)
        else:
            # Basic string replacement fallback
            html_content = html_template
            for key, value in data.items():
                html_content = html_content.replace(f"{{{{ {key} }}}}", str(value))

        with open(output_path, 'w') as f:
            f.write(html_content)

        return output_path

    def _generate_json_report(self, data: Dict, output_path: str) -> str:
        """Generate JSON report."""
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        return output_path

    def _generate_pdf_report(self, data: Dict, output_path: str) -> str:
        """Generate PDF report."""
        if not FPDF_AVAILABLE:
            self.logger.warning("fpdf2 not available, generating HTML instead")
            return self._generate_html_report(data, output_path.replace('.pdf', '.html'))

        pdf = FPDF()
        pdf.add_page()

        # Title
        pdf.set_font('Helvetica', 'B', 24)
        pdf.cell(0, 15, 'Security Assessment Report', ln=True, align='C')
        pdf.ln(10)

        # Target info
        pdf.set_font('Helvetica', '', 12)
        pdf.cell(0, 8, f"Target: {data.get('target', 'N/A')}", ln=True)
        pdf.cell(0, 8, f"Date: {data.get('date', 'N/A')}", ln=True)
        pdf.ln(10)

        # Summary
        pdf.set_font('Helvetica', 'B', 16)
        pdf.cell(0, 10, 'Summary', ln=True)
        pdf.set_font('Helvetica', '', 11)
        stats = data.get('stats', {})
        pdf.cell(0, 7, f"Critical: {stats.get('critical', 0)}", ln=True)
        pdf.cell(0, 7, f"High: {stats.get('high', 0)}", ln=True)
        pdf.cell(0, 7, f"Medium: {stats.get('medium', 0)}", ln=True)
        pdf.cell(0, 7, f"Low: {stats.get('low', 0)}", ln=True)
        pdf.ln(10)

        # Vulnerabilities
        pdf.set_font('Helvetica', 'B', 16)
        pdf.cell(0, 10, 'Vulnerabilities', ln=True)

        for vuln in data.get('vulnerabilities', []):
            pdf.set_font('Helvetica', 'B', 11)
            pdf.cell(0, 7, f"[{vuln.get('severity', 'N/A')}] {vuln.get('type', 'N/A')}", ln=True)
            pdf.set_font('Helvetica', '', 10)
            pdf.cell(0, 6, f"  URL: {vuln.get('url', 'N/A')}", ln=True)
            pdf.cell(0, 6, f"  Detail: {vuln.get('detail', 'N/A')[:100]}", ln=True)
            pdf.ln(3)

        pdf.output(output_path)
        return output_path

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """Generate report."""
        scan_results = kwargs.get('results', {})
        report_format = kwargs.get('format', 'html')
        output_dir = kwargs.get('output_dir', 'output')

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        target_clean = target.replace('://', '_').replace('/', '_').replace('.', '_')

        # Prepare report data
        vulnerabilities = scan_results.get('vulnerabilities', [])
        stats = {
            'critical': len([v for v in vulnerabilities if v.get('severity') == 'Critical']),
            'high': len([v for v in vulnerabilities if v.get('severity') == 'High']),
            'medium': len([v for v in vulnerabilities if v.get('severity') == 'Medium']),
            'low': len([v for v in vulnerabilities if v.get('severity') == 'Low']),
        }

        report_data = {
            'target': target,
            'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'assessment_type': kwargs.get('assessment_type', 'Automated Security Scan'),
            'vulnerabilities': vulnerabilities,
            'stats': stats,
            'sections': {k: v for k, v in scan_results.items() if k != 'vulnerabilities'}
        }

        os.makedirs(output_dir, exist_ok=True)

        if report_format == 'html':
            output_path = f"{output_dir}/report_{target_clean}_{timestamp}.html"
            self._generate_html_report(report_data, output_path)
        elif report_format == 'pdf':
            output_path = f"{output_dir}/report_{target_clean}_{timestamp}.pdf"
            self._generate_pdf_report(report_data, output_path)
        elif report_format == 'json':
            output_path = f"{output_dir}/report_{target_clean}_{timestamp}.json"
            self._generate_json_report(report_data, output_path)

        self.logger.info(f"📄 Report saved: {output_path}")

        return {
            'report_path': output_path,
            'format': report_format,
            'vulnerabilities_count': len(vulnerabilities),
            'stats': stats
        }