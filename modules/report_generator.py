from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.units import inch
from datetime import datetime


# ── Shared helpers ────────────────────────────────────────────────────────────

def _make_table(data, col_widths=None):
    col_widths = col_widths or [2 * inch, 4 * inch]
    t = Table(data, colWidths=col_widths)
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#1B3A6B')),
        ('TEXTCOLOR',  (0, 0), (0, -1), colors.white),
        ('BACKGROUND', (1, 0), (1, -1), colors.HexColor('#F3F4F6')),
        ('GRID',       (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
        ('PADDING',    (0, 0), (-1, -1), 7),
        ('FONTNAME',   (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE',   (0, 0), (-1, -1), 9),
    ]))
    return t


def _section_header(text, styles, color='#1B3A6B'):
    style = ParagraphStyle(
        'SectionHeader',
        parent=styles['Heading2'],
        textColor=colors.HexColor(color),
        fontSize=13,
        spaceAfter=6,
        borderPad=4,
    )
    return Paragraph(text, style)


# ── JSON report ───────────────────────────────────────────────────────────────

def generate_json_report(filename, sha256, vt_result, static_results,
                         behavior_results, yara_result=None, risk=None):
    report = {
        'report_info': {
            'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'tool': 'CyberGuard Sentinel v2'
        },
        'file_info'       : {'filename': filename, 'sha256': sha256},
        'risk_score'      : risk        or {},
        'virustotal'      : vt_result   or {},
        'yara'            : yara_result or {},
        'static_analysis' : static_results,
        'behavior_analysis': behavior_results,
        'final_verdict'   : behavior_results.get('verdict', 'UNKNOWN'),
        'threat_level'    : behavior_results.get('threat_level', 'UNKNOWN'),
    }
    return report


# ── PDF report ────────────────────────────────────────────────────────────────

def generate_pdf_report(filename, sha256, vt_result, static_results,
                        behavior_results, output_path,
                        yara_result=None, risk=None):
    """
    Generates a full PDF report.
    yara_result and risk are optional — report degrades gracefully if absent.
    """
    yara_result = yara_result or {}
    risk        = risk        or {}

    doc    = SimpleDocTemplate(output_path, pagesize=letter,
                               leftMargin=0.75*inch, rightMargin=0.75*inch,
                               topMargin=0.75*inch, bottomMargin=0.75*inch)
    styles = getSampleStyleSheet()
    story  = []

    verdict = behavior_results.get('verdict', 'UNKNOWN')
    verdict_color_map = {
        'MALWARE'    : '#B91C1C',
        'SUSPICIOUS' : '#C2410C',
        'CLEAN'      : '#15803D',
    }
    verdict_hex = verdict_color_map.get(verdict, '#374151')

    # ── TITLE ────────────────────────────────────────────────────
    story.append(Paragraph("🛡️  CyberGuard Sentinel v2", ParagraphStyle(
        'Title', parent=styles['Title'], fontSize=22,
        textColor=colors.HexColor('#1B3A6B'))))
    story.append(Paragraph(
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        styles['Normal']))
    story.append(Spacer(1, 0.2*inch))

    # ── RISK SCORE BANNER ────────────────────────────────────────
    if risk:
        score   = risk.get('risk_score', 0)
        level   = risk.get('threat_level', verdict)
        emoji   = risk.get('threat_emoji', '')
        rec     = risk.get('recommendation', '')

        banner_color_map = {
            'CRITICAL': '#7F1D1D', 'HIGH': '#7C2D12',
            'MEDIUM'  : '#78350F', 'LOW' : '#1E3A5F', 'CLEAN': '#14532D',
        }
        banner_hex = banner_color_map.get(level, '#1B3A6B')

        banner_data = [[
            f"Risk Score: {score}/100",
            f"{emoji} Threat Level: {level}",
            f"Verdict: {verdict}"
        ]]
        banner = Table(banner_data, colWidths=[2*inch, 2.5*inch, 2*inch])
        banner.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor(banner_hex)),
            ('TEXTCOLOR',  (0,0), (-1,-1), colors.white),
            ('FONTNAME',   (0,0), (-1,-1), 'Helvetica-Bold'),
            ('FONTSIZE',   (0,0), (-1,-1), 11),
            ('ALIGN',      (0,0), (-1,-1), 'CENTER'),
            ('PADDING',    (0,0), (-1,-1), 10),
            ('ROUNDEDCORNERS', [6]),
        ]))
        story.append(banner)
        if rec:
            story.append(Spacer(1, 0.1*inch))
            story.append(Paragraph(f"⚠ Recommendation: {rec}", ParagraphStyle(
                'Rec', parent=styles['Normal'],
                textColor=colors.HexColor(verdict_hex),
                fontSize=9, fontName='Helvetica-Bold')))
        story.append(Spacer(1, 0.25*inch))
    else:
        # Fallback — no risk score available
        story.append(Paragraph(
            f"Final Verdict: {verdict}",
            ParagraphStyle('V', parent=styles['Heading1'],
                           textColor=colors.HexColor(verdict_hex), fontSize=18)))
        story.append(Paragraph(
            f"Threat Level: {behavior_results.get('threat_level', 'UNKNOWN')}",
            styles['Heading2']))
        story.append(Spacer(1, 0.25*inch))

    # ── FILE INFO ────────────────────────────────────────────────
    story.append(_section_header("📄  File Information", styles))
    story.append(_make_table([
        ['Filename', filename],
        ['SHA-256',  sha256[:32] + '...'],
    ]))
    story.append(Spacer(1, 0.2*inch))

    # ── VIRUSTOTAL ───────────────────────────────────────────────
    story.append(_section_header("🌐  VirusTotal Results", styles))
    story.append(_make_table([
        ['Found',             str(vt_result.get('found', False))],
        ['Malicious Engines', str(vt_result.get('malicious', 0))],
        ['Suspicious',        str(vt_result.get('suspicious', 0))],
        ['Clean Engines',     str(vt_result.get('clean', 0))],
        ['Total Engines',     str(vt_result.get('total_engines', 0))],
        ['VT Verdict',        vt_result.get('verdict', 'N/A')],
    ]))
    story.append(Spacer(1, 0.2*inch))

    # ── YARA RESULTS ─────────────────────────────────────────────
    story.append(_section_header("🔍  YARA Scan Results", styles, color='#6D28D9'))

    if yara_result.get('error') and not yara_result.get('matched'):
        story.append(Paragraph(f"⚠ YARA error: {yara_result['error']}", styles['Normal']))

    elif not yara_result.get('matched'):
        story.append(Paragraph("✅  No YARA rules matched — no known signatures detected.",
                               styles['Normal']))
    else:
        matches     = yara_result.get('matches', [])
        top_sev     = yara_result.get('highest_severity', 'unknown').upper()
        cats        = ', '.join(yara_result.get('categories', []))
        match_count = yara_result.get('match_count', 0)

        summary_data = [
            ['Rules Matched',     str(match_count)],
            ['Highest Severity',  top_sev],
            ['Categories',        cats or 'N/A'],
        ]
        story.append(_make_table(summary_data))
        story.append(Spacer(1, 0.12*inch))

        # Individual matches table
        if matches:
            story.append(Paragraph("Matched Rules Detail:", ParagraphStyle(
                'Sub', parent=styles['Normal'],
                fontName='Helvetica-Bold', fontSize=9)))
            story.append(Spacer(1, 0.05*inch))

            sev_colors = {
                'critical': '#B91C1C', 'high': '#C2410C',
                'medium'  : '#92400E', 'low' : '#1E3A5F',
            }

            header = [['Rule Name', 'Category', 'Severity', 'Description']]
            rows   = []
            row_colors = []

            for m in matches:
                rows.append([
                    m.get('rule', ''),
                    m.get('category', '').title(),
                    m.get('severity', '').upper(),
                    m.get('description', '')[:55] + ('…' if len(m.get('description','')) > 55 else ''),
                ])
                row_colors.append(
                    colors.HexColor(sev_colors.get(m.get('severity',''), '#374151'))
                )

            match_table = Table(
                header + rows,
                colWidths=[1.6*inch, 1.1*inch, 0.9*inch, 2.9*inch]
            )
            ts = TableStyle([
                ('BACKGROUND', (0,0), (-1,0),  colors.HexColor('#1B3A6B')),
                ('TEXTCOLOR',  (0,0), (-1,0),  colors.white),
                ('FONTNAME',   (0,0), (-1,0),  'Helvetica-Bold'),
                ('FONTSIZE',   (0,0), (-1,-1), 8),
                ('GRID',       (0,0), (-1,-1), 0.4, colors.HexColor('#CBD5E1')),
                ('PADDING',    (0,0), (-1,-1), 5),
                ('ROWBACKGROUNDS', (0,1), (-1,-1),
                 [colors.HexColor('#FEF3C7'), colors.HexColor('#FFFBEB')]),
            ])
            # Color severity column per row
            for i, rc in enumerate(row_colors, start=1):
                ts.add('TEXTCOLOR', (2, i), (2, i), rc)
                ts.add('FONTNAME',  (2, i), (2, i), 'Helvetica-Bold')

            match_table.setStyle(ts)
            story.append(match_table)

    story.append(Spacer(1, 0.2*inch))

    # ── RISK SCORE BREAKDOWN ─────────────────────────────────────
    if risk and risk.get('factors'):
        story.append(_section_header("📊  Risk Score Breakdown", styles, color='#0D9488'))
        factors = risk['factors']
        factor_rows = [['Module', 'Score', 'Weight', 'Weighted']]
        for mod, info in factors.items():
            factor_rows.append([
                mod.title(),
                f"{info.get('score', 0):.1f}/100",
                f"{info.get('weight', 0)}%",
                f"{info.get('weighted', 0):.1f}",
            ])
        factor_rows.append([
            'TOTAL RISK SCORE', '', '',
            str(risk.get('risk_score', 0)) + ' / 100'
        ])

        ft = Table(factor_rows, colWidths=[2*inch, 1.3*inch, 1.1*inch, 1.6*inch])
        ft.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0),  colors.HexColor('#0D9488')),
            ('TEXTCOLOR',  (0,0), (-1,0),  colors.white),
            ('FONTNAME',   (0,0), (-1,0),  'Helvetica-Bold'),
            ('BACKGROUND', (0,-1),(-1,-1), colors.HexColor('#1B3A6B')),
            ('TEXTCOLOR',  (0,-1),(-1,-1), colors.white),
            ('FONTNAME',   (0,-1),(-1,-1), 'Helvetica-Bold'),
            ('GRID',       (0,0), (-1,-1), 0.4, colors.HexColor('#CBD5E1')),
            ('PADDING',    (0,0), (-1,-1), 6),
            ('FONTSIZE',   (0,0), (-1,-1), 9),
            ('ROWBACKGROUNDS', (0,1), (-1,-2),
             [colors.HexColor('#F0FDFA'), colors.white]),
        ]))
        story.append(ft)
        story.append(Spacer(1, 0.2*inch))

    # ── DETECTED ATTACK CHAINS ───────────────────────────────────
    story.append(_section_header("⛓  Detected Attack Chains", styles, color='#C2410C'))
    detected = behavior_results.get('detected_chains', [])
    if detected:
        for chain in detected:
            sev   = chain.get('severity', '')
            cname = chain.get('chain_name', '')
            desc  = chain.get('description', '')
            inds  = ', '.join(chain.get('matched_indicators', []))
            c     = colors.red if sev == 'CRITICAL' else colors.orange
            story.append(Paragraph(f"⚠ {cname}  —  {sev}",
                ParagraphStyle('Ch', parent=styles['Normal'],
                               textColor=c, fontName='Helvetica-Bold')))
            story.append(Paragraph(f"Description: {desc}", styles['Normal']))
            story.append(Paragraph(f"Matched: {inds}", styles['Normal']))
            story.append(Spacer(1, 0.1*inch))
    else:
        story.append(Paragraph("✅  No attack chains detected.", styles['Normal']))
    story.append(Spacer(1, 0.2*inch))

    # ── STATIC ANALYSIS ──────────────────────────────────────────
    story.append(_section_header("🔬  Static Analysis", styles))
    pe = static_results.get('pe_analysis', {})
    story.append(_make_table([
        ['Valid PE',           str(pe.get('is_valid_pe', False))],
        ['Packed',             str(pe.get('is_packed', False))],
        ['Total Strings',      str(static_results.get('total_strings', 0))],
        ['Suspicious Strings', str(len(static_results.get('suspicious_strings', [])))],
    ]))
    story.append(Spacer(1, 0.3*inch))

    # ── FOOTER ───────────────────────────────────────────────────
    story.append(Paragraph(
        "CyberGuard Sentinel v2  —  For authorized security analysis use only.",
        ParagraphStyle('Footer', parent=styles['Normal'],
                       fontSize=7, textColor=colors.HexColor('#94A3B8'),
                       alignment=1)))

    doc.build(story)
    return output_path
