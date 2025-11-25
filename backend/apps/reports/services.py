"""
Report Generation Services.
"""

import logging
import json
from datetime import datetime, timedelta
from typing import Dict, Any, List

from django.utils import timezone
from django.conf import settings

logger = logging.getLogger('scamlytic.reports')


class ReportGeneratorService:
    """
    Service for generating analysis reports.
    """

    def generate(self, report) -> Dict[str, Any]:
        """
        Generate report content based on type.
        """
        report.status = 'generating'
        report.save(update_fields=['status'])

        try:
            if report.report_type == 'single_analysis':
                content = self._generate_single_analysis_report(report)
            elif report.report_type in ['daily_summary', 'weekly_summary', 'monthly_summary']:
                content = self._generate_summary_report(report)
            elif report.report_type == 'threat_report':
                content = self._generate_threat_report(report)
            else:
                content = self._generate_batch_report(report)

            report.content = content
            report.status = 'completed'
            report.save(update_fields=['content', 'status'])

            # Generate file if needed
            if report.format in ['pdf', 'html']:
                self._generate_file(report)

            return content

        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            report.status = 'failed'
            report.save(update_fields=['status'])
            raise

    def _generate_single_analysis_report(self, report) -> Dict[str, Any]:
        """Generate report for a single analysis."""
        analyses = report.analyses.all()

        if not analyses.exists():
            return {'error': 'No analyses attached to report'}

        analysis = analyses.first()

        return {
            'report_type': 'single_analysis',
            'generated_at': timezone.now().isoformat(),
            'analysis': {
                'request_id': analysis.request_id,
                'type': analysis.analysis_type,
                'scam_score': analysis.scam_score,
                'verdict': analysis.verdict,
                'threat_type': str(analysis.threat_type) if analysis.threat_type else None,
                'explanation': analysis.explanation,
                'recommended_action': analysis.recommended_action,
                'signals': analysis.signals,
                'analyzed_at': analysis.created_at.isoformat(),
            },
            'recommendations': self._get_recommendations(analysis),
        }

    def _generate_summary_report(self, report) -> Dict[str, Any]:
        """Generate summary report for a date range."""
        from apps.analysis.models import AnalysisResult

        # Determine date range
        if report.date_from and report.date_to:
            date_from = report.date_from
            date_to = report.date_to
        else:
            date_to = timezone.now().date()
            if report.report_type == 'daily_summary':
                date_from = date_to - timedelta(days=1)
            elif report.report_type == 'weekly_summary':
                date_from = date_to - timedelta(days=7)
            else:
                date_from = date_to - timedelta(days=30)

        # Query analyses
        analyses = AnalysisResult.objects.filter(
            user=report.user,
            created_at__date__gte=date_from,
            created_at__date__lte=date_to
        )

        # Calculate statistics
        total_count = analyses.count()
        by_type = {}
        by_verdict = {}
        by_threat = {}

        for analysis in analyses:
            # By type
            by_type[analysis.analysis_type] = by_type.get(analysis.analysis_type, 0) + 1

            # By verdict
            by_verdict[analysis.verdict] = by_verdict.get(analysis.verdict, 0) + 1

            # By threat type
            threat = str(analysis.threat_type) if analysis.threat_type else 'LIKELY_SAFE'
            by_threat[threat] = by_threat.get(threat, 0) + 1

        # Calculate average score
        scores = [a.scam_score for a in analyses]
        avg_score = sum(scores) / len(scores) if scores else 0

        # High risk analyses
        high_risk = analyses.filter(verdict__in=['HIGH_RISK', 'CRITICAL_RISK'])
        high_risk_items = [
            {
                'request_id': a.request_id,
                'type': a.analysis_type,
                'score': a.scam_score,
                'verdict': a.verdict,
                'date': a.created_at.isoformat(),
            }
            for a in high_risk[:10]
        ]

        return {
            'report_type': report.report_type,
            'generated_at': timezone.now().isoformat(),
            'period': {
                'from': str(date_from),
                'to': str(date_to),
            },
            'summary': {
                'total_analyses': total_count,
                'average_scam_score': round(avg_score, 1),
                'high_risk_count': high_risk.count(),
            },
            'breakdown': {
                'by_type': by_type,
                'by_verdict': by_verdict,
                'by_threat_type': by_threat,
            },
            'high_risk_items': high_risk_items,
            'recommendations': self._get_summary_recommendations(by_threat),
        }

    def _generate_threat_report(self, report) -> Dict[str, Any]:
        """Generate threat intelligence report."""
        from apps.core.models import BlockedDomain, BlockedPhoneNumber, ThreatType
        from apps.analysis.models import AnalysisResult

        # Get recent threats
        recent_analyses = AnalysisResult.objects.filter(
            verdict__in=['HIGH_RISK', 'CRITICAL_RISK'],
            created_at__gte=timezone.now() - timedelta(days=30)
        ).order_by('-created_at')[:100]

        # Threat type distribution
        threat_distribution = {}
        for analysis in recent_analyses:
            threat = str(analysis.threat_type) if analysis.threat_type else 'UNKNOWN'
            threat_distribution[threat] = threat_distribution.get(threat, 0) + 1

        # Top blocked domains
        top_domains = BlockedDomain.objects.filter(
            is_active=True
        ).order_by('-report_count')[:20]

        # Top blocked phones
        top_phones = BlockedPhoneNumber.objects.filter(
            is_active=True
        ).order_by('-report_count')[:20]

        return {
            'report_type': 'threat_report',
            'generated_at': timezone.now().isoformat(),
            'period': {
                'from': (timezone.now() - timedelta(days=30)).isoformat(),
                'to': timezone.now().isoformat(),
            },
            'threat_landscape': {
                'total_threats_detected': recent_analyses.count(),
                'threat_distribution': threat_distribution,
            },
            'top_blocked_domains': [
                {
                    'domain': d.domain,
                    'threat_type': str(d.threat_type),
                    'report_count': d.report_count,
                }
                for d in top_domains
            ],
            'top_blocked_phones': [
                {
                    'phone': p.phone_number,
                    'country': p.country_code,
                    'threat_type': str(p.threat_type),
                    'report_count': p.report_count,
                }
                for p in top_phones
            ],
            'emerging_threats': self._identify_emerging_threats(recent_analyses),
        }

    def _generate_batch_report(self, report) -> Dict[str, Any]:
        """Generate batch analysis report."""
        analyses = report.analyses.all()

        items = []
        total_score = 0
        verdicts = {}

        for analysis in analyses:
            items.append({
                'request_id': analysis.request_id,
                'type': analysis.analysis_type,
                'scam_score': analysis.scam_score,
                'verdict': analysis.verdict,
                'threat_type': str(analysis.threat_type) if analysis.threat_type else None,
            })
            total_score += analysis.scam_score
            verdicts[analysis.verdict] = verdicts.get(analysis.verdict, 0) + 1

        return {
            'report_type': 'batch_analysis',
            'generated_at': timezone.now().isoformat(),
            'summary': {
                'total_items': len(items),
                'average_score': round(total_score / len(items), 1) if items else 0,
                'verdict_distribution': verdicts,
            },
            'items': items,
        }

    def _get_recommendations(self, analysis) -> List[str]:
        """Get recommendations based on analysis."""
        recommendations = []

        if analysis.scam_score >= 75:
            recommendations.extend([
                "Do not respond to or engage with this content",
                "Block the sender immediately",
                "Report to relevant authorities",
            ])
        elif analysis.scam_score >= 50:
            recommendations.extend([
                "Exercise extreme caution",
                "Verify through official channels",
                "Do not share personal information",
            ])
        elif analysis.scam_score >= 25:
            recommendations.extend([
                "Proceed with caution",
                "Verify the source independently",
            ])
        else:
            recommendations.append("No immediate action required")

        return recommendations

    def _get_summary_recommendations(self, threat_distribution: Dict[str, int]) -> List[str]:
        """Get recommendations based on threat distribution."""
        recommendations = []

        if threat_distribution.get('BVN_PHISHING', 0) > 0:
            recommendations.append(
                "BVN phishing attempts detected - remind users to never share BVN via messages"
            )

        if threat_distribution.get('PHISHING_URL', 0) > 0:
            recommendations.append(
                "Phishing URLs detected - implement URL filtering and user awareness training"
            )

        if threat_distribution.get('CRYPTO_SCAM', 0) > 0:
            recommendations.append(
                "Cryptocurrency scams detected - educate users about investment fraud"
            )

        if not recommendations:
            recommendations.append("Continue monitoring for emerging threats")

        return recommendations

    def _identify_emerging_threats(self, analyses) -> List[Dict[str, Any]]:
        """Identify emerging threat patterns."""
        # Simple pattern detection
        patterns = {}
        for analysis in analyses:
            for signal in analysis.signals:
                patterns[signal] = patterns.get(signal, 0) + 1

        # Sort by frequency
        sorted_patterns = sorted(patterns.items(), key=lambda x: x[1], reverse=True)

        return [
            {'pattern': p[0], 'count': p[1]}
            for p in sorted_patterns[:10]
        ]

    def _generate_file(self, report):
        """Generate PDF or HTML file for report."""
        try:
            if report.format == 'pdf':
                self._generate_pdf(report)
            elif report.format == 'html':
                self._generate_html(report)
        except Exception as e:
            logger.error(f"File generation failed: {e}")

    def _generate_pdf(self, report):
        """Generate PDF file."""
        # PDF generation would use ReportLab or WeasyPrint
        pass

    def _generate_html(self, report):
        """Generate HTML file."""
        # HTML generation would use Jinja2 templates
        pass
