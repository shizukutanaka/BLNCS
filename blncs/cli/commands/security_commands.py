"""
Security CLI Commands
Provides commands for security auditing and hardening.
"""

import click
from datetime import datetime
from typing import Dict, Any

from ...core.security_auditor import get_security_auditor, SecurityRiskLevel
from ...core.exceptions import format_error_for_cli


@click.command()
def security_status() -> None:
    """Show security audit status"""
    try:
        auditor = get_security_auditor()
        status = auditor.get_security_status()
        
        click.echo("Security Audit Status")
        click.echo("=" * 40)
        
        # Main status
        status_icon = "🟢 Running" if status['is_running'] else "🔴 Stopped"
        click.echo(f"Status: {status_icon}")
        
        if status['is_running']:
            click.echo(f"Audit Interval: {status['audit_interval_minutes']} minutes")
            if status['last_audit']:
                last_audit = datetime.fromisoformat(status['last_audit']).strftime('%Y-%m-%d %H:%M:%S')
                click.echo(f"Last Audit: {last_audit}")
        
        # Findings summary
        click.echo(f"\nFindings Summary:")
        click.echo(f"  Total: {status['total_findings']}")
        click.echo(f"  Active: {status['active_findings']}")
        click.echo(f"  Resolved: {status['resolved_findings']}")
        
        # Risk breakdown
        if status['risk_summary']:
            click.echo(f"\nActive Findings by Risk Level:")
            risk_icons = {
                'critical': '🚨',
                'high': '🔴',
                'medium': '🟡',
                'low': '🟢'
            }
            
            for risk_level in ['critical', 'high', 'medium', 'low']:
                count = status['risk_summary'].get(risk_level, 0)
                if count > 0:
                    icon = risk_icons.get(risk_level, '⚪')
                    click.echo(f"  {icon} {risk_level.title()}: {count}")
        
        # Monitoring info
        click.echo(f"\nMonitoring:")
        click.echo(f"  Monitored Files: {status['monitored_files']}")
        
        # Overall security posture
        if status['active_findings'] == 0:
            click.echo(f"\n✅ No active security findings")
        else:
            critical_high = status['risk_summary'].get('critical', 0) + status['risk_summary'].get('high', 0)
            if critical_high > 0:
                click.echo(f"\n⚠️  {critical_high} critical/high risk findings require attention")
            else:
                click.echo(f"\n💡 {status['active_findings']} medium/low risk findings to review")
    
    except Exception as e:
        click.echo(f"Error getting security status: {format_error_for_cli(e)}", err=True)


@click.command()
def security_start() -> None:
    """Start security auditing"""
    try:
        auditor = get_security_auditor()
        
        if auditor.is_running:
            click.echo("Security auditing is already running")
            return
        
        click.echo("Starting security auditing...")
        click.echo("This will perform an initial comprehensive security scan...")
        
        success = auditor.start_auditing()
        
        if success:
            click.echo("✅ Security auditing started successfully")
            click.echo("Continuous security monitoring is now active")
        else:
            click.echo("❌ Failed to start security auditing", err=True)
    
    except Exception as e:
        click.echo(f"Error starting security auditing: {format_error_for_cli(e)}", err=True)


@click.command()
def security_stop() -> None:
    """Stop security auditing"""
    try:
        auditor = get_security_auditor()
        
        if not auditor.is_running:
            click.echo("Security auditing is not running")
            return
        
        click.echo("Stopping security auditing...")
        
        success = auditor.stop_auditing()
        
        if success:
            click.echo("✅ Security auditing stopped successfully")
        else:
            click.echo("❌ Failed to stop security auditing", err=True)
    
    except Exception as e:
        click.echo(f"Error stopping security auditing: {format_error_for_cli(e)}", err=True)


@click.command()
@click.option('--risk-level', type=click.Choice(['low', 'medium', 'high', 'critical']),
              help='Filter findings by risk level')
@click.option('--include-resolved', is_flag=True, help='Include resolved findings')
def security_findings(risk_level: str, include_resolved: bool) -> None:
    """Show security findings"""
    try:
        auditor = get_security_auditor()
        findings = auditor.get_security_findings(include_resolved=include_resolved)
        
        # Filter by risk level if specified
        if risk_level:
            findings = [f for f in findings if f['risk_level'] == risk_level]
        
        if not findings:
            filter_text = f" ({risk_level})" if risk_level else ""
            resolved_text = " (including resolved)" if include_resolved else ""
            click.echo(f"No security findings{filter_text}{resolved_text}")
            return
        
        # Sort by risk level and timestamp
        risk_priority = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        findings.sort(key=lambda x: (risk_priority.get(x['risk_level'], 4), x['timestamp']), reverse=True)
        
        click.echo(f"Security Findings ({len(findings)})")
        click.echo("=" * 60)
        
        for finding in findings:
            # Risk level icon
            risk_icons = {
                'critical': '🚨',
                'high': '🔴',
                'medium': '🟡',
                'low': '🟢'
            }
            icon = risk_icons.get(finding['risk_level'], '⚪')
            
            # Status indicators
            status_indicators = []
            if finding['resolved']:
                status_indicators.append("✅ Resolved")
            if finding['false_positive']:
                status_indicators.append("❌ False Positive")
            
            status_text = f" ({', '.join(status_indicators)})" if status_indicators else ""
            
            timestamp = datetime.fromisoformat(finding['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
            
            click.echo(f"{icon} [{finding['finding_id'][:8]}...] {finding['title']}{status_text}")
            click.echo(f"   Risk: {finding['risk_level'].title()}")
            click.echo(f"   Type: {finding['check_type'].replace('_', ' ').title()}")
            click.echo(f"   Time: {timestamp}")
            click.echo(f"   Resource: {finding['affected_resource']}")
            click.echo(f"   Description: {finding['description']}")
            click.echo(f"   Recommendation: {finding['recommendation']}")
            click.echo()
    
    except Exception as e:
        click.echo(f"Error getting security findings: {format_error_for_cli(e)}", err=True)


@click.command()
@click.argument('finding_id')
def security_resolve(finding_id: str) -> None:
    """Resolve a security finding"""
    try:
        auditor = get_security_auditor()
        
        success = auditor.resolve_finding(finding_id)
        
        if success:
            click.echo(f"✅ Security finding {finding_id[:8]}... resolved")
        else:
            click.echo(f"❌ Security finding {finding_id} not found", err=True)
    
    except Exception as e:
        click.echo(f"Error resolving security finding: {format_error_for_cli(e)}", err=True)


@click.command()
@click.argument('finding_id')
def security_false_positive(finding_id: str) -> None:
    """Mark a security finding as false positive"""
    try:
        auditor = get_security_auditor()
        
        success = auditor.mark_false_positive(finding_id)
        
        if success:
            click.echo(f"✅ Security finding {finding_id[:8]}... marked as false positive")
        else:
            click.echo(f"❌ Security finding {finding_id} not found", err=True)
    
    except Exception as e:
        click.echo(f"Error marking finding as false positive: {format_error_for_cli(e)}", err=True)


@click.command()
def security_scan() -> None:
    """Run immediate security scan"""
    try:
        auditor = get_security_auditor()
        
        click.echo("Running comprehensive security scan...")
        click.echo("This may take a moment...")
        
        # Perform manual audit
        findings_count = auditor._perform_comprehensive_audit()
        
        click.echo(f"✅ Security scan completed")
        click.echo(f"Found {findings_count} new security findings")
        
        if findings_count > 0:
            click.echo(f"\n💡 Use 'security_findings' to view detailed results")
        else:
            click.echo(f"\n🎉 No new security issues found!")
    
    except Exception as e:
        click.echo(f"Error running security scan: {format_error_for_cli(e)}", err=True)


@click.command()
def security_harden() -> None:
    """Apply basic security hardening measures"""
    try:
        click.echo("Applying security hardening measures...")
        
        hardening_applied = []
        
        # Set secure file permissions
        import os
        import stat
        
        secure_files = {
            'config/config.yaml': 0o600,
            'blncs.db': 0o600,
            '.env': 0o600
        }
        
        for file_path, perm in secure_files.items():
            if os.path.exists(file_path):
                try:
                    os.chmod(file_path, perm)
                    hardening_applied.append(f"Set permissions {oct(perm)} on {file_path}")
                except Exception as e:
                    click.echo(f"⚠️  Failed to set permissions on {file_path}: {e}")
        
        # Create security directory
        security_dir = "security"
        if not os.path.exists(security_dir):
            try:
                os.makedirs(security_dir, mode=0o700)
                hardening_applied.append(f"Created secure directory: {security_dir}")
            except Exception as e:
                click.echo(f"⚠️  Failed to create security directory: {e}")
        
        # Set secure permissions on security directory
        if os.path.exists(security_dir):
            try:
                os.chmod(security_dir, 0o700)
                hardening_applied.append(f"Secured directory permissions: {security_dir}")
            except Exception as e:
                click.echo(f"⚠️  Failed to secure directory: {e}")
        
        if hardening_applied:
            click.echo("✅ Security hardening completed:")
            for action in hardening_applied:
                click.echo(f"  • {action}")
        else:
            click.echo("ℹ️  No hardening measures were needed or could be applied")
        
        click.echo(f"\n💡 Run 'security_scan' to verify security posture")
    
    except Exception as e:
        click.echo(f"Error applying security hardening: {format_error_for_cli(e)}", err=True)