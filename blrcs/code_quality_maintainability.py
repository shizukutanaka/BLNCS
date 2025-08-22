# BLRCS Code Quality and Maintainability Enhancement System
# Automated code quality monitoring, documentation generation, and maintainability improvements

import ast
import os
import sys
import re
import time
import logging
import json
import subprocess
from typing import Dict, List, Any, Optional, Set, Tuple, NamedTuple
from pathlib import Path
from dataclasses import dataclass, field
from collections import defaultdict, Counter
from enum import Enum
import threading
import hashlib

logger = logging.getLogger(__name__)

class CodeQualityLevel(Enum):
    """Code quality assessment levels"""
    EXCELLENT = "excellent"
    GOOD = "good" 
    ACCEPTABLE = "acceptable"
    NEEDS_IMPROVEMENT = "needs_improvement"
    POOR = "poor"

class IssueType(Enum):
    """Code issue types"""
    COMPLEXITY = "complexity"
    DUPLICATION = "duplication"
    DOCUMENTATION = "documentation"
    NAMING = "naming"
    STRUCTURE = "structure"
    SECURITY = "security"
    PERFORMANCE = "performance"
    MAINTAINABILITY = "maintainability"

@dataclass
class CodeIssue:
    """Code quality issue"""
    file_path: str
    line_number: int
    issue_type: IssueType
    severity: str  # critical, high, medium, low
    description: str
    suggestion: str
    estimated_fix_time: int  # minutes
    
@dataclass
class CodeMetrics:
    """Code metrics for a file"""
    file_path: str
    lines_of_code: int
    complexity_score: int
    duplication_percentage: float
    documentation_coverage: float
    test_coverage: float
    maintainability_index: float
    last_modified: float
    
@dataclass
class QualityReport:
    """Code quality report"""
    timestamp: float
    overall_score: float
    quality_level: CodeQualityLevel
    files_analyzed: int
    issues_found: List[CodeIssue]
    metrics: List[CodeMetrics]
    recommendations: List[str]
    improvement_suggestions: List[str]

class CodeAnalyzer:
    """Advanced code analysis and quality assessment"""
    
    def __init__(self, project_root: Path):
        self.project_root = Path(project_root)
        self.exclude_patterns = {
            "*.pyc", "__pycache__", ".git", ".venv", 
            "node_modules", "*.egg-info", "dist", "build"
        }
        self.complexity_threshold = 15
        self.duplication_threshold = 20.0
        self.documentation_threshold = 80.0
        
    def analyze_project(self) -> QualityReport:
        """Perform comprehensive project analysis"""
        python_files = self._find_python_files()
        issues = []
        metrics = []
        
        for file_path in python_files:
            try:
                file_metrics = self._analyze_file(file_path)
                file_issues = self._find_file_issues(file_path, file_metrics)
                
                metrics.append(file_metrics)
                issues.extend(file_issues)
                
            except Exception as e:
                logger.warning(f"Failed to analyze {file_path}: {e}")
        
        overall_score = self._calculate_overall_score(metrics, issues)
        quality_level = self._determine_quality_level(overall_score)
        
        return QualityReport(
            timestamp=time.time(),
            overall_score=overall_score,
            quality_level=quality_level,
            files_analyzed=len(metrics),
            issues_found=issues,
            metrics=metrics,
            recommendations=self._generate_recommendations(issues, metrics),
            improvement_suggestions=self._generate_improvement_suggestions(issues, metrics)
        )
    
    def _find_python_files(self) -> List[Path]:
        """Find all Python files in project"""
        python_files = []
        
        for file_path in self.project_root.rglob("*.py"):
            # Skip excluded patterns
            if any(pattern in str(file_path) for pattern in self.exclude_patterns):
                continue
            python_files.append(file_path)
            
        return python_files
    
    def _analyze_file(self, file_path: Path) -> CodeMetrics:
        """Analyze individual file metrics"""
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
        # Parse AST
        try:
            tree = ast.parse(content)
        except SyntaxError:
            # Return basic metrics for unparseable files
            return CodeMetrics(
                file_path=str(file_path),
                lines_of_code=len(content.splitlines()),
                complexity_score=0,
                duplication_percentage=0.0,
                documentation_coverage=0.0,
                test_coverage=0.0,
                maintainability_index=0.0,
                last_modified=file_path.stat().st_mtime
            )
        
        lines_of_code = len([line for line in content.splitlines() if line.strip()])
        complexity_score = self._calculate_complexity(tree)
        documentation_coverage = self._calculate_documentation_coverage(tree, content)
        maintainability_index = self._calculate_maintainability_index(
            lines_of_code, complexity_score, documentation_coverage
        )
        
        return CodeMetrics(
            file_path=str(file_path),
            lines_of_code=lines_of_code,
            complexity_score=complexity_score,
            duplication_percentage=0.0,  # Simplified for now
            documentation_coverage=documentation_coverage,
            test_coverage=0.0,  # Would require test execution
            maintainability_index=maintainability_index,
            last_modified=file_path.stat().st_mtime
        )
    
    def _calculate_complexity(self, tree: ast.AST) -> int:
        """Calculate cyclomatic complexity"""
        complexity = 1  # Base complexity
        
        for node in ast.walk(tree):
            # Count decision points
            if isinstance(node, (ast.If, ast.While, ast.For, ast.AsyncFor, 
                               ast.ExceptHandler, ast.With, ast.AsyncWith)):
                complexity += 1
            elif isinstance(node, ast.BoolOp):
                # Count boolean operators (and, or)
                complexity += len(node.values) - 1
            elif isinstance(node, (ast.ListComp, ast.DictComp, ast.SetComp, ast.GeneratorExp)):
                # Comprehensions add complexity
                complexity += 1
                
        return complexity
    
    def _calculate_documentation_coverage(self, tree: ast.AST, content: str) -> float:
        """Calculate documentation coverage percentage"""
        functions_and_classes = []
        documented = 0
        
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                functions_and_classes.append(node)
                
                # Check if has docstring
                if (node.body and isinstance(node.body[0], ast.Expr) and
                    isinstance(node.body[0].value, ast.Constant) and
                    isinstance(node.body[0].value.value, str)):
                    documented += 1
        
        if not functions_and_classes:
            return 100.0
            
        return (documented / len(functions_and_classes)) * 100.0
    
    def _calculate_maintainability_index(self, loc: int, complexity: int, doc_coverage: float) -> float:
        """Calculate maintainability index (0-100)"""
        if loc == 0:
            return 100.0
            
        # Simplified maintainability index calculation
        # Based on Halstead Volume, Cyclomatic Complexity, and Lines of Code
        
        # Normalize complexity (lower is better)
        complexity_penalty = min(complexity / 50.0, 1.0) * 30
        
        # Normalize lines of code (moderate is best)
        if loc < 50:
            loc_penalty = 0
        elif loc < 200:
            loc_penalty = ((loc - 50) / 150.0) * 10
        else:
            loc_penalty = 10 + ((loc - 200) / 500.0) * 20
            
        loc_penalty = min(loc_penalty, 30)
        
        # Documentation bonus
        doc_bonus = (doc_coverage / 100.0) * 10
        
        # Calculate final score
        base_score = 100.0
        maintainability = base_score - complexity_penalty - loc_penalty + doc_bonus
        
        return max(0.0, min(100.0, maintainability))
    
    def _find_file_issues(self, file_path: Path, metrics: CodeMetrics) -> List[CodeIssue]:
        """Find code issues in file"""
        issues = []
        
        # High complexity
        if metrics.complexity_score > self.complexity_threshold:
            issues.append(CodeIssue(
                file_path=str(file_path),
                line_number=1,
                issue_type=IssueType.COMPLEXITY,
                severity="high" if metrics.complexity_score > 25 else "medium",
                description=f"High cyclomatic complexity: {metrics.complexity_score}",
                suggestion="Consider breaking down complex functions into smaller ones",
                estimated_fix_time=60 if metrics.complexity_score > 25 else 30
            ))
        
        # Low documentation coverage
        if metrics.documentation_coverage < self.documentation_threshold:
            issues.append(CodeIssue(
                file_path=str(file_path),
                line_number=1,
                issue_type=IssueType.DOCUMENTATION,
                severity="medium" if metrics.documentation_coverage < 50 else "low",
                description=f"Low documentation coverage: {metrics.documentation_coverage:.1f}%",
                suggestion="Add docstrings to functions and classes",
                estimated_fix_time=20
            ))
        
        # Large file size
        if metrics.lines_of_code > 500:
            issues.append(CodeIssue(
                file_path=str(file_path),
                line_number=1,
                issue_type=IssueType.STRUCTURE,
                severity="medium" if metrics.lines_of_code > 1000 else "low",
                description=f"Large file size: {metrics.lines_of_code} lines",
                suggestion="Consider splitting into multiple modules",
                estimated_fix_time=90 if metrics.lines_of_code > 1000 else 45
            ))
        
        # Low maintainability
        if metrics.maintainability_index < 50:
            issues.append(CodeIssue(
                file_path=str(file_path),
                line_number=1,
                issue_type=IssueType.MAINTAINABILITY,
                severity="high" if metrics.maintainability_index < 30 else "medium",
                description=f"Low maintainability index: {metrics.maintainability_index:.1f}",
                suggestion="Refactor to improve code structure and reduce complexity",
                estimated_fix_time=120 if metrics.maintainability_index < 30 else 60
            ))
        
        return issues
    
    def _calculate_overall_score(self, metrics: List[CodeMetrics], issues: List[CodeIssue]) -> float:
        """Calculate overall project quality score"""
        if not metrics:
            return 0.0
            
        # Average maintainability index
        avg_maintainability = sum(m.maintainability_index for m in metrics) / len(metrics)
        
        # Issue penalty
        critical_issues = sum(1 for issue in issues if issue.severity == "critical")
        high_issues = sum(1 for issue in issues if issue.severity == "high")
        medium_issues = sum(1 for issue in issues if issue.severity == "medium")
        
        issue_penalty = (critical_issues * 10) + (high_issues * 5) + (medium_issues * 2)
        
        # Files analyzed bonus (more coverage = better)
        coverage_bonus = min(len(metrics) / 20.0, 1.0) * 5
        
        final_score = avg_maintainability - issue_penalty + coverage_bonus
        return max(0.0, min(100.0, final_score))
    
    def _determine_quality_level(self, score: float) -> CodeQualityLevel:
        """Determine quality level from score"""
        if score >= 90:
            return CodeQualityLevel.EXCELLENT
        elif score >= 80:
            return CodeQualityLevel.GOOD
        elif score >= 70:
            return CodeQualityLevel.ACCEPTABLE
        elif score >= 50:
            return CodeQualityLevel.NEEDS_IMPROVEMENT
        else:
            return CodeQualityLevel.POOR
    
    def _generate_recommendations(self, issues: List[CodeIssue], metrics: List[CodeMetrics]) -> List[str]:
        """Generate quality improvement recommendations"""
        recommendations = []
        
        # Analyze issue patterns
        issue_types = Counter(issue.issue_type for issue in issues)
        severity_counts = Counter(issue.severity for issue in issues)
        
        if issue_types[IssueType.COMPLEXITY] > 5:
            recommendations.append(
                "High complexity detected in multiple files - "
                "Implement function decomposition strategy"
            )
        
        if issue_types[IssueType.DOCUMENTATION] > 10:
            recommendations.append(
                "Low documentation coverage across project - "
                "Establish documentation standards and automated checking"
            )
        
        if severity_counts["high"] > 10:
            recommendations.append(
                "Multiple high-severity issues detected - "
                "Prioritize immediate code review and refactoring"
            )
        
        # File-specific recommendations
        large_files = [m for m in metrics if m.lines_of_code > 800]
        if len(large_files) > 3:
            recommendations.append(
                "Multiple large files detected - "
                "Consider modular architecture redesign"
            )
        
        return recommendations
    
    def _generate_improvement_suggestions(self, issues: List[CodeIssue], metrics: List[CodeMetrics]) -> List[str]:
        """Generate specific improvement suggestions"""
        suggestions = []
        
        # Calculate estimated improvement time
        total_fix_time = sum(issue.estimated_fix_time for issue in issues)
        
        suggestions.append(f"Total estimated improvement time: {total_fix_time} minutes")
        
        # Priority suggestions
        critical_issues = [i for i in issues if i.severity == "critical"]
        high_issues = [i for i in issues if i.severity == "high"]
        
        if critical_issues:
            suggestions.append(
                f"Address {len(critical_issues)} critical issues immediately"
            )
        
        if high_issues:
            suggestions.append(
                f"Plan refactoring for {len(high_issues)} high-priority issues"
            )
        
        # Quality gate suggestions
        avg_maintainability = sum(m.maintainability_index for m in metrics) / len(metrics) if metrics else 0
        if avg_maintainability < 70:
            suggestions.append(
                "Implement quality gates to prevent maintainability degradation"
            )
        
        return suggestions

class MaintainabilityEnhancer:
    """Automated maintainability improvement system"""
    
    def __init__(self, project_root: Path):
        self.project_root = Path(project_root)
        self.analyzer = CodeAnalyzer(project_root)
        self.enhancement_history = []
        
    def generate_improvement_plan(self) -> Dict[str, Any]:
        """Generate comprehensive improvement plan"""
        report = self.analyzer.analyze_project()
        
        # Group issues by priority and type
        issues_by_priority = defaultdict(list)
        issues_by_type = defaultdict(list)
        
        for issue in report.issues_found:
            issues_by_priority[issue.severity].append(issue)
            issues_by_type[issue.issue_type].append(issue)
        
        # Create implementation phases
        phases = {
            "Phase 1 - Critical Issues": {
                "issues": issues_by_priority["critical"],
                "estimated_time_days": sum(i.estimated_fix_time for i in issues_by_priority["critical"]) / 480,
                "priority": 1
            },
            "Phase 2 - High Priority": {
                "issues": issues_by_priority["high"],
                "estimated_time_days": sum(i.estimated_fix_time for i in issues_by_priority["high"]) / 480,
                "priority": 2
            },
            "Phase 3 - Medium Priority": {
                "issues": issues_by_priority["medium"][:20],  # Limit to top 20
                "estimated_time_days": sum(i.estimated_fix_time for i in issues_by_priority["medium"][:20]) / 480,
                "priority": 3
            },
            "Phase 4 - Maintenance": {
                "issues": issues_by_priority["low"][:10],  # Limit to top 10
                "estimated_time_days": sum(i.estimated_fix_time for i in issues_by_priority["low"][:10]) / 480,
                "priority": 4
            }
        }
        
        return {
            "report": report,
            "improvement_phases": phases,
            "total_estimated_days": sum(phase["estimated_time_days"] for phase in phases.values()),
            "roi_estimate": self._calculate_maintenance_roi(report),
            "automated_fixes": self._identify_automated_fixes(report.issues_found)
        }
    
    def _calculate_maintenance_roi(self, report: QualityReport) -> Dict[str, Any]:
        """Calculate ROI for maintenance improvements"""
        # Simplified ROI calculation
        current_maintenance_cost = 100 - report.overall_score  # Higher score = lower maintenance
        
        potential_improvement = min(30, current_maintenance_cost * 0.6)  # Conservative estimate
        
        return {
            "current_maintenance_overhead": f"{current_maintenance_cost:.1f}%",
            "potential_reduction": f"{potential_improvement:.1f}%",
            "estimated_yearly_savings_hours": potential_improvement * 10,  # Rough estimate
            "payback_period_weeks": 4  # Typical refactoring payback
        }
    
    def _identify_automated_fixes(self, issues: List[CodeIssue]) -> List[Dict[str, Any]]:
        """Identify issues that can be automatically fixed"""
        automated_fixes = []
        
        # Documentation issues can often be semi-automated
        doc_issues = [i for i in issues if i.issue_type == IssueType.DOCUMENTATION]
        if len(doc_issues) > 5:
            automated_fixes.append({
                "type": "documentation_generation",
                "description": "Generate skeleton docstrings for undocumented functions",
                "affected_files": len(set(i.file_path for i in doc_issues)),
                "tool": "automated_docstring_generator"
            })
        
        # Import organization
        automated_fixes.append({
            "type": "import_organization",
            "description": "Organize and optimize import statements",
            "affected_files": "all",
            "tool": "isort + automated script"
        })
        
        # Code formatting
        automated_fixes.append({
            "type": "code_formatting", 
            "description": "Apply consistent code formatting",
            "affected_files": "all",
            "tool": "black + flake8"
        })
        
        return automated_fixes

# Global instances
_project_root = Path.cwd()
code_analyzer = CodeAnalyzer(_project_root)
maintainability_enhancer = MaintainabilityEnhancer(_project_root)

def analyze_code_quality() -> QualityReport:
    """Analyze current code quality"""
    return code_analyzer.analyze_project()

def generate_improvement_plan() -> Dict[str, Any]:
    """Generate improvement plan"""
    return maintainability_enhancer.generate_improvement_plan()

def get_quality_metrics() -> Dict[str, Any]:
    """Get current quality metrics"""
    report = analyze_code_quality()
    return {
        "overall_score": report.overall_score,
        "quality_level": report.quality_level.value,
        "files_analyzed": report.files_analyzed,
        "total_issues": len(report.issues_found),
        "critical_issues": len([i for i in report.issues_found if i.severity == "critical"]),
        "high_issues": len([i for i in report.issues_found if i.severity == "high"]),
        "medium_issues": len([i for i in report.issues_found if i.severity == "medium"]),
        "low_issues": len([i for i in report.issues_found if i.severity == "low"])
    }