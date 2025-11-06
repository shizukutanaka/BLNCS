"""
Automated documentation generation system for BLNCS
Implements comprehensive documentation generation from code, APIs, and configurations
based on competitor analysis and industry best practices
"""

import os
import re
import json
import inspect
import ast
import textwrap
from typing import Dict, List, Optional, Set, Tuple, Any, Callable, TypeVar, Union
from dataclasses import dataclass, field
from enum import Enum
import logging
from pathlib import Path
import datetime
import markdown
import jinja2
from jinja2 import Environment, FileSystemLoader
import yaml
import shutil


class DocumentationType(Enum):
    """Types of documentation"""
    API_REFERENCE = "api_reference"
    CODE_DOCUMENTATION = "code_documentation"
    USER_GUIDE = "user_guide"
    DEVELOPER_GUIDE = "developer_guide"
    CONFIGURATION_GUIDE = "configuration_guide"
    DEPLOYMENT_GUIDE = "deployment_guide"


class DocumentationFormat(Enum):
    """Documentation output formats"""
    MARKDOWN = "markdown"
    HTML = "html"
    PDF = "pdf"
    JSON = "json"
    YAML = "yaml"


@dataclass
class DocumentationSection:
    """Documentation section"""
    title: str
    content: str
    level: int = 1  # Header level (1-6)
    subsections: List['DocumentationSection'] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class APIDocumentation:
    """API endpoint documentation"""
    endpoint: str
    method: str
    summary: str
    description: str
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    responses: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    examples: List[Dict[str, str]] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)


@dataclass
class CodeDocumentation:
    """Code element documentation"""
    name: str
    type: str  # function, class, module, etc.
    signature: str
    docstring: str
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    returns: Optional[Dict[str, Any]] = None
    examples: List[str] = field(default_factory=list)
    file_path: str = ""
    line_number: int = 0


class CodeAnalyzer:
    """Code analysis for documentation generation"""

    def __init__(self, source_paths: List[str]):
        """
        Initialize code analyzer

        Args:
            source_paths: List of source code paths to analyze
        """
        self.source_paths = [Path(p) for p in source_paths]
        self.logger = logging.getLogger(__name__)

    def analyze_module(self, module_path: Path) -> Dict[str, Any]:
        """
        Analyze Python module for documentation

        Args:
            module_path: Path to Python module

        Returns:
            Module analysis results
        """
        try:
            with open(module_path, 'r', encoding='utf-8') as f:
                content = f.read()

            tree = ast.parse(content)
            analyzer = ModuleAnalyzer()
            analyzer.visit(tree)

            return {
                'module_name': module_path.stem,
                'file_path': str(module_path),
                'classes': analyzer.classes,
                'functions': analyzer.functions,
                'imports': analyzer.imports,
                'docstring': self._extract_module_docstring(content)
            }

        except Exception as e:
            self.logger.error(f"Error analyzing module {module_path}: {e}")
            return {}

    def _extract_module_docstring(self, content: str) -> str:
        """Extract module-level docstring"""
        try:
            tree = ast.parse(content)
            if tree.body and isinstance(tree.body[0], ast.Expr) and isinstance(tree.body[0].value, ast.Str):
                return tree.body[0].value.s
        except:
            pass
        return ""

    def analyze_package(self, package_path: Path) -> Dict[str, Any]:
        """
        Analyze entire package

        Args:
            package_path: Path to package directory

        Returns:
            Package analysis results
        """
        package_info = {
            'package_name': package_path.name,
            'modules': [],
            'subpackages': []
        }

        for item in package_path.rglob('*.py'):
            if item.is_file() and not item.name.startswith('__'):
                module_info = self.analyze_module(item)
                if module_info:
                    package_info['modules'].append(module_info)

        for item in package_path.iterdir():
            if item.is_dir() and not item.name.startswith('.') and (item / '__init__.py').exists():
                subpackage_info = self.analyze_package(item)
                package_info['subpackages'].append(subpackage_info)

        return package_info


class ModuleAnalyzer(ast.NodeVisitor):
    """AST visitor for module analysis"""

    def __init__(self):
        self.classes = []
        self.functions = []
        self.imports = []

    def visit_ClassDef(self, node):
        """Visit class definition"""
        class_info = {
            'name': node.name,
            'docstring': self._extract_docstring(node),
            'methods': [],
            'bases': [base.id if isinstance(base, ast.Name) else str(base) for base in node.bases],
            'line_number': node.lineno
        }

        # Extract methods
        for item in node.body:
            if isinstance(item, ast.FunctionDef):
                method_info = {
                    'name': item.name,
                    'signature': f"{item.name}({', '.join(arg.arg for arg in item.args.args[1:])})",  # Skip 'self'
                    'docstring': self._extract_docstring(item),
                    'line_number': item.lineno
                }
                class_info['methods'].append(method_info)

        self.classes.append(class_info)

    def visit_FunctionDef(self, node):
        """Visit function definition"""
        if not node.name.startswith('_'):  # Skip private functions
            func_info = {
                'name': node.name,
                'signature': f"{node.name}({', '.join(arg.arg for arg in node.args.args)})",
                'docstring': self._extract_docstring(node),
                'line_number': node.lineno
            }
            self.functions.append(func_info)

    def visit_Import(self, node):
        """Visit import statement"""
        for alias in node.names:
            self.imports.append({
                'name': alias.name,
                'asname': alias.asname,
                'module': True
            })

    def visit_ImportFrom(self, node):
        """Visit from import statement"""
        module = node.module or ''
        for alias in node.names:
            self.imports.append({
                'name': f"{module}.{alias.name}",
                'asname': alias.asname,
                'module': module,
                'attribute': alias.name
            })

    def _extract_docstring(self, node) -> str:
        """Extract docstring from AST node"""
        if node.body and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Str):
            return node.body[0].value.s
        return ""


class APIDocumentationGenerator:
    """API documentation generator"""

    def __init__(self, api_endpoints: Dict[str, Any]):
        """
        Initialize API documentation generator

        Args:
            api_endpoints: API endpoint definitions
        """
        self.api_endpoints = api_endpoints
        self.logger = logging.getLogger(__name__)

    def generate_openapi_spec(self) -> Dict[str, Any]:
        """Generate OpenAPI specification"""
        spec = {
            'openapi': '3.0.3',
            'info': {
                'title': 'BLNCS Lightning Network API',
                'version': '1.0.0',
                'description': 'Comprehensive API for BLNCS Lightning Network operations'
            },
            'servers': [
                {
                    'url': 'https://api.blncs.example.com/v1',
                    'description': 'Production server'
                }
            ],
            'paths': {},
            'components': {
                'securitySchemes': {
                    'ApiKeyAuth': {
                        'type': 'apiKey',
                        'in': 'header',
                        'name': 'X-API-Key'
                    },
                    'BearerAuth': {
                        'type': 'http',
                        'scheme': 'bearer'
                    }
                },
                'schemas': self._generate_schemas()
            }
        }

        # Generate paths
        for endpoint_path, endpoint_data in self.api_endpoints.items():
            spec['paths'][endpoint_path] = self._generate_path_spec(endpoint_path, endpoint_data)

        return spec

    def _generate_path_spec(self, path: str, endpoint_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate OpenAPI path specification"""
        path_spec = {}

        methods = endpoint_data.get('methods', ['GET'])
        for method in methods:
            method_spec = {
                'summary': endpoint_data.get('summary', f'{method.upper()} {path}'),
                'description': endpoint_data.get('description', ''),
                'responses': self._generate_responses(endpoint_data.get('responses', {}))
            }

            # Add parameters
            if endpoint_data.get('parameters'):
                method_spec['parameters'] = endpoint_data['parameters']

            # Add request body
            if method.upper() in ['POST', 'PUT', 'PATCH'] and endpoint_data.get('request_body'):
                method_spec['requestBody'] = endpoint_data['request_body']

            # Add security
            if endpoint_data.get('auth_required'):
                method_spec['security'] = [
                    {'ApiKeyAuth': []},
                    {'BearerAuth': []}
                ]

            path_spec[method.lower()] = method_spec

        return path_spec

    def _generate_responses(self, responses: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Generate OpenAPI responses"""
        default_responses = {
            '200': {
                'description': 'Successful response',
                'content': {
                    'application/json': {
                        'schema': {'type': 'object'}
                    }
                }
            },
            '400': {
                'description': 'Bad request',
                'content': {
                    'application/json': {
                        'schema': {
                            'type': 'object',
                            'properties': {
                                'error': {'type': 'string'}
                            }
                        }
                    }
                }
            },
            '401': {
                'description': 'Unauthorized',
                'content': {
                    'application/json': {
                        'schema': {
                            'type': 'object',
                            'properties': {
                                'error': {'type': 'string'}
                            }
                        }
                    }
                }
            }
        }

        # Merge with custom responses
        default_responses.update(responses)
        return default_responses

    def _generate_schemas(self) -> Dict[str, Dict[str, Any]]:
        """Generate OpenAPI schemas"""
        return {
            'Error': {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'},
                    'code': {'type': 'integer'},
                    'details': {'type': 'object'}
                }
            },
            'Invoice': {
                'type': 'object',
                'properties': {
                    'payment_request': {'type': 'string'},
                    'amount': {'type': 'integer'},
                    'description': {'type': 'string'},
                    'expiry': {'type': 'integer'}
                }
            },
            'Payment': {
                'type': 'object',
                'properties': {
                    'payment_hash': {'type': 'string'},
                    'amount': {'type': 'integer'},
                    'status': {'type': 'string'},
                    'timestamp': {'type': 'integer'}
                }
            }
        }


class DocumentationGenerator:
    """Main documentation generation system"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize documentation generator

        Args:
            config: Documentation configuration
        """
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        # Template environment
        self.template_dir = Path(__file__).parent / 'templates'
        self.template_env = Environment(
            loader=FileSystemLoader(self.template_dir),
            trim_blocks=True,
            lstrip_blocks=True
        )

        # Documentation components
        self.code_analyzer = CodeAnalyzer(self.config.get('source_paths', []))
        self.api_generator = APIDocumentationGenerator(self.config.get('api_endpoints', {}))

        # Generated documentation cache
        self.generated_docs: Dict[str, str] = {}

    def generate_documentation(
        self,
        doc_type: DocumentationType,
        format_type: DocumentationFormat = DocumentationFormat.MARKDOWN,
        output_dir: Optional[str] = None
    ) -> str:
        """
        Generate documentation

        Args:
            doc_type: Type of documentation to generate
            format_type: Output format
            output_dir: Output directory (optional)

        Returns:
            Generated documentation content
        """
        try:
            if doc_type == DocumentationType.API_REFERENCE:
                content = self._generate_api_reference(format_type)
            elif doc_type == DocumentationType.CODE_DOCUMENTATION:
                content = self._generate_code_documentation(format_type)
            elif doc_type == DocumentationType.USER_GUIDE:
                content = self._generate_user_guide(format_type)
            elif doc_type == DocumentationType.DEVELOPER_GUIDE:
                content = self._generate_developer_guide(format_type)
            elif doc_type == DocumentationType.CONFIGURATION_GUIDE:
                content = self._generate_configuration_guide(format_type)
            elif doc_type == DocumentationType.DEPLOYMENT_GUIDE:
                content = self._generate_deployment_guide(format_type)
            else:
                raise ValueError(f"Unsupported documentation type: {doc_type}")

            # Save to file if output directory specified
            if output_dir:
                self._save_documentation(content, doc_type, format_type, output_dir)

            self.generated_docs[f"{doc_type.value}_{format_type.value}"] = content
            return content

        except Exception as e:
            self.logger.error(f"Documentation generation failed: {e}")
            return f"Error generating documentation: {e}"

    def _generate_api_reference(self, format_type: DocumentationFormat) -> str:
        """Generate API reference documentation"""
        if format_type == DocumentationFormat.JSON:
            return json.dumps(self.api_generator.generate_openapi_spec(), indent=2)
        elif format_type == DocumentationFormat.YAML:
            return yaml.dump(self.api_generator.generate_openapi_spec(), default_flow_style=False)
        elif format_type == DocumentationFormat.MARKDOWN:
            return self._render_template('api_reference.md', {
                'openapi_spec': self.api_generator.generate_openapi_spec(),
                'timestamp': datetime.datetime.now().isoformat()
            })
        else:
            return "API reference generation not implemented for this format"

    def _generate_code_documentation(self, format_type: DocumentationFormat) -> str:
        """Generate code documentation"""
        # Analyze codebase
        codebase_analysis = {}
        for source_path in self.code_analyzer.source_paths:
            if source_path.is_dir():
                codebase_analysis[source_path.name] = self.code_analyzer.analyze_package(source_path)
            elif source_path.is_file():
                codebase_analysis[source_path.stem] = self.code_analyzer.analyze_module(source_path)

        if format_type == DocumentationFormat.MARKDOWN:
            return self._render_template('code_documentation.md', {
                'codebase': codebase_analysis,
                'timestamp': datetime.datetime.now().isoformat()
            })
        elif format_type == DocumentationFormat.JSON:
            return json.dumps(codebase_analysis, indent=2, default=str)
        else:
            return "Code documentation generation not implemented for this format"

    def _generate_user_guide(self, format_type: DocumentationFormat) -> str:
        """Generate user guide"""
        guide_content = {
            'title': 'BLNCS User Guide',
            'sections': [
                {
                    'title': 'Getting Started',
                    'content': 'Installation and basic setup instructions...'
                },
                {
                    'title': 'Basic Operations',
                    'content': 'How to create invoices, make payments, and manage channels...'
                },
                {
                    'title': 'Advanced Features',
                    'content': 'Monitoring, automation, and enterprise features...'
                },
                {
                    'title': 'Troubleshooting',
                    'content': 'Common issues and solutions...'
                }
            ],
            'timestamp': datetime.datetime.now().isoformat()
        }

        if format_type == DocumentationFormat.MARKDOWN:
            return self._render_template('user_guide.md', guide_content)
        else:
            return json.dumps(guide_content, indent=2)

    def _generate_developer_guide(self, format_type: DocumentationFormat) -> str:
        """Generate developer guide"""
        guide_content = {
            'title': 'BLNCS Developer Guide',
            'sections': [
                {
                    'title': 'Architecture Overview',
                    'content': 'System architecture and component relationships...'
                },
                {
                    'title': 'API Integration',
                    'content': 'How to integrate with BLNCS APIs...'
                },
                {
                    'title': 'Extending BLNCS',
                    'content': 'Adding new features and modules...'
                },
                {
                    'title': 'Testing',
                    'content': 'Unit tests, integration tests, and CI/CD...'
                }
            ],
            'timestamp': datetime.datetime.now().isoformat()
        }

        if format_type == DocumentationFormat.MARKDOWN:
            return self._render_template('developer_guide.md', guide_content)
        else:
            return json.dumps(guide_content, indent=2)

    def _generate_configuration_guide(self, format_type: DocumentationFormat) -> str:
        """Generate configuration guide"""
        config_guide = {
            'title': 'BLNCS Configuration Guide',
            'configurations': [
                {
                    'section': 'Lightning Network',
                    'parameters': [
                        {'name': 'network', 'type': 'string', 'default': 'testnet', 'description': 'Bitcoin network'},
                        {'name': 'node_url', 'type': 'string', 'description': 'Lightning node URL'},
                        {'name': 'max_channels', 'type': 'integer', 'default': 25, 'description': 'Maximum channels'}
                    ]
                },
                {
                    'section': 'Database',
                    'parameters': [
                        {'name': 'url', 'type': 'string', 'default': 'sqlite:///./blncs.db', 'description': 'Database URL'},
                        {'name': 'pool_size', 'type': 'integer', 'default': 10, 'description': 'Connection pool size'}
                    ]
                }
            ],
            'timestamp': datetime.datetime.now().isoformat()
        }

        if format_type == DocumentationFormat.MARKDOWN:
            return self._render_template('configuration_guide.md', config_guide)
        else:
            return json.dumps(config_guide, indent=2)

    def _generate_deployment_guide(self, format_type: DocumentationFormat) -> str:
        """Generate deployment guide"""
        deployment_guide = {
            'title': 'BLNCS Deployment Guide',
            'environments': [
                {
                    'name': 'Development',
                    'requirements': ['Python 3.8+', 'SQLite'],
                    'steps': ['Clone repository', 'Install dependencies', 'Run setup script']
                },
                {
                    'name': 'Production',
                    'requirements': ['Python 3.8+', 'PostgreSQL', 'Redis', 'Nginx'],
                    'steps': ['Server provisioning', 'SSL certificate setup', 'Database setup', 'Application deployment']
                }
            ],
            'timestamp': datetime.datetime.now().isoformat()
        }

        if format_type == DocumentationFormat.MARKDOWN:
            return self._render_template('deployment_guide.md', deployment_guide)
        else:
            return json.dumps(deployment_guide, indent=2)

    def _render_template(self, template_name: str, context: Dict[str, Any]) -> str:
        """Render Jinja2 template"""
        try:
            template = self.template_env.get_template(template_name)
            return template.render(**context)
        except Exception as e:
            self.logger.error(f"Template rendering failed: {e}")
            return f"Error rendering template {template_name}: {e}"

    def _save_documentation(
        self,
        content: str,
        doc_type: DocumentationType,
        format_type: DocumentationFormat,
        output_dir: str
    ):
        """Save documentation to file"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        filename = f"{doc_type.value}.{format_type.value}"
        filepath = output_path / filename

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)

        self.logger.info(f"Documentation saved to {filepath}")

    def generate_all_documentation(self, output_dir: str, formats: Optional[List[DocumentationFormat]] = None):
        """
        Generate all documentation types

        Args:
            output_dir: Output directory
            formats: List of formats to generate (default: all)
        """
        if formats is None:
            formats = [DocumentationFormat.MARKDOWN, DocumentationFormat.HTML, DocumentationFormat.JSON]

        for doc_type in DocumentationType:
            for format_type in formats:
                try:
                    self.generate_documentation(doc_type, format_type, output_dir)
                except Exception as e:
                    self.logger.error(f"Failed to generate {doc_type.value} in {format_type.value}: {e}")

    def create_documentation_website(self, output_dir: str):
        """
        Create a complete documentation website

        Args:
            output_dir: Output directory for website
        """
        website_dir = Path(output_dir) / 'docs'
        website_dir.mkdir(parents=True, exist_ok=True)

        # Generate all documentation in HTML and Markdown
        self.generate_all_documentation(str(website_dir), [DocumentationFormat.HTML, DocumentationFormat.MARKDOWN])

        # Create index page
        index_content = '''
# BLNCS Documentation

Welcome to the comprehensive BLNCS documentation site.

## Documentation Sections

### User Documentation
- [User Guide](user_guide.html) - Getting started and basic usage
- [Configuration Guide](configuration_guide.html) - System configuration
- [Deployment Guide](deployment_guide.html) - Installation and deployment

### Developer Documentation
- [API Reference](api_reference.html) - Complete API documentation
- [Developer Guide](developer_guide.html) - Development and integration
- [Code Documentation](code_documentation.html) - Source code documentation

### Additional Resources
- [GitHub Repository](https://github.com/blncs/blncs)
- [Issue Tracker](https://github.com/blncs/blncs/issues)
- [Community Forum](https://forum.blncs.example.com)

---

*Generated on: {{ timestamp }}*
'''

        index_data = {
            'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

        index_html = self._render_template('index.md', index_data)
        (website_dir / 'README.md').write_text(index_html)

        # Create simple HTML wrapper if needed
        html_wrapper = '''
<!DOCTYPE html>
<html>
<head>
    <title>{{ title }}</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; max-width: 800px; margin: 0 auto; padding: 20px; }
        h1, h2, h3 { color: #333; }
        code { background: #f4f4f4; padding: 2px 4px; border-radius: 3px; }
        pre { background: #f4f4f4; padding: 10px; border-radius: 5px; overflow-x: auto; }
        .nav { background: #f8f9fa; padding: 10px; border-radius: 5px; margin-bottom: 20px; }
        .nav a { margin-right: 15px; text-decoration: none; color: #007bff; }
    </style>
</head>
<body>
    <div class="nav">
        <a href="index.html">Home</a>
        <a href="user_guide.html">User Guide</a>
        <a href="api_reference.html">API Reference</a>
        <a href="developer_guide.html">Developer Guide</a>
    </div>
    <article>
        {{ content }}
    </article>
</body>
</html>
'''

        # Convert Markdown files to HTML
        try:
            import markdown
            for md_file in website_dir.glob('*.md'):
                if md_file.name != 'README.md':
                    with open(md_file, 'r', encoding='utf-8') as f:
                        md_content = f.read()

                    html_content = markdown.markdown(md_content, extensions=['fenced_code', 'tables'])
                    html_full = html_wrapper.replace('{{ content }}', html_content).replace('{{ title }}', md_file.stem.replace('_', ' ').title())

                    html_file = md_file.with_suffix('.html')
                    with open(html_file, 'w', encoding='utf-8') as f:
                        f.write(html_full)

        except ImportError:
            self.logger.warning("Markdown package not available, skipping HTML generation")

        self.logger.info(f"Documentation website created at {website_dir}")


# Global documentation generator instance
_documentation_generator = None

def get_documentation_generator() -> DocumentationGenerator:
    """Get the global documentation generator instance"""
    global _documentation_generator
    if _documentation_generator is None:
        # Default configuration
        config = {
            'source_paths': ['blncs'],
            'api_endpoints': {
                '/info': {
                    'methods': ['GET'],
                    'summary': 'Get node information',
                    'description': 'Retrieve basic information about the Lightning node'
                },
                '/balance': {
                    'methods': ['GET'],
                    'summary': 'Get wallet balance',
                    'description': 'Retrieve current wallet balance'
                },
                '/invoice': {
                    'methods': ['POST'],
                    'summary': 'Create invoice',
                    'description': 'Create a new Lightning payment invoice',
                    'parameters': [
                        {
                            'name': 'amount',
                            'in': 'query',
                            'required': True,
                            'schema': {'type': 'integer'},
                            'description': 'Invoice amount in satoshis'
                        }
                    ]
                },
                '/pay': {
                    'methods': ['POST'],
                    'summary': 'Send payment',
                    'description': 'Send a Lightning payment',
                    'request_body': {
                        'required': True,
                        'content': {
                            'application/json': {
                                'schema': {
                                    'type': 'object',
                                    'properties': {
                                        'invoice': {'type': 'string'}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        _documentation_generator = DocumentationGenerator(config)
    return _documentation_generator
