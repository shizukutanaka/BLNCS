#!/usr/bin/env python3
"""
BLNCS Documentation Content Generator
Automatic generation of documentation from code analysis and templates.
"""

import ast
import inspect
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Union, Set
from dataclasses import dataclass, field
import re
import json
from datetime import datetime

try:
    from .documentation_manager import DocumentSection, get_documentation_manager
except ImportError:
    # For standalone testing
    import sys
    sys.path.append(str(Path(__file__).parent))
    from documentation_manager import DocumentSection, get_documentation_manager

logger = logging.getLogger(__name__)


@dataclass
class CodeElement:
    """Represents a code element for documentation"""
    name: str
    type: str  # function, class, module, method
    description: str
    signature: str = ''
    parameters: List[Dict[str, str]] = field(default_factory=list)
    returns: Optional[str] = None
    examples: List[str] = field(default_factory=list)
    module_path: str = ''
    line_number: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'type': self.type,
            'description': self.description,
            'signature': self.signature,
            'parameters': self.parameters,
            'returns': self.returns,
            'examples': self.examples,
            'module_path': self.module_path,
            'line_number': self.line_number
        }


class CodeAnalyzer:
    """Analyze Python code to extract documentation information"""
    
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.analyzed_modules: Dict[str, List[CodeElement]] = {}
    
    def analyze_module(self, module_path: Path) -> List[CodeElement]:
        """Analyze a Python module and extract code elements"""
        elements = []
        
        try:
            with open(module_path, 'r', encoding='utf-8') as f:
                source_code = f.read()
            
            # Parse AST
            tree = ast.parse(source_code)
            
            # Extract elements
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    element = self._analyze_function(node, module_path)
                    if element:
                        elements.append(element)
                elif isinstance(node, ast.ClassDef):
                    element = self._analyze_class(node, module_path)
                    if element:
                        elements.append(element)
                        # Analyze methods within the class
                        for item in node.body:
                            if isinstance(item, ast.FunctionDef):
                                method_element = self._analyze_method(item, node.name, module_path)
                                if method_element:
                                    elements.append(method_element)
            
            return elements
            
        except Exception as e:
            logger.error(f"Failed to analyze module {module_path}: {e}")
            return []
    
    def _analyze_function(self, node: ast.FunctionDef, module_path: Path) -> Optional[CodeElement]:
        """Analyze a function definition"""
        try:
            # Get docstring
            docstring = ast.get_docstring(node) or "No description available"
            
            # Get signature
            signature = self._get_function_signature(node)
            
            # Parse docstring for parameters and returns
            parameters, returns = self._parse_docstring(docstring)
            
            return CodeElement(
                name=node.name,
                type='function',
                description=docstring,
                signature=signature,
                parameters=parameters,
                returns=returns,
                module_path=str(module_path),
                line_number=node.lineno
            )
            
        except Exception as e:
            logger.error(f"Failed to analyze function {node.name}: {e}")
            return None
    
    def _analyze_class(self, node: ast.ClassDef, module_path: Path) -> Optional[CodeElement]:
        """Analyze a class definition"""
        try:
            # Get docstring
            docstring = ast.get_docstring(node) or "No description available"
            
            # Get base classes
            bases = [self._get_name(base) for base in node.bases]
            signature = f"class {node.name}({', '.join(bases)})" if bases else f"class {node.name}"
            
            return CodeElement(
                name=node.name,
                type='class',
                description=docstring,
                signature=signature,
                module_path=str(module_path),
                line_number=node.lineno
            )
            
        except Exception as e:
            logger.error(f"Failed to analyze class {node.name}: {e}")
            return None
    
    def _analyze_method(self, node: ast.FunctionDef, class_name: str, module_path: Path) -> Optional[CodeElement]:
        """Analyze a method definition"""
        try:
            # Get docstring
            docstring = ast.get_docstring(node) or "No description available"
            
            # Get signature
            signature = self._get_function_signature(node)
            
            # Parse docstring for parameters and returns
            parameters, returns = self._parse_docstring(docstring)
            
            return CodeElement(
                name=f"{class_name}.{node.name}",
                type='method',
                description=docstring,
                signature=signature,
                parameters=parameters,
                returns=returns,
                module_path=str(module_path),
                line_number=node.lineno
            )
            
        except Exception as e:
            logger.error(f"Failed to analyze method {node.name}: {e}")
            return None
    
    def _get_function_signature(self, node: ast.FunctionDef) -> str:
        """Get function signature as string"""
        try:
            args = []
            
            # Regular arguments
            for arg in node.args.args:
                args.append(arg.arg)
            
            # Default arguments
            defaults_offset = len(node.args.args) - len(node.args.defaults)
            for i, default in enumerate(node.args.defaults):
                arg_index = defaults_offset + i
                if arg_index < len(args):
                    args[arg_index] += f"={ast.unparse(default)}"
            
            # *args
            if node.args.vararg:
                args.append(f"*{node.args.vararg.arg}")
            
            # **kwargs
            if node.args.kwarg:
                args.append(f"**{node.args.kwarg.arg}")
            
            return f"{node.name}({', '.join(args)})"
            
        except Exception as e:
            logger.error(f"Failed to get signature for {node.name}: {e}")
            return f"{node.name}(...)"
    
    def _get_name(self, node) -> str:
        """Get name from AST node"""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return f"{self._get_name(node.value)}.{node.attr}"
        else:
            return str(node)
    
    def _parse_docstring(self, docstring: str) -> tuple[List[Dict[str, str]], Optional[str]]:
        """Parse docstring to extract parameters and return information"""
        parameters = []
        returns = None
        
        # Simple docstring parsing (could be enhanced with sphinx/google/numpy style parsing)
        lines = docstring.split('\n')
        current_section = None
        
        for line in lines:
            line = line.strip()
            
            if line.lower().startswith('parameters:') or line.lower().startswith('args:'):
                current_section = 'params'
                continue
            elif line.lower().startswith('returns:') or line.lower().startswith('return:'):
                current_section = 'returns'
                continue
            elif line.startswith('- ') and current_section == 'params':
                # Parameter description
                param_match = re.match(r'- (\w+)(?:\s*\(([^)]+)\))?\s*:\s*(.*)', line)
                if param_match:
                    param_name, param_type, param_desc = param_match.groups()
                    parameters.append({
                        'name': param_name,
                        'type': param_type or 'Any',
                        'description': param_desc
                    })
            elif current_section == 'returns' and line:
                returns = line
        
        return parameters, returns
    
    def analyze_project(self, patterns: List[str] = None) -> Dict[str, List[CodeElement]]:
        """Analyze entire project"""
        if patterns is None:
            patterns = ['**/*.py']
        
        results = {}
        
        for pattern in patterns:
            for py_file in self.project_root.glob(pattern):
                # Skip test files and __pycache__
                if 'test_' in py_file.name or '__pycache__' in str(py_file):
                    continue
                
                module_name = str(py_file.relative_to(self.project_root))
                elements = self.analyze_module(py_file)
                
                if elements:
                    results[module_name] = elements
        
        self.analyzed_modules = results
        return results


class ContentGenerator:
    """Generate documentation content from various sources"""
    
    def __init__(self, project_root: str = None):
        self.project_root = Path(project_root or Path(__file__).parent.parent.parent)
        self.doc_manager = get_documentation_manager()
        self.analyzer = CodeAnalyzer(str(self.project_root))
        self.templates = self._load_templates()
    
    def _load_templates(self) -> Dict[str, str]:
        """Load documentation templates"""
        templates = {
            'api_reference': '''# {module_name} API Reference

{module_description}

## Functions

{functions}

## Classes

{classes}

## Usage Examples

{examples}
''',
            
            'function_doc': '''### {name}

```python
{signature}
```

{description}

{parameters}

{returns}

{examples}
''',
            
            'class_doc': '''### {name}

```python
{signature}
```

{description}

#### Methods

{methods}
''',
            
            'cli_reference': '''# CLI Command Reference

## {command_name}

**Usage:** `{usage}`

{description}

### Options

{options}

### Examples

{examples}
''',
            
            'troubleshooting': '''# {issue_name} Troubleshooting

## Problem Description

{description}

## Common Causes

{causes}

## Solutions

{solutions}

## Prevention

{prevention}
'''
        }
        
        return templates
    
    def generate_api_documentation(self, module_patterns: List[str] = None) -> List[DocumentSection]:
        """Generate API documentation from code analysis"""
        logger.info("Generating API documentation from code analysis")
        
        # Analyze project code
        analyzed = self.analyzer.analyze_project(module_patterns)
        
        sections = []
        
        for module_path, elements in analyzed.items():
            # Group elements by type
            functions = [e for e in elements if e.type == 'function']
            classes = [e for e in elements if e.type == 'class']
            methods = [e for e in elements if e.type == 'method']
            
            # Skip modules with no public elements
            if not functions and not classes:
                continue
            
            # Generate module documentation
            module_name = module_path.replace('/', '.').replace('.py', '')
            
            # Functions section
            functions_content = []
            for func in functions:
                func_content = self._format_function_doc(func)
                functions_content.append(func_content)
            
            # Classes section
            classes_content = []
            for cls in classes:
                cls_methods = [m for m in methods if m.name.startswith(cls.name + '.')]
                cls_content = self._format_class_doc(cls, cls_methods)
                classes_content.append(cls_content)
            
            # Create section content
            content = self.templates['api_reference'].format(
                module_name=module_name,
                module_description=f"API reference for {module_name} module",
                functions='\n\n'.join(functions_content) if functions_content else 'No public functions.',
                classes='\n\n'.join(classes_content) if classes_content else 'No public classes.',
                examples=self._generate_usage_examples(module_name, elements)
            )
            
            # Create documentation section
            section = DocumentSection(
                id=f"api_{module_name.replace('.', '_')}",
                title=f"{module_name} API Reference",
                content=content,
                category='api_reference',
                tags=['api', 'reference', module_name.split('.')[-1]],
                difficulty='intermediate'
            )
            
            sections.append(section)
        
        logger.info(f"Generated {len(sections)} API documentation sections")
        return sections
    
    def _format_function_doc(self, func: CodeElement) -> str:
        """Format function documentation"""
        # Parameters section
        params_content = ""
        if func.parameters:
            params_lines = ["**Parameters:**"]
            for param in func.parameters:
                params_lines.append(f"- `{param['name']}` ({param['type']}): {param['description']}")
            params_content = '\n'.join(params_lines)
        
        # Returns section
        returns_content = ""
        if func.returns:
            returns_content = f"**Returns:** {func.returns}"
        
        # Examples section
        examples_content = ""
        if func.examples:
            examples_lines = ["**Examples:**"]
            for example in func.examples:
                examples_lines.append(f"```python\n{example}\n```")
            examples_content = '\n'.join(examples_lines)
        
        return self.templates['function_doc'].format(
            name=func.name,
            signature=func.signature,
            description=func.description,
            parameters=params_content,
            returns=returns_content,
            examples=examples_content
        )
    
    def _format_class_doc(self, cls: CodeElement, methods: List[CodeElement]) -> str:
        """Format class documentation"""
        # Methods section
        methods_content = []
        for method in methods:
            # Remove class name prefix from method name
            method_name = method.name.split('.')[-1]
            if not method_name.startswith('_'):  # Only document public methods
                method_doc = f"**{method_name}**\n```python\n{method.signature}\n```\n{method.description}\n"
                methods_content.append(method_doc)
        
        return self.templates['class_doc'].format(
            name=cls.name,
            signature=cls.signature,
            description=cls.description,
            methods='\n'.join(methods_content) if methods_content else 'No public methods documented.'
        )
    
    def _generate_usage_examples(self, module_name: str, elements: List[CodeElement]) -> str:
        """Generate usage examples for a module"""
        examples = []
        
        # Basic import example
        examples.append(f"```python\nfrom {module_name} import *\n```")
        
        # Function usage examples
        functions = [e for e in elements if e.type == 'function' and not e.name.startswith('_')]
        if functions:
            example_func = functions[0]  # Use first public function
            examples.append(f"```python\n# Example usage of {example_func.name}\nresult = {example_func.name}()\nprint(result)\n```")
        
        # Class usage examples
        classes = [e for e in elements if e.type == 'class' and not e.name.startswith('_')]
        if classes:
            example_class = classes[0]  # Use first public class
            examples.append(f"```python\n# Example usage of {example_class.name}\ninstance = {example_class.name}()\n# Use instance methods here\n```")
        
        return '\n\n'.join(examples)
    
    def generate_cli_documentation(self, cli_commands: Dict[str, Dict[str, Any]] = None) -> List[DocumentSection]:
        """Generate CLI command documentation"""
        logger.info("Generating CLI documentation")
        
        if cli_commands is None:
            cli_commands = self._discover_cli_commands()
        
        sections = []
        
        for command_name, command_info in cli_commands.items():
            content = self.templates['cli_reference'].format(
                command_name=command_name,
                usage=command_info.get('usage', f'blncs {command_name} [OPTIONS]'),
                description=command_info.get('description', 'No description available.'),
                options=self._format_cli_options(command_info.get('options', [])),
                examples=self._format_cli_examples(command_info.get('examples', []))
            )
            
            section = DocumentSection(
                id=f"cli_{command_name.replace(' ', '_')}",
                title=f"CLI: {command_name}",
                content=content,
                category='cli_reference',
                tags=['cli', 'command', command_name.split()[0]],
                difficulty='beginner'
            )
            
            sections.append(section)
        
        logger.info(f"Generated {len(sections)} CLI documentation sections")
        return sections
    
    def _discover_cli_commands(self) -> Dict[str, Dict[str, Any]]:
        """Discover CLI commands from code"""
        # This is a placeholder - in a real implementation, you would
        # analyze Click commands or argparse configurations
        return {
            'node info': {
                'usage': 'blncs node info',
                'description': 'Display information about the Lightning Network node',
                'options': [
                    {'name': '--format', 'type': 'choice', 'description': 'Output format (json, table)'},
                    {'name': '--verbose', 'type': 'flag', 'description': 'Verbose output'}
                ],
                'examples': [
                    'blncs node info',
                    'blncs node info --format json',
                    'blncs node info --verbose'
                ]
            },
            'wallet balance': {
                'usage': 'blncs wallet balance',
                'description': 'Show wallet balance information',
                'options': [
                    {'name': '--confirmed', 'type': 'flag', 'description': 'Show only confirmed balance'}
                ],
                'examples': [
                    'blncs wallet balance',
                    'blncs wallet balance --confirmed'
                ]
            }
        }
    
    def _format_cli_options(self, options: List[Dict[str, Any]]) -> str:
        """Format CLI options documentation"""
        if not options:
            return "No options available."
        
        option_lines = []
        for option in options:
            option_line = f"- `{option['name']}` ({option['type']}): {option['description']}"
            option_lines.append(option_line)
        
        return '\n'.join(option_lines)
    
    def _format_cli_examples(self, examples: List[str]) -> str:
        """Format CLI examples"""
        if not examples:
            return "No examples available."
        
        example_lines = []
        for example in examples:
            example_lines.append(f"```bash\n{example}\n```")
        
        return '\n\n'.join(example_lines)
    
    def generate_troubleshooting_docs(self, issues: List[Dict[str, Any]] = None) -> List[DocumentSection]:
        """Generate troubleshooting documentation"""
        logger.info("Generating troubleshooting documentation")
        
        if issues is None:
            issues = self._get_common_issues()
        
        sections = []
        
        for issue in issues:
            content = self.templates['troubleshooting'].format(
                issue_name=issue['name'],
                description=issue['description'],
                causes=self._format_list(issue.get('causes', [])),
                solutions=self._format_list(issue.get('solutions', [])),
                prevention=self._format_list(issue.get('prevention', []))
            )
            
            section = DocumentSection(
                id=f"troubleshoot_{issue['name'].lower().replace(' ', '_')}",
                title=f"Troubleshooting: {issue['name']}",
                content=content,
                category='troubleshooting',
                tags=['troubleshooting', 'problem', 'fix'] + issue.get('tags', []),
                difficulty='beginner'
            )
            
            sections.append(section)
        
        logger.info(f"Generated {len(sections)} troubleshooting sections")
        return sections
    
    def _get_common_issues(self) -> List[Dict[str, Any]]:
        """Get common issues for troubleshooting docs"""
        return [
            {
                'name': 'Connection Timeout',
                'description': 'Unable to connect to Lightning Network node due to timeout',
                'causes': [
                    'Network connectivity issues',
                    'Firewall blocking connection',
                    'Incorrect host/port configuration',
                    'Node is not running'
                ],
                'solutions': [
                    'Check network connectivity with ping',
                    'Verify firewall settings',
                    'Confirm node configuration',
                    'Restart Lightning node',
                    'Check node logs for errors'
                ],
                'prevention': [
                    'Set up monitoring for node availability',
                    'Use reliable network infrastructure',
                    'Keep node software updated'
                ],
                'tags': ['connection', 'network', 'timeout']
            },
            {
                'name': 'Authentication Failed',
                'description': 'Authentication to Lightning Network node fails',
                'causes': [
                    'Invalid macaroon file',
                    'Incorrect certificate path',
                    'File permission issues',
                    'Expired credentials'
                ],
                'solutions': [
                    'Verify macaroon file location and permissions',
                    'Check TLS certificate validity',
                    'Regenerate macaroon if necessary',
                    'Ensure files are readable by user'
                ],
                'prevention': [
                    'Regular credential rotation',
                    'Proper file permission management',
                    'Secure credential storage'
                ],
                'tags': ['authentication', 'macaroon', 'certificate']
            }
        ]
    
    def _format_list(self, items: List[str]) -> str:
        """Format a list of items"""
        if not items:
            return "No items available."
        
        return '\n'.join(f"- {item}" for item in items)
    
    def generate_all_documentation(self) -> List[DocumentSection]:
        """Generate all documentation sections"""
        logger.info("Generating complete documentation set")
        
        all_sections = []
        
        # Generate API documentation
        api_sections = self.generate_api_documentation()
        all_sections.extend(api_sections)
        
        # Generate CLI documentation
        cli_sections = self.generate_cli_documentation()
        all_sections.extend(cli_sections)
        
        # Generate troubleshooting documentation
        troubleshoot_sections = self.generate_troubleshooting_docs()
        all_sections.extend(troubleshoot_sections)
        
        logger.info(f"Generated {len(all_sections)} total documentation sections")
        return all_sections
    
    def update_documentation(self):
        """Update documentation manager with generated content"""
        logger.info("Updating documentation with generated content")
        
        sections = self.generate_all_documentation()
        
        for section in sections:
            self.doc_manager.add_section(section)
        
        logger.info("Documentation update completed")


def generate_documentation(project_root: str = None, output_dir: str = None) -> List[DocumentSection]:
    """Convenience function to generate documentation"""
    generator = ContentGenerator(project_root)
    sections = generator.generate_all_documentation()
    
    # Save to documentation manager
    generator.update_documentation()
    
    # Export if output directory specified
    if output_dir:
        doc_manager = get_documentation_manager()
        doc_manager.export_documentation(output_dir, format='html')
        doc_manager.export_documentation(output_dir, format='markdown')
    
    return sections


if __name__ == "__main__":
    # Test content generation
    import tempfile
    
    with tempfile.TemporaryDirectory() as temp_dir:
        print("Content Generator Test")
        print("=" * 30)
        
        # Test with current project
        project_root = Path(__file__).parent.parent.parent
        generator = ContentGenerator(str(project_root))
        
        # Test code analysis
        analyzer = CodeAnalyzer(str(project_root))
        analyzed = analyzer.analyze_project(['blncs/docs/*.py'])
        print(f"Analyzed modules: {len(analyzed)}")
        
        # Test API documentation generation
        api_sections = generator.generate_api_documentation(['blncs/docs/*.py'])
        print(f"Generated API sections: {len(api_sections)}")
        
        # Test CLI documentation generation
        cli_sections = generator.generate_cli_documentation()
        print(f"Generated CLI sections: {len(cli_sections)}")
        
        # Test troubleshooting documentation
        troubleshoot_sections = generator.generate_troubleshooting_docs()
        print(f"Generated troubleshooting sections: {len(troubleshoot_sections)}")
        
        # Test full generation
        all_sections = generator.generate_all_documentation()
        print(f"Total generated sections: {len(all_sections)}")
        
        # Test export
        export_dir = Path(temp_dir) / "generated_docs"
        generate_documentation(str(project_root), str(export_dir))
        print(f"Documentation exported to {export_dir}")
        
        print("Content generation test completed")