# BLRCS Documentation Generator
# Automated documentation generation with clean architecture
import ast
import inspect
import json
import re
import time
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Callable
from dataclasses import dataclass, field
from enum import Enum
import importlib.util
from collections import defaultdict
import subprocess

class DocType(Enum):
    """Documentation types"""
    API = "api"
    MODULE = "module"
    CLASS = "class"
    FUNCTION = "function"
    CONFIG = "config"
    TUTORIAL = "tutorial"
    CHANGELOG = "changelog"

class DocFormat(Enum):
    """Documentation formats"""
    MARKDOWN = "md"
    HTML = "html"
    JSON = "json"
    RST = "rst"

@dataclass
class DocItem:
    """Documentation item"""
    name: str
    type: DocType
    description: str = ""
    signature: str = ""
    parameters: List[Dict[str, str]] = field(default_factory=list)
    returns: str = ""
    examples: List[str] = field(default_factory=list)
    source_file: str = ""
    line_number: int = 0
    docstring: str = ""
    complexity: int = 0
    dependencies: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

@dataclass 
class DocConfig:
    """Documentation configuration"""
    source_dirs: List[Path] = field(default_factory=lambda: [Path("blrcs")])
    output_dir: Path = field(default_factory=lambda: Path("docs"))
    formats: List[DocFormat] = field(default_factory=lambda: [DocFormat.MARKDOWN])
    include_private: bool = False
    include_tests: bool = False
    include_examples: bool = True
    include_source_links: bool = True
    template_dir: Optional[Path] = None
    custom_css: Optional[Path] = None
    logo_path: Optional[Path] = None
    project_name: str = "BLRCS"
    project_version: str = "0.0.1"
    author: str = "BLRCS Team"
    
    def __post_init__(self):
        self.output_dir.mkdir(parents=True, exist_ok=True)

class CodeAnalyzer:
    """Code analysis for documentation"""
    
    def __init__(self):
        self.complexity_threshold = 10
        self.patterns = {
            'todo': re.compile(r'#\s*TODO:?\s*(.+)', re.IGNORECASE),
            'fixme': re.compile(r'#\s*FIXME:?\s*(.+)', re.IGNORECASE),
            'note': re.compile(r'#\s*NOTE:?\s*(.+)', re.IGNORECASE),
            'warning': re.compile(r'#\s*WARNING:?\s*(.+)', re.IGNORECASE)
        }
    
    def analyze_file(self, file_path: Path) -> List[DocItem]:
        """Analyze Python file for documentation"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                source = f.read()
            
            tree = ast.parse(source, filename=str(file_path))
            items = []
            
            # Analyze module
            module_doc = self._extract_module_doc(tree, file_path)
            if module_doc:
                items.append(module_doc)
            
            # Analyze classes and functions
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    class_doc = self._extract_class_doc(node, file_path, source)
                    if class_doc:
                        items.append(class_doc)
                
                elif isinstance(node, ast.FunctionDef):
                    func_doc = self._extract_function_doc(node, file_path, source)
                    if func_doc:
                        items.append(func_doc)
            
            return items
            
        except Exception as e:
            print(f"Error analyzing {file_path}: {e}")
            return []
    
    def _extract_module_doc(self, tree: ast.AST, file_path: Path) -> Optional[DocItem]:
        """Extract module documentation"""
        docstring = ast.get_docstring(tree)
        if not docstring:
            return None
        
        # Extract module info from comments
        source_lines = file_path.read_text().split('\n')
        description = ""
        for line in source_lines[:10]:  # Check first 10 lines
            if line.startswith('#') and not line.startswith('#!/'):
                description += line[1:].strip() + " "
        
        return DocItem(
            name=file_path.stem,
            type=DocType.MODULE,
            description=description.strip(),
            docstring=docstring,
            source_file=str(file_path),
            line_number=1
        )
    
    def _extract_class_doc(self, node: ast.ClassDef, file_path: Path, source: str) -> Optional[DocItem]:
        """Extract class documentation"""
        docstring = ast.get_docstring(node)
        
        # Extract base classes
        bases = [self._get_name(base) for base in node.bases]
        
        # Extract methods
        methods = []
        for item in node.body:
            if isinstance(item, ast.FunctionDef):
                methods.append(item.name)
        
        # Calculate complexity
        complexity = self._calculate_complexity(node)
        
        return DocItem(
            name=node.name,
            type=DocType.CLASS,
            description=f"Class with {len(methods)} methods, inherits from {', '.join(bases) if bases else 'object'}",
            docstring=docstring or "",
            source_file=str(file_path),
            line_number=node.lineno,
            complexity=complexity,
            dependencies=bases,
            tags=self._extract_tags(docstring)
        )
    
    def _extract_function_doc(self, node: ast.FunctionDef, file_path: Path, source: str) -> Optional[DocItem]:
        """Extract function documentation"""
        docstring = ast.get_docstring(node)
        
        # Extract signature
        signature = self._get_function_signature(node)
        
        # Extract parameters
        parameters = self._extract_parameters(node, docstring)
        
        # Extract return type
        returns = self._extract_return_info(node, docstring)
        
        # Calculate complexity
        complexity = self._calculate_complexity(node)
        
        # Extract examples from docstring
        examples = self._extract_examples(docstring)
        
        return DocItem(
            name=node.name,
            type=DocType.FUNCTION,
            description=self._extract_description(docstring),
            signature=signature,
            parameters=parameters,
            returns=returns,
            examples=examples,
            docstring=docstring or "",
            source_file=str(file_path),
            line_number=node.lineno,
            complexity=complexity,
            tags=self._extract_tags(docstring)
        )
    
    def _get_function_signature(self, node: ast.FunctionDef) -> str:
        """Get function signature"""
        args = []
        
        # Regular args
        for arg in node.args.args:
            arg_str = arg.arg
            if arg.annotation:
                arg_str += f": {self._get_name(arg.annotation)}"
            args.append(arg_str)
        
        # Default values
        defaults = node.args.defaults
        if defaults:
            for i, default in enumerate(defaults):
                arg_index = len(args) - len(defaults) + i
                if arg_index >= 0:
                    args[arg_index] += f" = {self._get_name(default)}"
        
        # Return type
        return_type = ""
        if node.returns:
            return_type = f" -> {self._get_name(node.returns)}"
        
        return f"{node.name}({', '.join(args)}){return_type}"
    
    def _extract_parameters(self, node: ast.FunctionDef, docstring: str) -> List[Dict[str, str]]:
        """Extract parameter information"""
        parameters = []
        
        for arg in node.args.args:
            param = {
                'name': arg.arg,
                'type': self._get_name(arg.annotation) if arg.annotation else 'Any',
                'description': self._extract_param_description(arg.arg, docstring)
            }
            parameters.append(param)
        
        return parameters
    
    def _extract_param_description(self, param_name: str, docstring: str) -> str:
        """Extract parameter description from docstring"""
        if not docstring:
            return ""
        
        # Look for parameter descriptions in various formats
        patterns = [
            rf'{param_name}\s*:\s*(.+?)(?=\n\s*\w+\s*:|$)',
            rf'@param\s+{param_name}\s*:\s*(.+?)(?=\n\s*@|$)',
            rf'{param_name}\s*\(.*?\)\s*:\s*(.+?)(?=\n|$)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, docstring, re.DOTALL | re.IGNORECASE)
            if match:
                return match.group(1).strip()
        
        return ""
    
    def _extract_return_info(self, node: ast.FunctionDef, docstring: str) -> str:
        """Extract return information"""
        # From annotation
        if node.returns:
            return_type = self._get_name(node.returns)
        else:
            return_type = "Any"
        
        # From docstring
        description = ""
        if docstring:
            patterns = [
                r'returns?\s*:\s*(.+?)(?=\n\s*\w+\s*:|$)',
                r'@return\s*:\s*(.+?)(?=\n\s*@|$)',
                r'@returns\s*:\s*(.+?)(?=\n\s*@|$)'
            ]
            
            for pattern in patterns:
                match = re.search(pattern, docstring, re.DOTALL | re.IGNORECASE)
                if match:
                    description = match.group(1).strip()
                    break
        
        if description:
            return f"{return_type}: {description}"
        return return_type
    
    def _extract_description(self, docstring: str) -> str:
        """Extract description from docstring"""
        if not docstring:
            return ""
        
        # Get first paragraph
        lines = docstring.strip().split('\n')
        description_lines = []
        
        for line in lines:
            line = line.strip()
            if not line:
                break
            if line.startswith(('@', 'Args:', 'Returns:', 'Parameters:')):
                break
            description_lines.append(line)
        
        return ' '.join(description_lines)
    
    def _extract_examples(self, docstring: str) -> List[str]:
        """Extract examples from docstring"""
        if not docstring:
            return []
        
        examples = []
        in_example = False
        current_example = []
        
        for line in docstring.split('\n'):
            line = line.strip()
            
            if 'example' in line.lower() and ':' in line:
                in_example = True
                current_example = []
                continue
            
            if in_example:
                if line.startswith('>>>') or line.startswith('...'):
                    current_example.append(line)
                elif line and not line.startswith(' '):
                    if current_example:
                        examples.append('\n'.join(current_example))
                        current_example = []
                    in_example = False
                elif line:
                    current_example.append(line)
        
        if current_example:
            examples.append('\n'.join(current_example))
        
        return examples
    
    def _extract_tags(self, docstring: str) -> List[str]:
        """Extract tags from docstring"""
        if not docstring:
            return []
        
        tags = []
        for pattern_name, pattern in self.patterns.items():
            if pattern.search(docstring):
                tags.append(pattern_name)
        
        # Check for other common tags
        tag_patterns = [
            r'@deprecated',
            r'@experimental',
            r'@internal',
            r'@public',
            r'@private'
        ]
        
        for pattern in tag_patterns:
            if re.search(pattern, docstring, re.IGNORECASE):
                tags.append(pattern[1:])  # Remove @
        
        return tags
    
    def _calculate_complexity(self, node: ast.AST) -> int:
        """Calculate cyclomatic complexity"""
        complexity = 1  # Base complexity
        
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For, ast.AsyncFor)):
                complexity += 1
            elif isinstance(child, ast.ExceptHandler):
                complexity += 1
            elif isinstance(child, (ast.And, ast.Or)):
                complexity += 1
        
        return complexity
    
    def _get_name(self, node: ast.AST) -> str:
        """Get name from AST node"""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return f"{self._get_name(node.value)}.{node.attr}"
        elif isinstance(node, ast.Constant):
            return str(node.value)
        else:
            return "Unknown"

class TemplateEngine:
    """Simple template engine for documentation"""
    
    def __init__(self, template_dir: Optional[Path] = None):
        self.template_dir = template_dir or Path(__file__).parent / "templates"
        self.templates: Dict[str, str] = {}
        self._load_templates()
    
    def _load_templates(self):
        """Load templates from directory"""
        if not self.template_dir.exists():
            # Create default templates
            self._create_default_templates()
        
        for template_file in self.template_dir.glob("*.md"):
            template_name = template_file.stem
            self.templates[template_name] = template_file.read_text()
    
    def _create_default_templates(self):
        """Create default templates"""
        self.template_dir.mkdir(parents=True, exist_ok=True)
        
        # Module template
        module_template = """# {name}

{description}

## Overview

{docstring}

## Classes

{classes}

## Functions

{functions}

## Dependencies

{dependencies}

---
*Generated on {timestamp}*
"""
        (self.template_dir / "module.md").write_text(module_template)
        
        # Class template
        class_template = """## {name}

{description}

**Complexity:** {complexity}

### Description

{docstring}

### Methods

{methods}

### Inheritance

{inheritance}
"""
        (self.template_dir / "class.md").write_text(class_template)
        
        # Function template
        function_template = """### {name}

```python
{signature}
```

{description}

**Complexity:** {complexity}

#### Parameters

{parameters}

#### Returns

{returns}

#### Examples

{examples}
"""
        (self.template_dir / "function.md").write_text(function_template)
        
        # API template
        api_template = """# {project_name} API Documentation

Version: {version}

## Modules

{modules}

## Quick Reference

{quick_reference}

## Configuration

{configuration}
"""
        (self.template_dir / "api.md").write_text(api_template)
    
    def render(self, template_name: str, context: Dict[str, Any]) -> str:
        """Render template with context"""
        if template_name not in self.templates:
            return f"Template '{template_name}' not found"
        
        template = self.templates[template_name]
        
        # Simple variable substitution
        for key, value in context.items():
            placeholder = f"{{{key}}}"
            if isinstance(value, list):
                value = '\n'.join(str(item) for item in value)
            elif value is None:
                value = ""
            
            template = template.replace(placeholder, str(value))
        
        return template

class DocumentationGenerator:
    """Main documentation generator"""
    
    def __init__(self, config: DocConfig):
        self.config = config
        self.analyzer = CodeAnalyzer()
        self.template_engine = TemplateEngine(config.template_dir)
        self.doc_items: List[DocItem] = []
        self.stats = {
            'modules': 0,
            'classes': 0,
            'functions': 0,
            'lines_analyzed': 0,
            'generation_time': 0
        }
    
    def generate(self):
        """Generate all documentation"""
        start_time = time.time()
        
        print(f"Generating documentation for {self.config.project_name}...")
        
        # Analyze source code
        self._analyze_source()
        
        # Generate documentation
        for doc_format in self.config.formats:
            if doc_format == DocFormat.MARKDOWN:
                self._generate_markdown()
            elif doc_format == DocFormat.HTML:
                self._generate_html()
            elif doc_format == DocFormat.JSON:
                self._generate_json()
        
        # Generate additional files
        self._generate_index()
        self._generate_changelog()
        
        self.stats['generation_time'] = time.time() - start_time
        self._print_stats()
    
    def _analyze_source(self):
        """Analyze source code"""
        print("Analyzing source code...")
        
        for source_dir in self.config.source_dirs:
            if not source_dir.exists():
                continue
            
            for py_file in source_dir.rglob("*.py"):
                # Skip test files if not included
                if not self.config.include_tests and 'test' in py_file.name.lower():
                    continue
                
                # Skip private modules if not included
                if not self.config.include_private and py_file.name.startswith('_'):
                    continue
                
                items = self.analyzer.analyze_file(py_file)
                self.doc_items.extend(items)
                
                # Update stats
                with open(py_file, 'r') as f:
                    self.stats['lines_analyzed'] += len(f.readlines())
        
        # Update stats
        for item in self.doc_items:
            if item.type == DocType.MODULE:
                self.stats['modules'] += 1
            elif item.type == DocType.CLASS:
                self.stats['classes'] += 1
            elif item.type == DocType.FUNCTION:
                self.stats['functions'] += 1
    
    def _generate_markdown(self):
        """Generate Markdown documentation"""
        print("Generating Markdown documentation...")
        
        # Group items by module
        modules = defaultdict(list)
        for item in self.doc_items:
            module_name = Path(item.source_file).stem
            modules[module_name].append(item)
        
        # Generate module documentation
        for module_name, items in modules.items():
            module_items = [item for item in items if item.type == DocType.MODULE]
            class_items = [item for item in items if item.type == DocType.CLASS]
            function_items = [item for item in items if item.type == DocType.FUNCTION]
            
            # Module documentation
            if module_items:
                module_doc = module_items[0]
                context = {
                    'name': module_name,
                    'description': module_doc.description,
                    'docstring': module_doc.docstring,
                    'classes': self._format_items_list(class_items),
                    'functions': self._format_items_list(function_items),
                    'dependencies': self._get_module_dependencies(items),
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                }
                
                content = self.template_engine.render('module', context)
                output_file = self.config.output_dir / f"{module_name}.md"
                output_file.write_text(content)
        
        # Generate API overview
        self._generate_api_overview()
    
    def _generate_api_overview(self):
        """Generate API overview"""
        modules_list = []
        for item in self.doc_items:
            if item.type == DocType.MODULE:
                modules_list.append(f"- [{item.name}]({item.name}.md) - {item.description}")
        
        quick_ref = []
        for item in self.doc_items:
            if item.type == DocType.FUNCTION and not item.name.startswith('_'):
                quick_ref.append(f"- `{item.signature}` - {item.description}")
        
        context = {
            'project_name': self.config.project_name,
            'version': self.config.project_version,
            'modules': '\n'.join(modules_list),
            'quick_reference': '\n'.join(quick_ref[:20]),  # Top 20
            'configuration': self._generate_config_docs()
        }
        
        content = self.template_engine.render('api', context)
        (self.config.output_dir / "api.md").write_text(content)
    
    def _generate_html(self):
        """Generate HTML documentation"""
        print("Generating HTML documentation...")
        
        # Convert Markdown to HTML (basic conversion)
        for md_file in self.config.output_dir.glob("*.md"):
            html_content = self._markdown_to_html(md_file.read_text())
            html_file = md_file.with_suffix('.html')
            
            # Wrap in basic HTML template
            full_html = f"""<!DOCTYPE html>
<html>
<head>
    <title>{md_file.stem} - {self.config.project_name}</title>
    <meta charset="utf-8">
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        code {{ background: #f4f4f4; padding: 2px 4px; }}
        pre {{ background: #f4f4f4; padding: 10px; overflow: auto; }}
        h1, h2, h3 {{ color: #333; }}
    </style>
    {self._get_custom_css()}
</head>
<body>
{html_content}
</body>
</html>"""
            
            html_file.write_text(full_html)
    
    def _generate_json(self):
        """Generate JSON documentation"""
        print("Generating JSON documentation...")
        
        doc_data = {
            'project': {
                'name': self.config.project_name,
                'version': self.config.project_version,
                'author': self.config.author,
                'generated_at': time.time()
            },
            'modules': [],
            'classes': [],
            'functions': [],
            'statistics': self.stats
        }
        
        for item in self.doc_items:
            item_data = {
                'name': item.name,
                'type': item.type.value,
                'description': item.description,
                'signature': item.signature,
                'parameters': item.parameters,
                'returns': item.returns,
                'examples': item.examples,
                'source_file': item.source_file,
                'line_number': item.line_number,
                'complexity': item.complexity,
                'dependencies': item.dependencies,
                'tags': item.tags
            }
            
            if item.type == DocType.MODULE:
                doc_data['modules'].append(item_data)
            elif item.type == DocType.CLASS:
                doc_data['classes'].append(item_data)
            elif item.type == DocType.FUNCTION:
                doc_data['functions'].append(item_data)
        
        json_file = self.config.output_dir / "documentation.json"
        with open(json_file, 'w') as f:
            json.dump(doc_data, f, indent=2)
    
    def _generate_index(self):
        """Generate index file"""
        index_content = f"""# {self.config.project_name} Documentation

Welcome to the {self.config.project_name} documentation.

## Available Documentation

- [API Reference](api.md) - Complete API documentation
- [Modules](modules.md) - Module documentation

## Statistics

- **Modules:** {self.stats['modules']}
- **Classes:** {self.stats['classes']}
- **Functions:** {self.stats['functions']}
- **Lines Analyzed:** {self.stats['lines_analyzed']}

## Quick Links

{self._generate_quick_links()}

---
*Documentation generated on {time.strftime('%Y-%m-%d %H:%M:%S')}*
"""
        
        (self.config.output_dir / "README.md").write_text(index_content)
    
    def _generate_changelog(self):
        """Generate changelog"""
        changelog_content = f"""# Changelog

## Version {self.config.project_version}

### Added
- Comprehensive documentation system
- Automated code analysis
- Multiple output formats

### Changed
- Improved documentation structure

### Fixed
- Documentation generation issues

---
*Generated on {time.strftime('%Y-%m-%d')}*
"""
        
        (self.config.output_dir / "CHANGELOG.md").write_text(changelog_content)
    
    def _format_items_list(self, items: List[DocItem]) -> str:
        """Format items as markdown list"""
        if not items:
            return "None"
        
        formatted = []
        for item in items:
            if item.type == DocType.CLASS:
                formatted.append(f"- **{item.name}** - {item.description}")
            elif item.type == DocType.FUNCTION:
                formatted.append(f"- `{item.name}()` - {item.description}")
        
        return '\n'.join(formatted)
    
    def _get_module_dependencies(self, items: List[DocItem]) -> str:
        """Get module dependencies"""
        deps = set()
        for item in items:
            deps.update(item.dependencies)
        
        if not deps:
            return "None"
        
        return '\n'.join(f"- {dep}" for dep in sorted(deps))
    
    def _generate_config_docs(self) -> str:
        """Generate configuration documentation"""
        config_items = [item for item in self.doc_items if 'config' in item.name.lower()]
        
        if not config_items:
            return "Configuration documentation not available."
        
        docs = []
        for item in config_items:
            docs.append(f"### {item.name}")
            docs.append(item.description)
            if item.parameters:
                docs.append("**Parameters:**")
                for param in item.parameters:
                    docs.append(f"- `{param['name']}` ({param['type']}): {param['description']}")
        
        return '\n\n'.join(docs)
    
    def _generate_quick_links(self) -> str:
        """Generate quick links"""
        links = []
        
        # Important modules
        important_modules = ['config', 'database', 'auth', 'security']
        for module_name in important_modules:
            module_items = [item for item in self.doc_items 
                          if item.type == DocType.MODULE and module_name in item.name.lower()]
            if module_items:
                links.append(f"- [{module_name.title()}]({module_items[0].name}.md)")
        
        return '\n'.join(links) if links else "No quick links available."
    
    def _markdown_to_html(self, markdown: str) -> str:
        """Basic Markdown to HTML conversion"""
        html = markdown
        
        # Headers
        html = re.sub(r'^### (.+)$', r'<h3>\1</h3>', html, flags=re.MULTILINE)
        html = re.sub(r'^## (.+)$', r'<h2>\1</h2>', html, flags=re.MULTILINE)
        html = re.sub(r'^# (.+)$', r'<h1>\1</h1>', html, flags=re.MULTILINE)
        
        # Code blocks
        html = re.sub(r'```python\n(.*?)\n```', r'<pre><code>\1</code></pre>', 
                     html, flags=re.DOTALL)
        html = re.sub(r'```\n(.*?)\n```', r'<pre><code>\1</code></pre>', 
                     html, flags=re.DOTALL)
        
        # Inline code
        html = re.sub(r'`([^`]+)`', r'<code>\1</code>', html)
        
        # Bold
        html = re.sub(r'\*\*([^*]+)\*\*', r'<strong>\1</strong>', html)
        
        # Paragraphs
        html = re.sub(r'\n\n', r'</p>\n<p>', html)
        html = '<p>' + html + '</p>'
        
        return html
    
    def _get_custom_css(self) -> str:
        """Get custom CSS if available"""
        if self.config.custom_css and self.config.custom_css.exists():
            return f'<style>\n{self.config.custom_css.read_text()}\n</style>'
        return ""
    
    def _print_stats(self):
        """Print generation statistics"""
        print("\nDocumentation Generation Complete!")
        print(f"Modules: {self.stats['modules']}")
        print(f"Classes: {self.stats['classes']}")
        print(f"Functions: {self.stats['functions']}")
        print(f"Lines Analyzed: {self.stats['lines_analyzed']}")
        print(f"Generation Time: {self.stats['generation_time']:.2f}s")
        print(f"Output Directory: {self.config.output_dir}")

# Convenience functions
def generate_docs(source_dirs: List[str] = None, output_dir: str = "docs", 
                  formats: List[str] = None, **kwargs):
    """Generate documentation with default settings"""
    
    # Convert string paths to Path objects
    if source_dirs:
        source_dirs = [Path(d) for d in source_dirs]
    
    if formats:
        formats = [DocFormat(f) for f in formats]
    
    config = DocConfig(
        source_dirs=source_dirs or [Path("blrcs")],
        output_dir=Path(output_dir),
        formats=formats or [DocFormat.MARKDOWN],
        **kwargs
    )
    
    generator = DocumentationGenerator(config)
    generator.generate()
    
    return generator.stats

def create_doc_config(**kwargs) -> DocConfig:
    """Create documentation configuration"""
    return DocConfig(**kwargs)

# CLI interface
def main():
    """Command line interface"""
    import argparse
    
    parser = argparse.ArgumentParser(description='BLRCS Documentation Generator')
    parser.add_argument('--source', nargs='+', default=['blrcs'], 
                       help='Source directories to analyze')
    parser.add_argument('--output', default='docs', 
                       help='Output directory')
    parser.add_argument('--format', choices=['md', 'html', 'json'], 
                       nargs='+', default=['md'],
                       help='Output formats')
    parser.add_argument('--include-private', action='store_true',
                       help='Include private modules')
    parser.add_argument('--include-tests', action='store_true',
                       help='Include test files')
    
    args = parser.parse_args()
    
    # Generate documentation
    stats = generate_docs(
        source_dirs=args.source,
        output_dir=args.output,
        formats=args.format,
        include_private=args.include_private,
        include_tests=args.include_tests
    )
    
    print(f"\nGeneration completed in {stats['generation_time']:.2f}s")

if __name__ == "__main__":
    main()