"""
API Documentation Generator
Automatic generation of API documentation from code and specifications.
"""

import ast
import inspect
from typing import Dict, List, Any, Optional, Callable, Type, get_type_hints
from pathlib import Path
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
import docstring_parser

@dataclass
class ParameterDoc:
    """Parameter documentation."""
    name: str
    type_hint: str
    description: str
    required: bool = True
    default_value: Any = None

@dataclass 
class FunctionDoc:
    """Function documentation."""
    name: str
    description: str
    parameters: List[ParameterDoc] = field(default_factory=list)
    return_type: str = "None"
    return_description: str = ""
    examples: List[str] = field(default_factory=list)
    raises: List[str] = field(default_factory=list)
    deprecated: bool = False

@dataclass
class ModuleDoc:
    """Module documentation."""
    name: str
    description: str
    functions: List[FunctionDoc] = field(default_factory=list)
    classes: List[str] = field(default_factory=list)
    file_path: str = ""

class DocumentationExtractor:
    """Extract documentation from Python code."""
    
    def __init__(self):
        """Initialize documentation extractor."""
        self.modules: Dict[str, ModuleDoc] = {}
    
    def extract_from_function(self, func: Callable) -> FunctionDoc:
        """Extract documentation from a function."""
        func_doc = FunctionDoc(
            name=func.__name__,
            description=self._get_short_description(func.__doc__ or "")
        )
        
        # Parse docstring
        if func.__doc__:
            parsed_doc = docstring_parser.parse(func.__doc__)
            func_doc.description = parsed_doc.short_description or ""
            
            # Extract parameters
            for param in parsed_doc.params:
                param_doc = ParameterDoc(
                    name=param.arg_name or "",
                    type_hint=param.type_name or "Any",
                    description=param.description or "",
                    required=not param.is_optional
                )
                func_doc.parameters.append(param_doc)
            
            # Extract return information
            if parsed_doc.returns:
                func_doc.return_type = parsed_doc.returns.type_name or "Any"
                func_doc.return_description = parsed_doc.returns.description or ""
            
            # Extract raises information
            for exception in parsed_doc.raises:
                func_doc.raises.append(f"{exception.type_name}: {exception.description}")
        
        # Get type hints
        try:
            type_hints = get_type_hints(func)
            signature = inspect.signature(func)
            
            for param_name, param in signature.parameters.items():
                # Find corresponding parameter doc
                param_doc = next(
                    (p for p in func_doc.parameters if p.name == param_name),
                    None
                )
                
                if param_doc is None:
                    param_doc = ParameterDoc(
                        name=param_name,
                        type_hint="Any",
                        description="",
                        required=param.default == inspect.Parameter.empty
                    )
                    func_doc.parameters.append(param_doc)
                
                # Update type hint
                if param_name in type_hints:
                    param_doc.type_hint = str(type_hints[param_name]).replace("typing.", "")
                
                # Update default value
                if param.default != inspect.Parameter.empty:
                    param_doc.default_value = param.default
                    param_doc.required = False
            
            # Update return type
            if 'return' in type_hints and func_doc.return_type == "Any":
                func_doc.return_type = str(type_hints['return']).replace("typing.", "")
                
        except Exception as e:
            print(f"Warning: Could not extract type hints for {func.__name__}: {e}")
        
        return func_doc
    
    def extract_from_module(self, module_path: str) -> ModuleDoc:
        """Extract documentation from a Python module file."""
        path = Path(module_path)
        if not path.exists():
            raise FileNotFoundError(f"Module file not found: {module_path}")
        
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        try:
            tree = ast.parse(content)
        except SyntaxError as e:
            raise ValueError(f"Syntax error in module {module_path}: {e}")
        
        module_doc = ModuleDoc(
            name=path.stem,
            description=self._extract_module_docstring(tree),
            file_path=str(path)
        )
        
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                func_doc = self._extract_function_from_ast(node)
                if func_doc:
                    module_doc.functions.append(func_doc)
            elif isinstance(node, ast.ClassDef):
                module_doc.classes.append(node.name)
        
        self.modules[module_doc.name] = module_doc
        return module_doc
    
    def _extract_module_docstring(self, tree: ast.AST) -> str:
        """Extract module-level docstring."""
        if (isinstance(tree, ast.Module) and 
            tree.body and 
            isinstance(tree.body[0], ast.Expr) and
            isinstance(tree.body[0].value, ast.Constant) and
            isinstance(tree.body[0].value.value, str)):
            return tree.body[0].value.value
        return ""
    
    def _extract_function_from_ast(self, node: ast.FunctionDef) -> Optional[FunctionDoc]:
        """Extract function documentation from AST node."""
        if node.name.startswith('_'):  # Skip private functions
            return None
        
        func_doc = FunctionDoc(
            name=node.name,
            description=""
        )
        
        # Extract docstring
        if (node.body and 
            isinstance(node.body[0], ast.Expr) and
            isinstance(node.body[0].value, ast.Constant) and
            isinstance(node.body[0].value.value, str)):
            docstring = node.body[0].value.value
            func_doc.description = self._get_short_description(docstring)
            
            # Parse docstring
            try:
                parsed_doc = docstring_parser.parse(docstring)
                if parsed_doc.short_description:
                    func_doc.description = parsed_doc.short_description
                    
                # Extract parameters
                for param in parsed_doc.params:
                    param_doc = ParameterDoc(
                        name=param.arg_name or "",
                        type_hint=param.type_name or "Any",
                        description=param.description or "",
                        required=not param.is_optional
                    )
                    func_doc.parameters.append(param_doc)
            except Exception:
                pass  # Continue with basic docstring
        
        # Extract function arguments
        for arg in node.args.args:
            if arg.arg == 'self':
                continue
                
            # Find existing parameter doc
            param_doc = next(
                (p for p in func_doc.parameters if p.name == arg.arg),
                None
            )
            
            if param_doc is None:
                param_doc = ParameterDoc(
                    name=arg.arg,
                    type_hint="Any",
                    description="",
                    required=True
                )
                func_doc.parameters.append(param_doc)
            
            # Extract type annotation
            if arg.annotation:
                param_doc.type_hint = ast.unparse(arg.annotation)
        
        # Extract return type annotation
        if node.returns:
            func_doc.return_type = ast.unparse(node.returns)
        
        return func_doc
    
    def _get_short_description(self, docstring: str) -> str:
        """Extract short description from docstring."""
        if not docstring:
            return ""
        
        lines = docstring.strip().split('\n')
        return lines[0].strip()

class MarkdownGenerator:
    """Generate Markdown documentation."""
    
    def __init__(self):
        """Initialize Markdown generator."""
        pass
    
    def generate_module_doc(self, module_doc: ModuleDoc) -> str:
        """Generate Markdown documentation for a module."""
        lines = []
        
        # Module header
        lines.append(f"# {module_doc.name}")
        lines.append("")
        if module_doc.description:
            lines.append(module_doc.description)
            lines.append("")
        
        if module_doc.file_path:
            lines.append(f"**File:** `{module_doc.file_path}`")
            lines.append("")
        
        # Table of contents
        if module_doc.functions or module_doc.classes:
            lines.append("## Contents")
            lines.append("")
            
            if module_doc.functions:
                lines.append("### Functions")
                for func in module_doc.functions:
                    lines.append(f"- [{func.name}](#{func.name.lower().replace('_', '-')})")
                lines.append("")
            
            if module_doc.classes:
                lines.append("### Classes")
                for class_name in module_doc.classes:
                    lines.append(f"- {class_name}")
                lines.append("")
        
        # Function documentation
        if module_doc.functions:
            lines.append("## Functions")
            lines.append("")
            
            for func in module_doc.functions:
                lines.extend(self._generate_function_doc(func))
                lines.append("")
        
        return '\n'.join(lines)
    
    def _generate_function_doc(self, func_doc: FunctionDoc) -> List[str]:
        """Generate Markdown documentation for a function."""
        lines = []
        
        # Function header
        lines.append(f"### {func_doc.name}")
        lines.append("")
        
        if func_doc.description:
            lines.append(func_doc.description)
            lines.append("")
        
        # Function signature
        params = []
        for param in func_doc.parameters:
            param_str = f"{param.name}: {param.type_hint}"
            if not param.required and param.default_value is not None:
                param_str += f" = {param.default_value}"
            params.append(param_str)
        
        signature = f"{func_doc.name}({', '.join(params)}) -> {func_doc.return_type}"
        lines.append("```python")
        lines.append(signature)
        lines.append("```")
        lines.append("")
        
        # Parameters
        if func_doc.parameters:
            lines.append("**Parameters:**")
            lines.append("")
            for param in func_doc.parameters:
                required_text = "required" if param.required else "optional"
                lines.append(f"- `{param.name}` ({param.type_hint}, {required_text}): {param.description}")
            lines.append("")
        
        # Return value
        if func_doc.return_type != "None":
            lines.append("**Returns:**")
            lines.append("")
            lines.append(f"- {func_doc.return_type}: {func_doc.return_description}")
            lines.append("")
        
        # Raises
        if func_doc.raises:
            lines.append("**Raises:**")
            lines.append("")
            for raise_info in func_doc.raises:
                lines.append(f"- {raise_info}")
            lines.append("")
        
        # Examples
        if func_doc.examples:
            lines.append("**Examples:**")
            lines.append("")
            for example in func_doc.examples:
                lines.append("```python")
                lines.append(example)
                lines.append("```")
            lines.append("")
        
        # Deprecation notice
        if func_doc.deprecated:
            lines.append("**⚠️ Deprecated:** This function is deprecated and will be removed in a future version.")
            lines.append("")
        
        return lines
    
    def generate_api_index(self, modules: Dict[str, ModuleDoc]) -> str:
        """Generate API documentation index."""
        lines = []
        
        lines.append("# BLNCS API Documentation")
        lines.append("")
        lines.append(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")
        lines.append("This documentation provides comprehensive information about the BLNCS API modules and functions.")
        lines.append("")
        
        # Modules index
        lines.append("## Modules")
        lines.append("")
        for module_name, module_doc in sorted(modules.items()):
            lines.append(f"### [{module_name}]({module_name.lower()}.md)")
            if module_doc.description:
                lines.append(f"{module_doc.description}")
            
            if module_doc.functions:
                lines.append(f"\n**Functions:** {len(module_doc.functions)}")
            if module_doc.classes:
                lines.append(f"**Classes:** {len(module_doc.classes)}")
            lines.append("")
        
        return '\n'.join(lines)

class DocumentationGenerator:
    """Main documentation generator orchestrator."""
    
    def __init__(self, output_dir: str = "docs/api"):
        """Initialize documentation generator."""
        self.output_dir = Path(output_dir)
        self.extractor = DocumentationExtractor()
        self.markdown_generator = MarkdownGenerator()
    
    def generate_from_directory(self, source_dir: str, pattern: str = "*.py") -> None:
        """Generate documentation from all Python files in a directory."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        source_path = Path(source_dir)
        if not source_path.exists():
            raise FileNotFoundError(f"Source directory not found: {source_dir}")
        
        # Extract documentation from all Python files
        python_files = list(source_path.rglob(pattern))
        modules = {}
        
        for py_file in python_files:
            if py_file.name.startswith('__'):
                continue
                
            try:
                module_doc = self.extractor.extract_from_module(str(py_file))
                modules[module_doc.name] = module_doc
            except Exception as e:
                print(f"Warning: Could not process {py_file}: {e}")
        
        # Generate Markdown files
        for module_name, module_doc in modules.items():
            markdown_content = self.markdown_generator.generate_module_doc(module_doc)
            output_file = self.output_dir / f"{module_name.lower()}.md"
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(markdown_content)
        
        # Generate index file
        index_content = self.markdown_generator.generate_api_index(modules)
        index_file = self.output_dir / "index.md"
        
        with open(index_file, 'w', encoding='utf-8') as f:
            f.write(index_content)
        
        print(f"Generated documentation for {len(modules)} modules in {self.output_dir}")

if __name__ == "__main__":
    # Generate documentation for BLNCS core modules
    generator = DocumentationGenerator("docs/api")
    generator.generate_from_directory("blncs/core")
    generator.generate_from_directory("blncs/cli")
    generator.generate_from_directory("blncs/lightning")
    
    print("API documentation generated successfully!")