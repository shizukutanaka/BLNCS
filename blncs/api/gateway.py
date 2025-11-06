#!/usr/bin/env python3
"""
APIゲートウェイ・クライアントライブラリ・自動ドキュメント生成システム for BLNCS
統合性を向上
"""

import json
import inspect
from typing import Dict, List, Any, Callable, Optional
from dataclasses import dataclass, field
from functools import wraps
import re
from pathlib import Path

@dataclass
class APIEndpoint:
    """APIエンドポイント定義"""
    path: str
    method: str
    summary: str
    description: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    responses: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    deprecated: bool = False

@dataclass
class APISchema:
    """APIスキーマ"""
    title: str
    version: str
    description: str
    endpoints: List[APIEndpoint] = field(default_factory=list)
    components: Dict[str, Any] = field(default_factory=dict)

class APIGateway:
    """APIゲートウェイ"""

    def __init__(self):
        self.routes = {}
        self.middlewares = []
        self.rate_limits = {}

    def register_route(self, path: str, method: str, handler: Callable, **kwargs):
        """ルートを登録"""
        if path not in self.routes:
            self.routes[path] = {}

        self.routes[path][method] = {
            'handler': handler,
            'metadata': kwargs
        }

    def add_middleware(self, middleware: Callable):
        """ミドルウェアを追加"""
        self.middlewares.append(middleware)

    def set_rate_limit(self, path: str, limit: int, window: int):
        """レート制限を設定"""
        self.rate_limits[path] = {'limit': limit, 'window': window}

    def process_request(self, path: str, method: str, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """リクエストを処理"""
        # ミドルウェア適用
        for middleware in self.middlewares:
            request_data = middleware(path, method, request_data)

        # レート制限チェック
        if path in self.rate_limits:
            if not self._check_rate_limit(path, request_data.get('client_ip')):
                return {'error': 'Rate limit exceeded', 'status': 429}

        # ルート処理
        if path in self.routes and method in self.routes[path]:
            handler_info = self.routes[path][method]
            handler = handler_info['handler']
            return handler(request_data)

        return {'error': 'Not found', 'status': 404}

    def _check_rate_limit(self, path: str, client_ip: str) -> bool:
        """レート制限チェック"""
        # 簡易実装（実際はRedisなどで管理）
        return True

class APIClientLibrary:
    """APIクライアントライブラリ"""

    def __init__(self, base_url: str, api_key: Optional[str] = None):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.session = None

    def _get_headers(self) -> Dict[str, str]:
        """ヘッダー取得"""
        headers = {'Content-Type': 'application/json'}
        if self.api_key:
            headers['Authorization'] = f'Bearer {self.api_key}'
        return headers

    def get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """GETリクエスト"""
        import requests
        url = f"{self.base_url}{endpoint}"
        response = requests.get(url, headers=self._get_headers(), params=params)
        return response.json()

    def post(self, endpoint: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """POSTリクエスト"""
        import requests
        url = f"{self.base_url}{endpoint}"
        response = requests.post(url, headers=self._get_headers(), json=data)
        return response.json()

    def put(self, endpoint: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """PUTリクエスト"""
        import requests
        url = f"{self.base_url}{endpoint}"
        response = requests.put(url, headers=self._get_headers(), json=data)
        return response.json()

    def delete(self, endpoint: str) -> Dict[str, Any]:
        """DELETEリクエスト"""
        import requests
        url = f"{self.base_url}{endpoint}"
        response = requests.delete(url, headers=self._get_headers())
        return response.json()

class AutoDocumentationGenerator:
    """自動ドキュメント生成システム"""

    def __init__(self):
        self.schemas = {}

    def register_api_schema(self, name: str, schema: APISchema):
        """APIスキーマを登録"""
        self.schemas[name] = schema

    def generate_openapi_spec(self, schema_name: str) -> Dict[str, Any]:
        """OpenAPI仕様を生成"""
        if schema_name not in self.schemas:
            raise ValueError(f"Schema {schema_name} not found")

        schema = self.schemas[schema_name]

        openapi = {
            'openapi': '3.0.3',
            'info': {
                'title': schema.title,
                'version': schema.version,
                'description': schema.description
            },
            'paths': {},
            'components': {
                'schemas': schema.components
            }
        }

        for endpoint in schema.endpoints:
            if endpoint.path not in openapi['paths']:
                openapi['paths'][endpoint.path] = {}

            openapi['paths'][endpoint.path][endpoint.method.lower()] = {
                'summary': endpoint.summary,
                'description': endpoint.description,
                'parameters': [
                    {
                        'name': param_name,
                        'in': 'query' if param_info.get('in') == 'query' else 'path',
                        'schema': param_info.get('schema', {'type': 'string'}),
                        'required': param_info.get('required', False)
                    } for param_name, param_info in endpoint.parameters.items()
                ],
                'responses': endpoint.responses,
                'tags': endpoint.tags,
                'deprecated': endpoint.deprecated
            }

        return openapi

    def generate_markdown_docs(self, schema_name: str) -> str:
        """Markdownドキュメントを生成"""
        if schema_name not in self.schemas:
            raise ValueError(f"Schema {schema_name} not found")

        schema = self.schemas[schema_name]

        docs = f"# {schema.title}\n\n"
        docs += f"**Version:** {schema.version}\n\n"
        docs += f"{schema.description}\n\n"

        # エンドポイント一覧
        docs += "## Endpoints\n\n"

        for endpoint in schema.endpoints:
            docs += f"### {endpoint.method.upper()} {endpoint.path}\n\n"
            docs += f"**Summary:** {endpoint.summary}\n\n"
            docs += f"**Description:** {endpoint.description}\n\n"

            if endpoint.parameters:
                docs += "**Parameters:**\n"
                for param_name, param_info in endpoint.parameters.items():
                    docs += f"- `{param_name}`: {param_info.get('description', 'No description')}\n"
                docs += "\n"

            if endpoint.responses:
                docs += "**Responses:**\n"
                for status_code, response_info in endpoint.responses.items():
                    docs += f"- `{status_code}`: {response_info.get('description', 'No description')}\n"
                docs += "\n"

            if endpoint.tags:
                docs += f"**Tags:** {', '.join(endpoint.tags)}\n\n"

            docs += "---\n\n"

        return docs

    def save_openapi_spec(self, schema_name: str, filename: str):
        """OpenAPI仕様をファイルに保存"""
        openapi_spec = self.generate_openapi_spec(schema_name)
        with open(filename, 'w') as f:
            json.dump(openapi_spec, f, indent=2)

    def save_markdown_docs(self, schema_name: str, filename: str):
        """Markdownドキュメントをファイルに保存"""
        docs = self.generate_markdown_docs(schema_name)
        with open(filename, 'w') as f:
            f.write(docs)

# デコレーター関数
def api_endpoint(path: str, method: str, summary: str, description: str = "", **kwargs):
    """APIエンドポイントデコレーター"""
    def decorator(func: Callable):
        func._api_metadata = {
            'path': path,
            'method': method,
            'summary': summary,
            'description': description,
            **kwargs
        }
        return func
    return decorator

# グローバルインスタンス
api_gateway = APIGateway()
doc_generator = AutoDocumentationGenerator()

def create_api_client(base_url: str, api_key: Optional[str] = None) -> APIClientLibrary:
    """APIクライアントを作成"""
    return APIClientLibrary(base_url, api_key)

def register_api_documentation(title: str, version: str, description: str):
    """APIドキュメントを登録"""
    schema = APISchema(title=title, version=version, description=description)
    doc_generator.register_api_schema('main', schema)
    return schema

def generate_api_docs(output_dir: str = 'docs/api'):
    """APIドキュメントを生成"""
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)

    # OpenAPI仕様を生成
    doc_generator.save_openapi_spec('main', output_path / 'openapi.json')

    # Markdownドキュメントを生成
    doc_generator.save_markdown_docs('main', output_path / 'api_reference.md')

    print(f"APIドキュメントを {output_dir} に生成しました")
