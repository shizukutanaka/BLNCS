"""
Interactive Documentation and Tutorial System for BLNCS

This module provides advanced documentation features including:
- Interactive tutorials with step-by-step guidance
- Live demo environments
- API playground for testing endpoints
- Dynamic documentation updates
- Multi-format documentation export
"""

import time
import json
import logging
import threading
import asyncio
from typing import Dict, List, Optional, Any, Callable, Set, Tuple, Union
from dataclasses import dataclass, asdict
from collections import defaultdict
import uuid
import webbrowser
import http.server
import socketserver
from pathlib import Path

logger = logging.getLogger(__name__)

@dataclass
class TutorialStep:
    """Tutorial step definition."""
    id: str
    title: str
    description: str
    code_snippet: Optional[str] = None
    interactive_elements: List[Dict[str, Any]] = None
    validation_function: Optional[Callable] = None
    hints: List[str] = None
    next_step_conditions: Dict[str, Any] = None

@dataclass
class Tutorial:
    """Interactive tutorial."""
    id: str
    title: str
    description: str
    difficulty: str  # beginner, intermediate, advanced
    estimated_time: int  # minutes
    steps: List[TutorialStep]
    prerequisites: List[str] = None
    tags: List[str] = None

@dataclass
class DemoEnvironment:
    """Live demo environment."""
    id: str
    name: str
    description: str
    demo_type: str  # api, gui, cli
    setup_script: str
    cleanup_script: str
    interactive: bool = True
    timeout: int = 300  # 5 minutes

@dataclass
class APIPlaygroundSession:
    """API playground session."""
    session_id: str
    user_id: str
    endpoint: str
    method: str
    parameters: Dict[str, Any]
    headers: Dict[str, str]
    body: str
    response: Optional[Dict[str, Any]] = None
    created_at: float = None

class InteractiveTutorialManager:
    """Interactive tutorial management system."""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.InteractiveTutorialManager")
        self.tutorials: Dict[str, Tutorial] = {}
        self.user_progress: Dict[str, Dict[str, Any]] = defaultdict(dict)
        self.active_sessions = {}

        self._load_default_tutorials()

    def _load_default_tutorials(self):
        """Load default interactive tutorials."""
        # API Basics Tutorial
        api_tutorial = Tutorial(
            id="api_basics",
            title="BLNCS API Basics",
            description="Learn how to use the BLNCS API effectively",
            difficulty="beginner",
            estimated_time=15,
            steps=[
                TutorialStep(
                    id="step_1",
                    title="API Authentication",
                    description="Learn how to authenticate with the BLNCS API",
                    code_snippet="""
import requests

# Set up authentication
headers = {
    'Authorization': 'Bearer YOUR_API_KEY',
    'Content-Type': 'application/json'
}

# Make authenticated request
response = requests.get('https://api.blncs.example.com/v1/system/status', headers=headers)
print(response.json())
                    """,
                    interactive_elements=[{
                        'type': 'code_editor',
                        'language': 'python',
                        'placeholder': 'Enter your API authentication code...'
                    }],
                    hints=["Remember to replace YOUR_API_KEY with your actual API key",
                          "Always include the Authorization header"]
                ),
                TutorialStep(
                    id="step_2",
                    title="Making API Requests",
                    description="Learn how to make different types of API requests",
                    code_snippet="""
import requests

base_url = 'https://api.blncs.example.com/v1'

# GET request - retrieve data
response = requests.get(f'{base_url}/lightning/info')
print('Lightning info:', response.json())

# POST request - create resource
new_channel = {
    'node_id': 'node_123',
    'capacity': 1000000
}
response = requests.post(f'{base_url}/lightning/channels', json=new_channel)
print('Channel created:', response.json())
                    """,
                    interactive_elements=[{
                        'type': 'multiple_choice',
                        'question': 'Which HTTP method is used to retrieve data?',
                        'options': ['GET', 'POST', 'PUT', 'DELETE'],
                        'correct': 'GET'
                    }]
                )
            ],
            tags=["api", "beginner", "authentication"]
        )

        self.tutorials[api_tutorial.id] = api_tutorial

        # GUI Tutorial
        gui_tutorial = Tutorial(
            id="gui_basics",
            title="BLNCS GUI Basics",
            description="Learn how to use the BLNCS graphical interface",
            difficulty="beginner",
            estimated_time=20,
            steps=[
                TutorialStep(
                    id="step_1",
                    title="Starting the GUI",
                    description="Learn how to launch the BLNCS GUI",
                    code_snippet="""
from blncs.gui.dashboard_gui import create_dashboard_gui

# Launch GUI
gui = create_dashboard_gui('http://localhost:5000')
gui.start()
                    """,
                    interactive_elements=[{
                        'type': 'code_editor',
                        'language': 'python',
                        'placeholder': 'Enter code to launch the GUI...'
                    }]
                )
            ],
            tags=["gui", "beginner", "interface"]
        )

        self.tutorials[gui_tutorial.id] = gui_tutorial

    def start_tutorial(self, tutorial_id: str, user_id: str) -> str:
        """Start tutorial for user."""
        if tutorial_id not in self.tutorials:
            raise ValueError(f"Tutorial not found: {tutorial_id}")

        session_id = str(uuid.uuid4())
        self.active_sessions[session_id] = {
            'tutorial_id': tutorial_id,
            'user_id': user_id,
            'current_step': 0,
            'progress': {},
            'started_at': time.time()
        }

        self.logger.info(f"Started tutorial {tutorial_id} for user {user_id}")
        return session_id

    def get_tutorial_step(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get current tutorial step."""
        if session_id not in self.active_sessions:
            return None

        session = self.active_sessions[session_id]
        tutorial = self.tutorials[session['tutorial_id']]
        current_step_idx = session['current_step']

        if current_step_idx >= len(tutorial.steps):
            return None  # Tutorial completed

        step = tutorial.steps[current_step_idx]
        return {
            'tutorial_id': tutorial.id,
            'step_id': step.id,
            'title': step.title,
            'description': step.description,
            'code_snippet': step.code_snippet,
            'interactive_elements': step.interactive_elements or [],
            'hints': step.hints or [],
            'total_steps': len(tutorial.steps),
            'current_step': current_step_idx + 1
        }

    def submit_step_answer(self, session_id: str, answer: Dict[str, Any]) -> Dict[str, Any]:
        """Submit answer for tutorial step."""
        if session_id not in self.active_sessions:
            return {'error': 'Session not found'}

        session = self.active_sessions[session_id]
        tutorial = self.tutorials[session['tutorial_id']]
        current_step_idx = session['current_step']

        if current_step_idx >= len(tutorial.steps):
            return {'error': 'Tutorial already completed'}

        step = tutorial.steps[current_step_idx]

        # Validate answer if validation function exists
        if step.validation_function:
            try:
                is_valid = step.validation_function(answer)
            except Exception as e:
                return {'error': f'Validation failed: {e}'}
        else:
            is_valid = True  # Assume valid if no validation

        # Record progress
        session['progress'][step.id] = {
            'completed': is_valid,
            'answer': answer,
            'completed_at': time.time()
        }

        # Move to next step if valid
        if is_valid:
            session['current_step'] += 1

        return {
            'valid': is_valid,
            'next_step': session['current_step'],
            'tutorial_completed': session['current_step'] >= len(tutorial.steps)
        }

class DemoEnvironmentManager:
    """Live demo environment management."""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.DemoEnvironmentManager")
        self.environments: Dict[str, DemoEnvironment] = {}
        self.active_demos = {}

        self._load_default_demos()

    def _load_default_demos(self):
        """Load default demo environments."""
        self.environments['api_demo'] = DemoEnvironment(
            id="api_demo",
            name="API Demo",
            description="Interactive API testing environment",
            demo_type="api",
            setup_script="setup_api_demo()",
            cleanup_script="cleanup_api_demo()",
            interactive=True,
            timeout=600
        )

        self.environments['gui_demo'] = DemoEnvironment(
            id="gui_demo",
            name="GUI Demo",
            description="Interactive GUI demonstration",
            demo_type="gui",
            setup_script="setup_gui_demo()",
            cleanup_script="cleanup_gui_demo()",
            interactive=True,
            timeout=900
        )

    def start_demo(self, demo_id: str, user_id: str) -> str:
        """Start demo environment."""
        if demo_id not in self.environments:
            raise ValueError(f"Demo not found: {demo_id}")

        demo_session_id = str(uuid.uuid4())
        demo = self.environments[demo_id]

        # Start demo environment
        try:
            exec(demo.setup_script)
            self.logger.info(f"Started demo {demo_id} for user {user_id}")

        except Exception as e:
            self.logger.error(f"Failed to start demo {demo_id}: {e}")
            raise

        self.active_demos[demo_session_id] = {
            'demo_id': demo_id,
            'user_id': user_id,
            'started_at': time.time(),
            'timeout': demo.timeout
        }

        return demo_session_id

    def stop_demo(self, demo_session_id: str):
        """Stop demo environment."""
        if demo_session_id not in self.active_demos:
            return

        demo_session = self.active_demos[demo_session_id]
        demo = self.environments[demo_session['demo_id']]

        try:
            exec(demo.cleanup_script)
            self.logger.info(f"Stopped demo {demo_session['demo_id']}")

        except Exception as e:
            self.logger.error(f"Failed to stop demo {demo_session['demo_id']}: {e}")

        del self.active_demos[demo_session_id]

class APIPlayground:
    """Interactive API playground."""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.APIPlayground")
        self.sessions: Dict[str, APIPlaygroundSession] = {}
        self.session_timeout = 1800  # 30 minutes

    def create_session(self, user_id: str, endpoint: str, method: str) -> str:
        """Create API playground session."""
        session_id = str(uuid.uuid4())

        session = APIPlaygroundSession(
            session_id=session_id,
            user_id=user_id,
            endpoint=endpoint,
            method=method,
            parameters={},
            headers={'Content-Type': 'application/json'},
            body='',
            created_at=time.time()
        )

        self.sessions[session_id] = session
        self.logger.info(f"Created API playground session: {session_id}")

        return session_id

    def execute_request(self, session_id: str) -> Dict[str, Any]:
        """Execute API request in playground."""
        if session_id not in self.sessions:
            return {'error': 'Session not found'}

        session = self.sessions[session_id]

        try:
            import requests

            # Build request URL
            base_url = "https://api.blncs.example.com"  # Would be configurable
            url = f"{base_url}{session.endpoint}"

            # Prepare request
            headers = session.headers.copy()

            # Add authentication if needed
            if 'Authorization' not in headers:
                headers['Authorization'] = 'Bearer DEMO_API_KEY'  # Demo key

            # Make request
            if session.method.upper() == 'GET':
                response = requests.get(url, headers=headers, params=session.parameters, timeout=10)
            elif session.method.upper() == 'POST':
                response = requests.post(url, headers=headers, json=json.loads(session.body) if session.body else {}, timeout=10)
            elif session.method.upper() == 'PUT':
                response = requests.put(url, headers=headers, json=json.loads(session.body) if session.body else {}, timeout=10)
            elif session.method.upper() == 'DELETE':
                response = requests.delete(url, headers=headers, timeout=10)
            else:
                return {'error': f'Unsupported method: {session.method}'}

            # Store response
            session.response = {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'body': response.text,
                'json': response.json() if response.headers.get('content-type', '').startswith('application/json') else None
            }

            return {
                'success': True,
                'response': session.response
            }

        except Exception as e:
            session.response = {
                'error': str(e),
                'status_code': 0
            }

            return {
                'success': False,
                'error': str(e)
            }

    def update_session(self, session_id: str, updates: Dict[str, Any]) -> bool:
        """Update playground session parameters."""
        if session_id not in self.sessions:
            return False

        session = self.sessions[session_id]

        for key, value in updates.items():
            if hasattr(session, key):
                setattr(session, key, value)

        return True

    def get_session_history(self, user_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Get user's session history."""
        user_sessions = [
            session for session in self.sessions.values()
            if session.user_id == user_id
        ]

        return [asdict(session) for session in user_sessions[-limit:]]

class DocumentationServer:
    """Interactive documentation server."""

    def __init__(self, host: str = 'localhost', port: int = 8080):
        self.host = host
        self.port = port
        self.logger = logging.getLogger(f"{__name__}.DocumentationServer")
        self.server = None
        self.server_thread = None

    def start_server(self):
        """Start documentation server."""
        if self.server:
            return

        # Create HTTP server
        handler = DocumentationRequestHandler
        self.server = socketserver.TCPServer((self.host, self.port), handler)

        # Start server in thread
        self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.server_thread.start()

        self.logger.info(f"Documentation server started at http://{self.host}:{self.port}")

    def stop_server(self):
        """Stop documentation server."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None

        if self.server_thread:
            self.server_thread.join(timeout=5)

        self.logger.info("Documentation server stopped")

class DocumentationRequestHandler(http.server.SimpleHTTPRequestHandler):
    """Custom request handler for documentation server."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(Path(__file__).parent / 'docs'), **kwargs)

    def do_GET(self):
        """Handle GET requests."""
        if self.path == '/':
            self.path = '/index.html'
        elif self.path == '/api/playground':
            self._serve_api_playground()
        elif self.path == '/tutorials':
            self._serve_tutorials()
        elif self.path.startswith('/tutorial/'):
            self._serve_tutorial(self.path.split('/')[-1])
        elif self.path.startswith('/demo/'):
            self._serve_demo(self.path.split('/')[-1])
        else:
            super().do_GET()

    def _serve_api_playground(self):
        """Serve API playground interface."""
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>BLNCS API Playground</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .container { max-width: 1200px; margin: 0 auto; }
                .section { margin: 20px 0; padding: 20px; border: 1px solid #ddd; }
                textarea { width: 100%; height: 150px; font-family: monospace; }
                .response { background: #f5f5f5; padding: 10px; margin: 10px 0; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>BLNCS API Playground</h1>

                <div class="section">
                    <h2>Request Configuration</h2>
                    <label>Method:</label>
                    <select id="method">
                        <option value="GET">GET</option>
                        <option value="POST">POST</option>
                        <option value="PUT">PUT</option>
                        <option value="DELETE">DELETE</option>
                    </select>

                    <label>Endpoint:</label>
                    <input type="text" id="endpoint" value="/v1/system/status" style="width: 300px;">

                    <h3>Parameters</h3>
                    <textarea id="parameters" placeholder="JSON parameters...">{}</textarea>

                    <h3>Headers</h3>
                    <textarea id="headers" placeholder="JSON headers...">{"Authorization": "Bearer DEMO_API_KEY"}</textarea>

                    <h3>Body</h3>
                    <textarea id="body" placeholder="JSON body..."></textarea>

                    <button onclick="executeRequest()">Execute Request</button>
                </div>

                <div class="section">
                    <h2>Response</h2>
                    <div id="response" class="response">Response will appear here...</div>
                </div>
            </div>

            <script>
                async function executeRequest() {
                    const method = document.getElementById('method').value;
                    const endpoint = document.getElementById('endpoint').value;
                    const parameters = document.getElementById('parameters').value;
                    const headers = document.getElementById('headers').value;
                    const body = document.getElementById('body').value;

                    try {
                        const response = await fetch('/api/execute', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({method, endpoint, parameters, headers, body})
                        });

                        const result = await response.json();
                        document.getElementById('response').textContent = JSON.stringify(result, null, 2);

                    } catch (error) {
                        document.getElementById('response').textContent = 'Error: ' + error.message;
                    }
                }
            </script>
        </body>
        </html>
        """

        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())

    def _serve_tutorials(self):
        """Serve tutorials list."""
        # In a real implementation, this would show available tutorials
        html = "<h1>Available Tutorials</h1><ul><li>API Basics</li><li>GUI Basics</li></ul>"

        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())

    def _serve_tutorial(self, tutorial_id: str):
        """Serve specific tutorial."""
        # In a real implementation, this would serve the tutorial content
        html = f"<h1>Tutorial: {tutorial_id}</h1><p>Tutorial content would be here...</p>"

        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())

    def _serve_demo(self, demo_id: str):
        """Serve demo interface."""
        html = f"<h1>Demo: {demo_id}</h1><p>Interactive demo would be here...</p>"

        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())

class InteractiveDocumentationManager:
    """Main interactive documentation management system."""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.InteractiveDocumentationManager")
        self.tutorial_manager = InteractiveTutorialManager()
        self.demo_manager = DemoEnvironmentManager()
        self.api_playground = APIPlayground()
        self.doc_server = DocumentationServer()

        self.documentation_active = False
        self.server_thread = None

    def start_documentation_server(self):
        """Start interactive documentation server."""
        if self.documentation_active:
            return

        self.documentation_active = True
        self.doc_server.start_server()

        # Open browser
        def open_browser():
            time.sleep(2)  # Wait for server to start
            webbrowser.open(f"http://{self.doc_server.host}:{self.doc_server.port}")

        browser_thread = threading.Thread(target=open_browser, daemon=True)
        browser_thread.start()

        self.logger.info("Interactive documentation server started")

    def stop_documentation_server(self):
        """Stop interactive documentation server."""
        self.documentation_active = False
        self.doc_server.stop_server()
        self.logger.info("Interactive documentation server stopped")

    def create_tutorial_session(self, tutorial_id: str, user_id: str) -> str:
        """Create interactive tutorial session."""
        return self.tutorial_manager.start_tutorial(tutorial_id, user_id)

    def create_demo_session(self, demo_id: str, user_id: str) -> str:
        """Create demo session."""
        return self.demo_manager.start_demo(demo_id, user_id)

    def create_api_session(self, user_id: str, endpoint: str, method: str) -> str:
        """Create API playground session."""
        return self.api_playground.create_session(user_id, endpoint, method)

    def get_documentation_analytics(self) -> Dict[str, Any]:
        """Get documentation usage analytics."""
        return {
            'active_tutorial_sessions': len(self.tutorial_manager.active_sessions),
            'active_demo_sessions': len(self.demo_manager.active_demos),
            'api_playground_sessions': len(self.api_playground.sessions),
            'total_tutorials': len(self.tutorial_manager.tutorials),
            'total_demos': len(self.demo_manager.environments)
        }

def create_interactive_documentation() -> InteractiveDocumentationManager:
    """Factory function to create interactive documentation system."""
    return InteractiveDocumentationManager()

# Example usage
if __name__ == "__main__":
    # Create interactive documentation system
    doc_manager = create_interactive_documentation()

    # Start documentation server
    doc_manager.start_documentation_server()

    # Create tutorial session
    tutorial_session = doc_manager.create_tutorial_session("api_basics", "user_123")
    print(f"Created tutorial session: {tutorial_session}")

    # Create demo session
    demo_session = doc_manager.create_demo_session("api_demo", "user_123")
    print(f"Created demo session: {demo_session}")

    # Create API playground session
    api_session = doc_manager.create_api_session("user_123", "/v1/system/status", "GET")
    print(f"Created API session: {api_session}")

    # Get analytics
    analytics = doc_manager.get_documentation_analytics()
    print(f"Documentation analytics: {json.dumps(analytics, indent=2)}")

    print("Interactive documentation system setup complete!")

    # Keep server running
    try:
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        doc_manager.stop_documentation_server()
        print("Documentation server stopped")
