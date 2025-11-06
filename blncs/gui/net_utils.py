"""
Modern networking utilities for BLNCS GUI with Atlassian-inspired reliability.

This module provides robust networking components optimized for the native GUI,
including proxy-aware WebSocket connections and resilient HTTP sessions.
"""

import random
import time
import threading
from typing import Callable, Optional, Dict, Any

# Configure logger
logger = logging.getLogger(__name__)


class NetworkUtils:
    """
    Modern networking utilities with Atlassian-inspired reliability features.

    Provides proxy-aware WebSocket URL construction and resilient HTTP sessions
    with configurable timeouts and retry strategies.
    """

    def __init__(self):
        """Initialize network utilities with sensible defaults."""
        self._session_defaults = {
            'timeout': 30,
            'user_agent': 'BLNCS-GUI/2.0',
            'verify_ssl': True,
            'max_retries': 3,
            'backoff_factor': 0.3,
            'status_forcelist': (500, 502, 503, 504)
        }

    def build_ws_url(self, base_url: str, endpoint: str = '/ws/dashboard') -> str:
        """
        Build WebSocket URL with scheme conversion and path handling.

        Args:
            base_url: Base HTTP/HTTPS URL (e.g., 'http://localhost:5000')
            endpoint: WebSocket endpoint path (default: '/ws/dashboard')

        Returns:
            Properly formatted WebSocket URL (ws:// or wss://)

        Raises:
            ValueError: If base_url is invalid or endpoint is malformed
        """
        try:
            parsed = urlparse(base_url)

            if not parsed.scheme or not parsed.netloc:
                raise ValueError(f"Invalid base URL: {base_url}")

            # Convert http/https to ws/wss
            ws_scheme = 'wss' if parsed.scheme == 'https' else 'ws'

            # Build WebSocket URL
            ws_url = urlunparse((
                ws_scheme,
                parsed.netloc,
                endpoint,
                None,  # params
                None,  # query
                None   # fragment
            ))

            logger.debug(f"Built WebSocket URL: {ws_url}")
            return ws_url

        except Exception as e:
            logger.error(f"Failed to build WebSocket URL from {base_url}: {e}")
            raise ValueError(f"Invalid WebSocket URL construction: {e}") from e

    def create_http_session(
        self,
        timeout: Optional[int] = None,
        user_agent: Optional[str] = None,
        verify_ssl: Optional[bool] = None,
        proxies: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        max_retries: Optional[int] = None,
        **kwargs
    ) -> requests.Session:
        """
        Create a robust HTTP session with Atlassian-inspired reliability.

        Args:
            timeout: Request timeout in seconds (default: 30)
            user_agent: Custom User-Agent string (default: 'BLNCS-GUI/2.0')
            verify_ssl: SSL verification setting (default: True)
            proxies: Proxy configuration dict (default: None)
            headers: Additional headers (default: None)
            max_retries: Maximum retry attempts (default: 3)
            **kwargs: Additional session configuration

        Returns:
            Configured requests.Session with retry strategy and adapters
        """
        # Use defaults or provided values
        timeout = timeout or self._session_defaults['timeout']
        user_agent = user_agent or self._session_defaults['user_agent']
        verify_ssl = verify_ssl if verify_ssl is not None else self._session_defaults['verify_ssl']
        max_retries = max_retries or self._session_defaults['max_retries']

        # Create session with modern configuration
        session = requests.Session()

        # Configure retry strategy (Atlassian-inspired resilience)
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=self._session_defaults['backoff_factor'],
            status_forcelist=self._session_defaults['status_forcelist'],
            allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE"]
        )

        # Mount adapters with retry strategy
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        # Set default headers
        session.headers.update({
            'User-Agent': user_agent,
            'Accept': 'application/json, text/plain, */*',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache'
        })

        # Add custom headers
        if headers:
            session.headers.update(headers)

        # Configure SSL and timeout
        session.verify = verify_ssl

        # Ensure all requests use the configured timeout by default
        original_request = session.request

        def request_with_timeout(method, url, **request_kwargs):
            if 'timeout' not in request_kwargs:
                request_kwargs['timeout'] = timeout
            return original_request(method, url, **request_kwargs)

        session.request = request_with_timeout  # type: ignore[assignment]

        # Handle proxy configuration with environment fallback
        if proxies is None and not os.getenv('BLNCS_GUI_NO_PROXY'):
            proxies = self._get_system_proxies()

        if proxies:
            session.proxies.update(proxies)
            logger.debug(f"Using proxy configuration: {proxies}")

        # Additional session configuration
        for key, value in kwargs.items():
            setattr(session, key, value)

        logger.debug("Created HTTP session with modern configuration")
        return session

    def _get_system_proxies(self) -> Dict[str, str]:
        """
        Get system proxy configuration with Atlassian-style proxy handling.

        Returns:
            Dictionary of proxy URLs by protocol, or empty dict if no proxies
        """
        proxies = {}

        # Check for explicit proxy environment variables
        proxy_vars = {
            'http': os.getenv('HTTP_PROXY', os.getenv('http_proxy')),
            'https': os.getenv('HTTPS_PROXY', os.getenv('https_proxy')),
            'no_proxy': os.getenv('NO_PROXY', os.getenv('no_proxy'))
        }

        for protocol, proxy_url in proxy_vars.items():
            if protocol == 'no_proxy' and proxy_url:
                # Handle no_proxy list (not used in session.proxies)
                continue
            elif proxy_url:
                proxies[protocol] = proxy_url

        return proxies

    def test_connectivity(self, base_url: str, timeout: int = 10) -> Tuple[bool, str]:
        """
        Test connectivity to the BLNCS API with modern error handling.

        Args:
            base_url: Base URL to test (e.g., 'http://localhost:5000')
            timeout: Connection timeout in seconds (default: 10)

        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            session = self.create_http_session(timeout=timeout)

            # Test basic connectivity with health endpoint
            health_url = urljoin(base_url, '/health')
            response = session.get(health_url, timeout=timeout)

            if response.status_code == 200:
                return True, "API connectivity verified"
            else:
                return False, f"API returned status {response.status_code}"

        except requests.exceptions.Timeout:
            return False, "Connection timeout"
        except requests.exceptions.ConnectionError:
            return False, "Connection refused"
        except requests.exceptions.RequestException as e:
            return False, f"Request failed: {str(e)}"
        except Exception as e:
            return False, f"Unexpected error: {str(e)}"

    def create_websocket_connection(
        self,
        ws_url: str,
        header: Optional[Dict[str, str]] = None,
        cookie: Optional[str] = None,
        enable_trace: bool = False
    ) -> websocket.WebSocket:
        """
        Create WebSocket connection with modern configuration.

        Args:
            ws_url: WebSocket URL to connect to
            header: Optional headers dictionary
            cookie: Optional cookie string
            enable_trace: Enable WebSocket trace logging (default: False)

        Returns:
            Configured WebSocket connection object
        """
        try:
            # Create WebSocket with modern options
            ws = websocket.WebSocket()

            # Apply headers if provided
            if header:
                ws.headers = header

            # Apply cookie if provided
            if cookie:
                ws.cookies = cookie

            # Configure tracing for debugging
            ws.enable_trace = enable_trace

            logger.debug(f"Created WebSocket connection for: {ws_url}")
            return ws

        except Exception as e:
            logger.error(f"Failed to create WebSocket connection: {e}")
            raise


class ResilientWebSocket:
    """
    Resilient WebSocket connection with jittered exponential backoff.
    """

    def __init__(self, url: str, on_message: Callable, on_error: Callable = None,
                 on_close: Callable = None, on_open: Callable = None,
                 max_reconnect_attempts: int = 10, base_delay: float = 1.0,
                 max_delay: float = 60.0):
        """
        Initialize resilient WebSocket connection.

        Args:
            url: WebSocket URL to connect to
            on_message: Callback for received messages
            on_error: Callback for errors (optional)
            on_close: Callback for connection close (optional)
            on_open: Callback for successful connection (optional)
            max_reconnect_attempts: Maximum reconnection attempts
            base_delay: Base delay for exponential backoff (seconds)
            max_delay: Maximum delay for backoff (seconds)
        """
        self.url = url
        self.on_message = on_message
        self.on_error = on_error
        self.on_close = on_close
        self.on_open = on_open
        self.max_reconnect_attempts = max_reconnect_attempts
        self.base_delay = base_delay
        self.max_delay = max_delay

        self.websocket = None
        self.is_connected = False
        self.reconnect_attempts = 0
        self._stop_event = threading.Event()
        self._reconnect_thread = None

    def connect(self):
        """Start WebSocket connection with resilient reconnection."""
        if self.is_connected or self._reconnect_thread and self._reconnect_thread.is_alive():
            return

        self._reconnect_thread = threading.Thread(target=self._connection_loop, daemon=True)
        self._reconnect_thread.start()

    def disconnect(self):
        """Stop WebSocket connection and reconnection attempts."""
        self._stop_event.set()
        if self.websocket:
            try:
                self.websocket.close()
            except:
                pass
        self.is_connected = False

    def _connection_loop(self):
        """Main connection loop with reconnection logic."""
        while not self._stop_event.is_set():
            try:
                self._connect_websocket()
                break  # Successful connection, exit loop
            except Exception as e:
                logger.error(f"WebSocket connection failed: {e}")
                if self.reconnect_attempts >= self.max_reconnect_attempts:
                    logger.error("Max reconnection attempts reached")
                    if self.on_error:
                        self.on_error(f"Max reconnection attempts ({self.max_reconnect_attempts}) reached")
                    break

                # Calculate delay with jittered exponential backoff
                delay = min(self.base_delay * (2 ** self.reconnect_attempts), self.max_delay)
                jitter = random.uniform(0.5, 1.5) * delay
                actual_delay = min(jitter, self.max_delay)

                logger.info(f"Reconnecting in {actual_delay:.2f} seconds (attempt {self.reconnect_attempts + 1}/{self.max_reconnect_attempts})")

                if self._stop_event.wait(actual_delay):
                    break  # Stop requested

                self.reconnect_attempts += 1

    def _connect_websocket(self):
        """Establish WebSocket connection."""
        try:
            self.websocket = websocket.WebSocket()
            self.websocket.connect(self.url)

            self.is_connected = True
            self.reconnect_attempts = 0

            logger.info(f"WebSocket connected to {self.url}")

            if self.on_open:
                self.on_open()

            # Start message handling thread
            threading.Thread(target=self._message_loop, daemon=True).start()

        except Exception as e:
            logger.error(f"Failed to connect WebSocket: {e}")
            raise

    def _message_loop(self):
        """Handle incoming WebSocket messages."""
        try:
            while not self._stop_event.is_set() and self.is_connected:
                message = self.websocket.recv()
                if message:
                    if self.on_message:
                        self.on_message(message)
        except websocket.WebSocketConnectionClosedException:
            logger.warning("WebSocket connection closed")
            self.is_connected = False
            if self.on_close:
                self.on_close()
        except Exception as e:
            logger.error(f"WebSocket message error: {e}")
            self.is_connected = False
            if self.on_error:
                self.on_error(str(e))
        finally:
            self.is_connected = False

    def send(self, message: str):
        """Send message through WebSocket."""
        if self.is_connected and self.websocket:
            try:
                self.websocket.send(message)
            except Exception as e:
                logger.error(f"Failed to send WebSocket message: {e}")
                self.is_connected = False
                raise

    def is_alive(self) -> bool:
        """Check if WebSocket connection is alive."""
        return self.is_connected and self.websocket is not None
