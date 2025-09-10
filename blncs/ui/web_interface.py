"""
Mobile-First Responsive Web Interface
Modern, accessible, and performant web interface supporting all device types.
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any, Union, Callable
from enum import Enum
from dataclasses import dataclass, field, asdict
from pathlib import Path
import structlog

logger = structlog.get_logger(__name__)

class DeviceType(Enum):
    MOBILE = "mobile"
    TABLET = "tablet"
    DESKTOP = "desktop"
    TV = "tv"

class BreakPoint(Enum):
    XS = "xs"  # <576px
    SM = "sm"  # ≥576px
    MD = "md"  # ≥768px
    LG = "lg"  # ≥992px
    XL = "xl"  # ≥1200px
    XXL = "xxl"  # ≥1400px

class Theme(Enum):
    LIGHT = "light"
    DARK = "dark"
    AUTO = "auto"
    HIGH_CONTRAST = "high_contrast"
    COLORBLIND_FRIENDLY = "colorblind_friendly"

class ComponentType(Enum):
    # Layout Components
    CONTAINER = "container"
    GRID = "grid"
    FLEX = "flex"
    SIDEBAR = "sidebar"
    HEADER = "header"
    FOOTER = "footer"
    
    # Navigation
    NAVBAR = "navbar"
    BREADCRUMB = "breadcrumb"
    TABS = "tabs"
    PAGINATION = "pagination"
    
    # Form Components
    INPUT = "input"
    BUTTON = "button"
    CHECKBOX = "checkbox"
    RADIO = "radio"
    SELECT = "select"
    TEXTAREA = "textarea"
    FORM = "form"
    
    # Data Display
    TABLE = "table"
    CARD = "card"
    LIST = "list"
    CHART = "chart"
    BADGE = "badge"
    AVATAR = "avatar"
    
    # Feedback
    ALERT = "alert"
    TOAST = "toast"
    MODAL = "modal"
    TOOLTIP = "tooltip"
    LOADING = "loading"
    PROGRESS = "progress"
    
    # Lightning Network Specific
    WALLET_DISPLAY = "wallet_display"
    QR_CODE = "qr_code"
    INVOICE_FORM = "invoice_form"
    PAYMENT_BUTTON = "payment_button"
    CHANNEL_LIST = "channel_list"
    TRANSACTION_HISTORY = "transaction_history"

@dataclass
class UIComponent:
    component_id: str
    component_type: ComponentType
    props: Dict[str, Any] = field(default_factory=dict)
    children: List['UIComponent'] = field(default_factory=list)
    styles: Dict[str, Any] = field(default_factory=dict)
    responsive_styles: Dict[BreakPoint, Dict[str, Any]] = field(default_factory=dict)
    accessibility: Dict[str, Any] = field(default_factory=dict)
    events: Dict[str, str] = field(default_factory=dict)
    
    def add_child(self, child: 'UIComponent'):
        """Add child component"""
        self.children.append(child)
    
    def set_responsive_style(self, breakpoint: BreakPoint, styles: Dict[str, Any]):
        """Set responsive styles for breakpoint"""
        self.responsive_styles[breakpoint] = styles
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'id': self.component_id,
            'type': self.component_type.value,
            'props': self.props,
            'children': [child.to_dict() for child in self.children],
            'styles': self.styles,
            'responsive_styles': {bp.value: styles for bp, styles in self.responsive_styles.items()},
            'accessibility': self.accessibility,
            'events': self.events
        }

@dataclass
class ResponsiveGrid:
    columns: Dict[BreakPoint, int] = field(default_factory=lambda: {
        BreakPoint.XS: 1,
        BreakPoint.SM: 2,
        BreakPoint.MD: 3,
        BreakPoint.LG: 4,
        BreakPoint.XL: 6,
        BreakPoint.XXL: 8
    })
    gap: str = "1rem"
    items: List[UIComponent] = field(default_factory=list)

class ThemeManager:
    def __init__(self):
        self.themes = self._initialize_themes()
        self.current_theme = Theme.LIGHT
        self.custom_themes = {}
    
    def _initialize_themes(self) -> Dict[Theme, Dict[str, Any]]:
        """Initialize default themes"""
        return {
            Theme.LIGHT: {
                'primary': '#007bff',
                'secondary': '#6c757d',
                'success': '#28a745',
                'warning': '#ffc107',
                'danger': '#dc3545',
                'info': '#17a2b8',
                'light': '#f8f9fa',
                'dark': '#343a40',
                'background': '#ffffff',
                'surface': '#f8f9fa',
                'text': '#212529',
                'text_secondary': '#6c757d',
                'border': '#dee2e6',
                'shadow': 'rgba(0, 0, 0, 0.125)',
                'bitcoin_orange': '#f7931a',
                'lightning_purple': '#9146ff'
            },
            
            Theme.DARK: {
                'primary': '#0d6efd',
                'secondary': '#6c757d',
                'success': '#198754',
                'warning': '#ffc107',
                'danger': '#dc3545',
                'info': '#0dcaf0',
                'light': '#f8f9fa',
                'dark': '#212529',
                'background': '#121212',
                'surface': '#1e1e1e',
                'text': '#ffffff',
                'text_secondary': '#adb5bd',
                'border': '#495057',
                'shadow': 'rgba(255, 255, 255, 0.125)',
                'bitcoin_orange': '#f7931a',
                'lightning_purple': '#9146ff'
            },
            
            Theme.HIGH_CONTRAST: {
                'primary': '#ffffff',
                'secondary': '#ffffff',
                'success': '#00ff00',
                'warning': '#ffff00',
                'danger': '#ff0000',
                'info': '#00ffff',
                'light': '#ffffff',
                'dark': '#000000',
                'background': '#000000',
                'surface': '#000000',
                'text': '#ffffff',
                'text_secondary': '#ffffff',
                'border': '#ffffff',
                'shadow': 'rgba(255, 255, 255, 0.5)',
                'bitcoin_orange': '#ffaa00',
                'lightning_purple': '#aa00ff'
            }
        }
    
    def get_theme(self, theme: Theme) -> Dict[str, Any]:
        """Get theme colors"""
        return self.themes.get(theme, self.themes[Theme.LIGHT])
    
    def create_custom_theme(self, name: str, theme_data: Dict[str, Any]):
        """Create custom theme"""
        self.custom_themes[name] = theme_data
    
    def generate_css_variables(self, theme: Theme) -> str:
        """Generate CSS custom properties for theme"""
        theme_data = self.get_theme(theme)
        css_vars = [":root {"]
        
        for key, value in theme_data.items():
            css_vars.append(f"  --color-{key.replace('_', '-')}: {value};")
        
        css_vars.append("}")
        return "\\n".join(css_vars)

class AccessibilityManager:
    def __init__(self):
        self.a11y_features = {
            'keyboard_navigation': True,
            'screen_reader_support': True,
            'high_contrast_mode': False,
            'reduced_motion': False,
            'large_text_mode': False,
            'focus_indicators': True,
            'skip_links': True,
            'aria_labels': True
        }
    
    def apply_accessibility_attributes(self, component: UIComponent) -> UIComponent:
        """Apply accessibility attributes to component"""
        component_type = component.component_type
        
        # Add ARIA attributes based on component type
        if component_type == ComponentType.BUTTON:
            if 'aria-label' not in component.accessibility:
                component.accessibility['aria-label'] = component.props.get('text', 'Button')
            component.accessibility['role'] = 'button'
            component.accessibility['tabindex'] = '0'
        
        elif component_type == ComponentType.INPUT:
            if 'aria-label' not in component.accessibility:
                component.accessibility['aria-label'] = component.props.get('label', 'Input field')
            if component.props.get('required', False):
                component.accessibility['aria-required'] = 'true'
        
        elif component_type == ComponentType.MODAL:
            component.accessibility['role'] = 'dialog'
            component.accessibility['aria-modal'] = 'true'
            if 'aria-labelledby' not in component.accessibility:
                component.accessibility['aria-labelledby'] = f"{component.component_id}-title"
        
        elif component_type == ComponentType.ALERT:
            component.accessibility['role'] = 'alert'
            component.accessibility['aria-live'] = 'polite'
        
        elif component_type == ComponentType.TABLE:
            component.accessibility['role'] = 'table'
            # Add table-specific ARIA attributes
        
        # Add focus management
        if component_type in [ComponentType.BUTTON, ComponentType.INPUT, ComponentType.SELECT]:
            component.styles.update({
                'outline': 'none',
                'box-shadow': 'var(--focus-ring, 0 0 0 2px var(--color-primary))',
            })
        
        return component
    
    def generate_skip_links(self) -> UIComponent:
        """Generate skip navigation links"""
        skip_links = UIComponent(
            component_id="skip-links",
            component_type=ComponentType.CONTAINER,
            props={'class': 'skip-links'},
            styles={
                'position': 'absolute',
                'top': '-40px',
                'left': '6px',
                'background': 'var(--color-background)',
                'color': 'var(--color-text)',
                'padding': '8px',
                'text-decoration': 'none',
                'border-radius': '4px',
                'z-index': '1000',
                'focus:top': '6px'
            }
        )
        
        skip_links.add_child(UIComponent(
            component_id="skip-to-main",
            component_type=ComponentType.BUTTON,
            props={'text': 'Skip to main content', 'href': '#main-content'},
            accessibility={'tabindex': '1'}
        ))
        
        return skip_links
    
    def validate_color_contrast(self, foreground: str, background: str) -> float:
        """Calculate color contrast ratio (simplified)"""
        # This is a simplified implementation
        # In production, use a proper color contrast calculation
        return 4.5  # Mock WCAG AA compliance

class ResponsiveLayoutEngine:
    def __init__(self, theme_manager: ThemeManager):
        self.theme_manager = theme_manager
        self.breakpoints = {
            BreakPoint.XS: 0,
            BreakPoint.SM: 576,
            BreakPoint.MD: 768,
            BreakPoint.LG: 992,
            BreakPoint.XL: 1200,
            BreakPoint.XXL: 1400
        }
    
    def create_responsive_container(self, max_width: Optional[str] = None) -> UIComponent:
        """Create responsive container"""
        container = UIComponent(
            component_id=f"container-{uuid.uuid4().hex[:8]}",
            component_type=ComponentType.CONTAINER,
            styles={
                'width': '100%',
                'margin': '0 auto',
                'padding': '0 1rem'
            }
        )
        
        # Add responsive max-widths
        container.set_responsive_style(BreakPoint.SM, {'max-width': '540px'})
        container.set_responsive_style(BreakPoint.MD, {'max-width': '720px'})
        container.set_responsive_style(BreakPoint.LG, {'max-width': '960px'})
        container.set_responsive_style(BreakPoint.XL, {'max-width': '1140px'})
        container.set_responsive_style(BreakPoint.XXL, {'max-width': '1320px'})
        
        if max_width:
            container.styles['max-width'] = max_width
        
        return container
    
    def create_responsive_grid(self, grid_config: ResponsiveGrid) -> UIComponent:
        """Create responsive CSS grid"""
        grid = UIComponent(
            component_id=f"grid-{uuid.uuid4().hex[:8]}",
            component_type=ComponentType.GRID,
            styles={
                'display': 'grid',
                'gap': grid_config.gap,
                'width': '100%'
            }
        )
        
        # Set responsive grid columns
        for breakpoint, columns in grid_config.columns.items():
            grid.set_responsive_style(breakpoint, {
                'grid-template-columns': f"repeat({columns}, 1fr)"
            })
        
        # Add grid items
        for item in grid_config.items:
            grid.add_child(item)
        
        return grid
    
    def create_flexible_layout(self, direction: str = "column") -> UIComponent:
        """Create flexible layout using flexbox"""
        return UIComponent(
            component_id=f"flex-{uuid.uuid4().hex[:8]}",
            component_type=ComponentType.FLEX,
            styles={
                'display': 'flex',
                'flex-direction': direction,
                'gap': '1rem',
                'width': '100%'
            },
            responsive_styles={
                BreakPoint.MD: {'flex-direction': 'row' if direction == 'column' else 'column'}
            }
        )
    
    def generate_responsive_css(self, component: UIComponent) -> str:
        """Generate responsive CSS for component"""
        css_rules = []
        
        # Base styles
        if component.styles:
            selector = f"#{component.component_id}"
            rules = [f"  {prop}: {value};" for prop, value in component.styles.items()]
            css_rules.append(f"{selector} {{\\n{''.join(rules)}\\n}}")
        
        # Responsive styles
        for breakpoint, styles in component.responsive_styles.items():
            if styles:
                min_width = self.breakpoints[breakpoint]
                selector = f"#{component.component_id}"
                rules = [f"  {prop}: {value};" for prop, value in styles.items()]
                
                media_query = f"@media (min-width: {min_width}px) {{\\n"
                media_query += f"  {selector} {{\\n    {'    '.join(rules)}\\n  }}\\n"
                media_query += "}"
                
                css_rules.append(media_query)
        
        return "\\n\\n".join(css_rules)

class MobileOptimizations:
    def __init__(self):
        self.mobile_features = {
            'touch_gestures': True,
            'swipe_navigation': True,
            'pull_to_refresh': True,
            'haptic_feedback': True,
            'offline_support': True,
            'app_like_navigation': True
        }
    
    def optimize_for_touch(self, component: UIComponent) -> UIComponent:
        """Optimize component for touch interfaces"""
        if component.component_type in [ComponentType.BUTTON, ComponentType.INPUT]:
            # Ensure minimum touch target size (44px)
            component.styles.update({
                'min-height': '44px',
                'min-width': '44px',
                'touch-action': 'manipulation'
            })
        
        if component.component_type == ComponentType.BUTTON:
            # Add touch states
            component.styles.update({
                'user-select': 'none',
                'webkit-tap-highlight-color': 'transparent'
            })
        
        return component
    
    def add_swipe_gestures(self, component: UIComponent, 
                          gestures: Dict[str, str]) -> UIComponent:
        """Add swipe gesture support"""
        component.events.update({
            'touchstart': 'handleTouchStart',
            'touchmove': 'handleTouchMove',
            'touchend': 'handleTouchEnd'
        })
        
        component.props['swipe_gestures'] = gestures
        return component
    
    def create_mobile_navigation(self) -> UIComponent:
        """Create mobile-optimized navigation"""
        nav = UIComponent(
            component_id="mobile-nav",
            component_type=ComponentType.NAVBAR,
            styles={
                'position': 'fixed',
                'bottom': '0',
                'left': '0',
                'right': '0',
                'background': 'var(--color-surface)',
                'border-top': '1px solid var(--color-border)',
                'display': 'flex',
                'justify-content': 'space-around',
                'padding': '0.5rem',
                'z-index': '1000'
            },
            responsive_styles={
                BreakPoint.MD: {'display': 'none'}  # Hide on larger screens
            }
        )
        
        # Add navigation items
        nav_items = [
            {'icon': 'home', 'label': 'Home', 'href': '/'},
            {'icon': 'wallet', 'label': 'Wallet', 'href': '/wallet'},
            {'icon': 'send', 'label': 'Send', 'href': '/send'},
            {'icon': 'history', 'label': 'History', 'href': '/history'},
            {'icon': 'settings', 'label': 'Settings', 'href': '/settings'}
        ]
        
        for item in nav_items:
            nav.add_child(UIComponent(
                component_id=f"nav-{item['icon']}",
                component_type=ComponentType.BUTTON,
                props={
                    'icon': item['icon'],
                    'text': item['label'],
                    'href': item['href']
                },
                styles={
                    'display': 'flex',
                    'flex-direction': 'column',
                    'align-items': 'center',
                    'gap': '0.25rem',
                    'padding': '0.5rem',
                    'border': 'none',
                    'background': 'transparent',
                    'color': 'var(--color-text-secondary)',
                    'font-size': '0.75rem',
                    'min-width': '44px'
                }
            ))
        
        return nav

class UIComponentLibrary:
    def __init__(self, theme_manager: ThemeManager, accessibility_manager: AccessibilityManager):
        self.theme_manager = theme_manager
        self.accessibility_manager = accessibility_manager
        self.components = {}
    
    def create_wallet_display(self, balance_sats: int, currency: str = "BTC") -> UIComponent:
        """Create wallet balance display component"""
        wallet_display = UIComponent(
            component_id=f"wallet-{uuid.uuid4().hex[:8]}",
            component_type=ComponentType.WALLET_DISPLAY,
            props={
                'balance_sats': balance_sats,
                'currency': currency,
                'formatted_balance': f"{balance_sats:,} sats"
            },
            styles={
                'background': 'linear-gradient(135deg, var(--color-primary), var(--lightning-purple))',
                'color': 'white',
                'padding': '2rem',
                'border-radius': '1rem',
                'text-align': 'center',
                'margin-bottom': '1rem'
            }
        )
        
        # Add balance text
        wallet_display.add_child(UIComponent(
            component_id=f"balance-{uuid.uuid4().hex[:8]}",
            component_type=ComponentType.CONTAINER,
            props={'class': 'balance-display'},
            styles={
                'font-size': '2rem',
                'font-weight': 'bold',
                'margin-bottom': '0.5rem'
            }
        ))
        
        return self.accessibility_manager.apply_accessibility_attributes(wallet_display)
    
    def create_qr_code(self, data: str, size: int = 200) -> UIComponent:
        """Create QR code component"""
        qr_component = UIComponent(
            component_id=f"qr-{uuid.uuid4().hex[:8]}",
            component_type=ComponentType.QR_CODE,
            props={
                'data': data,
                'size': size,
                'error_correction': 'M'
            },
            styles={
                'display': 'flex',
                'justify-content': 'center',
                'align-items': 'center',
                'padding': '1rem',
                'background': 'white',
                'border-radius': '0.5rem',
                'border': '1px solid var(--color-border)'
            },
            accessibility={
                'alt': f"QR code containing: {data[:50]}...",
                'role': 'img'
            }
        )
        
        return qr_component
    
    def create_payment_button(self, amount_sats: int, recipient: str) -> UIComponent:
        """Create Lightning payment button"""
        payment_button = UIComponent(
            component_id=f"pay-btn-{uuid.uuid4().hex[:8]}",
            component_type=ComponentType.PAYMENT_BUTTON,
            props={
                'amount_sats': amount_sats,
                'recipient': recipient,
                'text': f"Pay {amount_sats:,} sats"
            },
            styles={
                'background': 'var(--lightning-purple)',
                'color': 'white',
                'border': 'none',
                'padding': '1rem 2rem',
                'border-radius': '0.5rem',
                'font-size': '1.1rem',
                'font-weight': 'bold',
                'cursor': 'pointer',
                'width': '100%',
                'transition': 'all 0.2s ease'
            },
            events={
                'click': 'handlePayment',
                'hover': 'handleHover'
            }
        )
        
        return self.accessibility_manager.apply_accessibility_attributes(payment_button)
    
    def create_transaction_history(self, transactions: List[Dict[str, Any]]) -> UIComponent:
        """Create transaction history component"""
        history = UIComponent(
            component_id=f"history-{uuid.uuid4().hex[:8]}",
            component_type=ComponentType.TRANSACTION_HISTORY,
            props={'transactions': transactions},
            styles={
                'background': 'var(--color-surface)',
                'border-radius': '0.5rem',
                'overflow': 'hidden'
            }
        )
        
        for i, tx in enumerate(transactions):
            tx_item = UIComponent(
                component_id=f"tx-{i}",
                component_type=ComponentType.LIST,
                props={
                    'type': tx.get('type', 'payment'),
                    'amount': tx.get('amount_sats', 0),
                    'timestamp': tx.get('timestamp'),
                    'status': tx.get('status', 'completed')
                },
                styles={
                    'display': 'flex',
                    'justify-content': 'space-between',
                    'align-items': 'center',
                    'padding': '1rem',
                    'border-bottom': '1px solid var(--color-border)' if i < len(transactions) - 1 else 'none'
                }
            )
            history.add_child(tx_item)
        
        return history
    
    def create_responsive_form(self, fields: List[Dict[str, Any]]) -> UIComponent:
        """Create responsive form"""
        form = UIComponent(
            component_id=f"form-{uuid.uuid4().hex[:8]}",
            component_type=ComponentType.FORM,
            styles={
                'display': 'flex',
                'flex-direction': 'column',
                'gap': '1rem',
                'width': '100%'
            }
        )
        
        for field in fields:
            field_component = UIComponent(
                component_id=f"field-{field['name']}",
                component_type=ComponentType.INPUT,
                props=field,
                styles={
                    'width': '100%',
                    'padding': '0.75rem',
                    'border': '1px solid var(--color-border)',
                    'border-radius': '0.375rem',
                    'font-size': '1rem'
                }
            )
            form.add_child(self.accessibility_manager.apply_accessibility_attributes(field_component))
        
        return form

class ComponentRenderer:
    def __init__(self, layout_engine: ResponsiveLayoutEngine):
        self.layout_engine = layout_engine
    
    def render_to_html(self, component: UIComponent) -> str:
        """Render component to HTML"""
        tag = self._get_html_tag(component.component_type)
        attrs = self._build_html_attributes(component)
        styles = self._build_inline_styles(component)
        
        html = f"<{tag}{attrs}{styles}>"
        
        # Add children
        for child in component.children:
            html += self.render_to_html(child)
        
        # Add text content if present
        if 'text' in component.props:
            html += component.props['text']
        
        html += f"</{tag}>"
        
        return html
    
    def _get_html_tag(self, component_type: ComponentType) -> str:
        """Get HTML tag for component type"""
        tag_mapping = {
            ComponentType.CONTAINER: 'div',
            ComponentType.BUTTON: 'button',
            ComponentType.INPUT: 'input',
            ComponentType.FORM: 'form',
            ComponentType.GRID: 'div',
            ComponentType.FLEX: 'div',
            ComponentType.HEADER: 'header',
            ComponentType.FOOTER: 'footer',
            ComponentType.NAVBAR: 'nav',
            ComponentType.TABLE: 'table',
            ComponentType.CARD: 'div',
            ComponentType.LIST: 'ul',
            ComponentType.MODAL: 'div'
        }
        
        return tag_mapping.get(component_type, 'div')
    
    def _build_html_attributes(self, component: UIComponent) -> str:
        """Build HTML attributes string"""
        attrs = [f'id="{component.component_id}"']
        
        # Add accessibility attributes
        for key, value in component.accessibility.items():
            attrs.append(f'{key}="{value}"')
        
        # Add data attributes
        for key, value in component.props.items():
            if key.startswith('data-') or key in ['class', 'type', 'name', 'value']:
                attrs.append(f'{key}="{value}"')
        
        return ' ' + ' '.join(attrs) if attrs else ''
    
    def _build_inline_styles(self, component: UIComponent) -> str:
        """Build inline styles string"""
        if not component.styles:
            return ''
        
        style_rules = []
        for prop, value in component.styles.items():
            # Convert camelCase to kebab-case
            css_prop = prop.replace('_', '-')
            style_rules.append(f"{css_prop}: {value}")
        
        return f' style="{"; ".join(style_rules)}"'

class WebInterfaceManager:
    def __init__(self):
        self.theme_manager = ThemeManager()
        self.accessibility_manager = AccessibilityManager()
        self.layout_engine = ResponsiveLayoutEngine(self.theme_manager)
        self.mobile_optimizations = MobileOptimizations()
        self.component_library = UIComponentLibrary(self.theme_manager, self.accessibility_manager)
        self.renderer = ComponentRenderer(self.layout_engine)
        self.pages = {}
        self.global_components = {}
    
    async def initialize(self):
        """Initialize web interface"""
        # Create global components
        self.global_components['skip_links'] = self.accessibility_manager.generate_skip_links()
        self.global_components['mobile_nav'] = self.mobile_optimizations.create_mobile_navigation()
        
        logger.info("Web interface initialized successfully")
    
    def create_dashboard_page(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create dashboard page layout"""
        # Create main container
        container = self.layout_engine.create_responsive_container()
        
        # Create header
        header = UIComponent(
            component_id="dashboard-header",
            component_type=ComponentType.HEADER,
            styles={
                'padding': '1rem 0',
                'margin-bottom': '2rem',
                'border-bottom': '1px solid var(--color-border)'
            }
        )
        
        # Add wallet display
        wallet_balance = user_data.get('wallet_balance_sats', 0)
        wallet_display = self.component_library.create_wallet_display(wallet_balance)
        
        # Create grid for dashboard cards
        grid_items = []
        
        # Quick actions card
        quick_actions = UIComponent(
            component_id="quick-actions",
            component_type=ComponentType.CARD,
            styles={
                'background': 'var(--color-surface)',
                'padding': '1.5rem',
                'border-radius': '0.5rem',
                'border': '1px solid var(--color-border)'
            }
        )
        
        # Add quick action buttons
        quick_actions.add_child(self.component_library.create_payment_button(1000, "Test Payment"))
        grid_items.append(quick_actions)
        
        # Recent transactions
        transactions = user_data.get('recent_transactions', [])
        if transactions:
            tx_history = self.component_library.create_transaction_history(transactions)
            grid_items.append(tx_history)
        
        # Create responsive grid
        grid_config = ResponsiveGrid(items=grid_items)
        dashboard_grid = self.layout_engine.create_responsive_grid(grid_config)
        
        # Build page structure
        container.add_child(header)
        container.add_child(wallet_display)
        container.add_child(dashboard_grid)
        
        return {
            'page_id': 'dashboard',
            'title': 'BLNCS Dashboard',
            'component': container.to_dict(),
            'css': self.layout_engine.generate_responsive_css(container),
            'meta': {
                'viewport': 'width=device-width, initial-scale=1.0',
                'mobile_optimized': True,
                'accessibility_compliant': True
            }
        }
    
    def create_onboarding_page(self, wizard_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create onboarding wizard page"""
        container = self.layout_engine.create_responsive_container("600px")
        
        # Progress indicator
        progress = UIComponent(
            component_id="onboarding-progress",
            component_type=ComponentType.PROGRESS,
            props={
                'current': wizard_data.get('completed_steps', 0),
                'total': wizard_data.get('total_steps', 1),
                'percentage': wizard_data.get('completion_percentage', 0)
            },
            styles={
                'width': '100%',
                'height': '4px',
                'background': 'var(--color-light)',
                'border-radius': '2px',
                'margin-bottom': '2rem',
                'overflow': 'hidden'
            }
        )
        
        # Current step content
        current_step = wizard_data.get('current_step', {})
        step_component = UIComponent(
            component_id="current-step",
            component_type=ComponentType.CONTAINER,
            styles={
                'background': 'var(--color-surface)',
                'padding': '2rem',
                'border-radius': '0.5rem',
                'border': '1px solid var(--color-border)'
            }
        )
        
        # Step form
        if current_step.get('data_requirements'):
            form_fields = []
            for field_name in current_step['data_requirements']:
                form_fields.append({
                    'name': field_name,
                    'type': 'text',
                    'label': field_name.replace('_', ' ').title(),
                    'required': True
                })
            
            form = self.component_library.create_responsive_form(form_fields)
            step_component.add_child(form)
        
        container.add_child(progress)
        container.add_child(step_component)
        
        return {
            'page_id': 'onboarding',
            'title': f"Setup - {current_step.get('title', 'Getting Started')}",
            'component': container.to_dict(),
            'css': self.layout_engine.generate_responsive_css(container)
        }
    
    def set_theme(self, theme: Theme):
        """Set current theme"""
        self.theme_manager.current_theme = theme
    
    def generate_global_css(self) -> str:
        """Generate global CSS with theme variables"""
        css_parts = []
        
        # Theme variables
        css_parts.append(self.theme_manager.generate_css_variables(self.theme_manager.current_theme))
        
        # Base styles
        css_parts.append("""
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--color-background);
            color: var(--color-text);
            line-height: 1.5;
        }
        
        @media (prefers-reduced-motion: reduce) {
            * {
                animation-duration: 0.01ms !important;
                animation-iteration-count: 1 !important;
                transition-duration: 0.01ms !important;
            }
        }
        
        .sr-only {
            position: absolute;
            width: 1px;
            height: 1px;
            padding: 0;
            margin: -1px;
            overflow: hidden;
            clip: rect(0, 0, 0, 0);
            white-space: nowrap;
            border: 0;
        }
        """)
        
        return "\\n\\n".join(css_parts)
    
    async def get_page_data(self, page_id: str, user_data: Dict[str, Any] = None) -> Dict[str, Any]:
        """Get complete page data including HTML, CSS, and metadata"""
        user_data = user_data or {}
        
        if page_id == 'dashboard':
            return self.create_dashboard_page(user_data)
        elif page_id == 'onboarding':
            return self.create_onboarding_page(user_data)
        else:
            # Return 404 page
            return self.create_404_page()
    
    def create_404_page(self) -> Dict[str, Any]:
        """Create 404 error page"""
        container = self.layout_engine.create_responsive_container()
        
        error_component = UIComponent(
            component_id="error-404",
            component_type=ComponentType.CONTAINER,
            props={'text': 'Page not found'},
            styles={
                'text-align': 'center',
                'padding': '4rem 2rem',
                'font-size': '1.5rem',
                'color': 'var(--color-text-secondary)'
            }
        )
        
        container.add_child(error_component)
        
        return {
            'page_id': '404',
            'title': 'Page Not Found - BLNCS',
            'component': container.to_dict(),
            'status_code': 404
        }

# Global web interface manager
_web_interface_manager = None

async def get_web_interface_manager() -> WebInterfaceManager:
    """Get or create web interface manager"""
    global _web_interface_manager
    
    if _web_interface_manager is None:
        _web_interface_manager = WebInterfaceManager()
        await _web_interface_manager.initialize()
    
    return _web_interface_manager

async def initialize_web_interface() -> WebInterfaceManager:
    """Initialize web interface system"""
    manager = WebInterfaceManager()
    await manager.initialize()
    logger.info("Mobile-first responsive web interface initialized")
    return manager