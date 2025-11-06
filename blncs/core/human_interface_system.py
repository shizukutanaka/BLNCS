"""
Human-Centric Interface System
Ultra-intuitive Lightning Network operations for end users
"""

import asyncio
import logging
import re
import difflib
from typing import Any, Dict, List, Optional, Tuple, Callable, Union
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum
import json
import time

logger = logging.getLogger(__name__)


class IntentType(Enum):
    """User intent categories"""
    BALANCE_INQUIRY = "balance"
    PAYMENT_SEND = "payment"
    INVOICE_CREATE = "invoice"
    STATUS_CHECK = "status"
    HELP_REQUEST = "help"
    CHANNEL_MANAGE = "channel"
    TRANSACTION_HISTORY = "history"
    SETTINGS_CHANGE = "settings"
    UNKNOWN = "unknown"


class UXLevel(Enum):
    """User experience levels"""
    BEGINNER = "beginner"      # First-time users
    INTERMEDIATE = "intermediate"  # Some crypto experience
    ADVANCED = "advanced"      # Technical users
    EXPERT = "expert"         # Lightning developers


@dataclass
class UserContext:
    """User context and preferences"""
    user_id: str
    ux_level: UXLevel = UXLevel.BEGINNER
    preferred_language: str = "en"
    preferred_currency: str = "sats"
    last_commands: List[str] = field(default_factory=list)
    error_count: int = 0
    success_count: int = 0
    session_start: datetime = field(default_factory=datetime.now)


@dataclass
class ParsedCommand:
    """Parsed user command"""
    original_text: str
    intent: IntentType
    confidence: float
    parameters: Dict[str, Any] = field(default_factory=dict)
    suggestions: List[str] = field(default_factory=list)
    ambiguities: List[str] = field(default_factory=list)


class NaturalLanguageProcessor:
    """Process natural language commands"""

    def __init__(self):
        self.intent_patterns = {
            IntentType.BALANCE_INQUIRY: [
                r"\b(balance|funds|money|sats|bitcoin|btc)\b",
                r"\bhow much\b",
                r"\bcheck.*balance\b",
                r"\bshow.*balance\b"
            ],
            IntentType.PAYMENT_SEND: [
                r"\b(send|pay|transfer|give)\b",
                r"\bpay\s+\d+",
                r"\bsend.*sats?\b",
                r"\btransfer.*to\b"
            ],
            IntentType.INVOICE_CREATE: [
                r"\b(invoice|bill|charge|request)\b",
                r"\bcreate.*invoice\b",
                r"\brequest.*payment\b",
                r"\bcharge.*for\b"
            ],
            IntentType.STATUS_CHECK: [
                r"\b(status|health|state|condition)\b",
                r"\bhow.*doing\b",
                r"\bcheck.*system\b",
                r"\bnode.*status\b"
            ],
            IntentType.HELP_REQUEST: [
                r"\b(help|assist|guide|how|what|explain)\b",
                r"\bdon't know\b",
                r"\bconfused\b",
                r"\bwhat.*do\b"
            ],
            IntentType.CHANNEL_MANAGE: [
                r"\b(channel|connection|peer|node)\b",
                r"\bopen.*channel\b",
                r"\bclose.*channel\b",
                r"\bconnect.*to\b"
            ],
            IntentType.TRANSACTION_HISTORY: [
                r"\b(history|transactions|payments|past|previous)\b",
                r"\bshow.*payments\b",
                r"\blist.*transactions\b",
                r"\bpayment.*history\b"
            ]
        }

        self.amount_patterns = [
            r"(\d+(?:\.\d+)?)\s*(sats?|satoshis?)",
            r"(\d+(?:\.\d+)?)\s*(btc|bitcoin)",
            r"(\d+(?:\.\d+)?)\s*(msat|millisat)",
            r"\$(\d+(?:\.\d+)?)",
            r"(\d+(?:\.\d+)?)\s*dollars?"
        ]

        self.common_typos = {
            "ballance": "balance",
            "ballence": "balance",
            "paymemt": "payment",
            "invoce": "invoice",
            "statis": "status",
            "chanels": "channels",
            "lightening": "lightning",
            "transferr": "transfer"
        }

    def parse_command(self, text: str, context: UserContext) -> ParsedCommand:
        """Parse natural language command"""
        # Normalize input
        text_lower = text.lower().strip()

        # Fix common typos
        for typo, correction in self.common_typos.items():
            text_lower = text_lower.replace(typo, correction)

        # Detect intent
        intent, confidence = self._detect_intent(text_lower)

        # Extract parameters
        parameters = self._extract_parameters(text_lower, intent)

        # Generate suggestions if confidence is low
        suggestions = []
        if confidence < 0.7:
            suggestions = self._generate_suggestions(text_lower, context)

        # Detect ambiguities
        ambiguities = self._detect_ambiguities(text_lower, intent)

        return ParsedCommand(
            original_text=text,
            intent=intent,
            confidence=confidence,
            parameters=parameters,
            suggestions=suggestions,
            ambiguities=ambiguities
        )

    def _detect_intent(self, text: str) -> Tuple[IntentType, float]:
        """Detect user intent from text"""
        scores = {}

        for intent, patterns in self.intent_patterns.items():
            score = 0
            for pattern in patterns:
                matches = len(re.findall(pattern, text, re.IGNORECASE))
                score += matches

            if score > 0:
                scores[intent] = score

        if not scores:
            return IntentType.UNKNOWN, 0.0

        # Find best match
        best_intent = max(scores, key=scores.get)
        max_score = scores[best_intent]

        # Calculate confidence based on score and text length
        confidence = min(max_score / (len(text.split()) + 1), 1.0)

        return best_intent, confidence

    def _extract_parameters(self, text: str, intent: IntentType) -> Dict[str, Any]:
        """Extract parameters from text based on intent"""
        parameters = {}

        # Extract amounts
        amount = self._extract_amount(text)
        if amount:
            parameters['amount'] = amount

        # Extract addresses/invoice
        if intent == IntentType.PAYMENT_SEND:
            invoice = self._extract_invoice(text)
            if invoice:
                parameters['invoice'] = invoice

        # Extract descriptors
        if intent == IntentType.INVOICE_CREATE:
            description = self._extract_description(text)
            if description:
                parameters['description'] = description

        return parameters

    def _extract_amount(self, text: str) -> Optional[int]:
        """Extract amount in satoshis"""
        for pattern in self.amount_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                try:
                    if len(match.groups()) == 2:
                        amount_str, unit = match.groups()
                        amount = float(amount_str)

                        # Convert to satoshis
                        if unit.lower() in ['btc', 'bitcoin']:
                            return int(amount * 100_000_000)
                        elif unit.lower() in ['sats', 'sat', 'satoshi', 'satoshis']:
                            return int(amount)
                        elif unit.lower() in ['msat', 'millisat']:
                            return int(amount / 1000)
                    else:
                        # Dollar amount (assume $1 = 2000 sats for demo)
                        amount = float(match.group(1))
                        return int(amount * 2000)

                except ValueError:
                    continue

        return None

    def _extract_invoice(self, text: str) -> Optional[str]:
        """Extract Lightning invoice from text"""
        # Look for Lightning invoice pattern
        invoice_pattern = r'\b(lnbc\w+)\b'
        match = re.search(invoice_pattern, text, re.IGNORECASE)
        if match:
            return match.group(1)
        return None

    def _extract_description(self, text: str) -> Optional[str]:
        """Extract description from text"""
        # Look for quoted strings or "for" clauses
        patterns = [
            r'"([^"]+)"',
            r"'([^']+)'",
            r'\bfor\s+(.+?)(?:\s+\d+|\s*$)',
            r'\bdescription[:\s]+(.+?)(?:\s+\d+|\s*$)'
        ]

        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1).strip()

        return None

    def _generate_suggestions(self, text: str, context: UserContext) -> List[str]:
        """Generate command suggestions"""
        suggestions = []

        # Find closest matching commands
        common_commands = [
            "check balance", "send payment", "create invoice",
            "show status", "help", "list channels", "payment history"
        ]

        # Use fuzzy matching
        close_matches = difflib.get_close_matches(text, common_commands, n=3, cutoff=0.3)
        suggestions.extend(close_matches)

        # Add contextual suggestions based on UX level
        if context.ux_level == UXLevel.BEGINNER:
            suggestions.extend([
                "Type 'help' for guidance",
                "Try 'check balance' to see your funds",
                "Say 'what can I do?' for options"
            ])

        return suggestions[:5]  # Limit to 5 suggestions

    def _detect_ambiguities(self, text: str, intent: IntentType) -> List[str]:
        """Detect ambiguous elements in command"""
        ambiguities = []

        # Check for multiple amounts
        amount_matches = []
        for pattern in self.amount_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            amount_matches.extend(matches)

        if len(amount_matches) > 1:
            ambiguities.append("Multiple amounts found - which one did you mean?")

        # Check for ambiguous pronouns
        if re.search(r'\b(it|that|this|them)\b', text) and intent != IntentType.HELP_REQUEST:
            ambiguities.append("What does 'it' refer to?")

        return ambiguities


class ConversationalInterface:
    """Conversational interface for Lightning operations"""

    def __init__(self):
        self.nlp = NaturalLanguageProcessor()
        self.user_contexts = {}
        self.conversation_history = {}

    def get_user_context(self, user_id: str) -> UserContext:
        """Get or create user context"""
        if user_id not in self.user_contexts:
            self.user_contexts[user_id] = UserContext(user_id=user_id)
        return self.user_contexts[user_id]

    async def process_message(self, user_id: str, message: str) -> Dict[str, Any]:
        """Process user message and return response"""
        context = self.get_user_context(user_id)

        # Parse command
        parsed = self.nlp.parse_command(message, context)

        # Update conversation history
        if user_id not in self.conversation_history:
            self.conversation_history[user_id] = []

        self.conversation_history[user_id].append({
            'timestamp': datetime.now(),
            'user_message': message,
            'parsed_intent': parsed.intent.value,
            'confidence': parsed.confidence
        })

        # Execute command
        response = await self._execute_command(parsed, context)

        # Update user context
        context.last_commands.append(message)
        if response.get('success', False):
            context.success_count += 1
        else:
            context.error_count += 1

        return response

    async def _execute_command(self, parsed: ParsedCommand, context: UserContext) -> Dict[str, Any]:
        """Execute parsed command"""
        try:
            if parsed.intent == IntentType.BALANCE_INQUIRY:
                return await self._handle_balance_inquiry(parsed, context)
            elif parsed.intent == IntentType.PAYMENT_SEND:
                return await self._handle_payment_send(parsed, context)
            elif parsed.intent == IntentType.INVOICE_CREATE:
                return await self._handle_invoice_create(parsed, context)
            elif parsed.intent == IntentType.STATUS_CHECK:
                return await self._handle_status_check(parsed, context)
            elif parsed.intent == IntentType.HELP_REQUEST:
                return await self._handle_help_request(parsed, context)
            elif parsed.intent == IntentType.CHANNEL_MANAGE:
                return await self._handle_channel_manage(parsed, context)
            elif parsed.intent == IntentType.TRANSACTION_HISTORY:
                return await self._handle_transaction_history(parsed, context)
            else:
                return await self._handle_unknown_command(parsed, context)

        except Exception as e:
            logger.error(f"Error executing command: {e}")
            return {
                'success': False,
                'message': self._format_error_message(str(e), context),
                'error': str(e)
            }

    async def _handle_balance_inquiry(self, parsed: ParsedCommand, context: UserContext) -> Dict[str, Any]:
        """Handle balance inquiry"""
        # Simulate balance check
        balance_sats = 150000  # Demo balance

        if context.ux_level == UXLevel.BEGINNER:
            message = f"💰 You have {balance_sats:,} sats in your Lightning wallet!\n"
            message += f"That's about ${balance_sats / 2000:.2f} USD."
        else:
            message = f"Balance: {balance_sats:,} sats"

        return {
            'success': True,
            'message': message,
            'data': {'balance_sats': balance_sats}
        }

    async def _handle_payment_send(self, parsed: ParsedCommand, context: UserContext) -> Dict[str, Any]:
        """Handle payment sending"""
        amount = parsed.parameters.get('amount')
        invoice = parsed.parameters.get('invoice')

        if not amount and not invoice:
            return {
                'success': False,
                'message': "💡 I need either an amount or a Lightning invoice to send a payment. Try: 'send 1000 sats' or paste a Lightning invoice."
            }

        if amount and not invoice:
            return {
                'success': False,
                'message': f"💡 I see you want to send {amount} sats! Please provide a Lightning invoice or destination."
            }

        # Simulate payment
        payment_hash = "abc123def456"

        if context.ux_level == UXLevel.BEGINNER:
            message = f"✅ Payment sent successfully!\n"
            message += f"Amount: {amount or 'invoice amount'} sats\n"
            message += f"Payment ID: {payment_hash}"
        else:
            message = f"Payment successful: {payment_hash}"

        return {
            'success': True,
            'message': message,
            'data': {'payment_hash': payment_hash, 'amount': amount}
        }

    async def _handle_invoice_create(self, parsed: ParsedCommand, context: UserContext) -> Dict[str, Any]:
        """Handle invoice creation"""
        amount = parsed.parameters.get('amount', 1000)
        description = parsed.parameters.get('description', 'Lightning payment')

        # Generate mock invoice
        invoice = f"lnbc{amount}u1p..."

        if context.ux_level == UXLevel.BEGINNER:
            message = f"📄 Invoice created!\n"
            message += f"Amount: {amount} sats\n"
            message += f"Description: {description}\n"
            message += f"Invoice: {invoice}\n\n"
            message += "💡 Share this invoice with the person who will pay you!"
        else:
            message = f"Invoice: {invoice}"

        return {
            'success': True,
            'message': message,
            'data': {'invoice': invoice, 'amount': amount, 'description': description}
        }

    async def _handle_status_check(self, parsed: ParsedCommand, context: UserContext) -> Dict[str, Any]:
        """Handle status check"""
        # Simulate status check
        status = {
            'node_online': True,
            'channels_active': 5,
            'channels_total': 6,
            'sync_status': 'synced'
        }

        if context.ux_level == UXLevel.BEGINNER:
            message = "🟢 Everything looks good!\n"
            message += f"• Your Lightning node is online\n"
            message += f"• {status['channels_active']} of {status['channels_total']} channels are active\n"
            message += f"• Your node is synced with the network"
        else:
            message = f"Status: Online | Channels: {status['channels_active']}/{status['channels_total']} | Sync: {status['sync_status']}"

        return {
            'success': True,
            'message': message,
            'data': status
        }

    async def _handle_help_request(self, parsed: ParsedCommand, context: UserContext) -> Dict[str, Any]:
        """Handle help request"""
        if context.ux_level == UXLevel.BEGINNER:
            message = "🤖 Welcome to Lightning! Here's what you can do:\n\n"
            message += "💰 Check your balance: 'check balance'\n"
            message += "💸 Send money: 'send 1000 sats' + Lightning invoice\n"
            message += "📄 Request payment: 'create invoice for 5000 sats'\n"
            message += "📊 Check status: 'how is everything?'\n"
            message += "📜 See history: 'show my payments'\n\n"
            message += "💡 Just type naturally - I understand plain English!"
        else:
            message = "Available commands: balance, send, invoice, status, channels, history"

        return {
            'success': True,
            'message': message
        }

    async def _handle_channel_manage(self, parsed: ParsedCommand, context: UserContext) -> Dict[str, Any]:
        """Handle channel management"""
        # Simulate channel list
        channels = [
            {'id': 'chan_1', 'capacity': 1000000, 'status': 'active'},
            {'id': 'chan_2', 'capacity': 500000, 'status': 'active'},
            {'id': 'chan_3', 'capacity': 2000000, 'status': 'pending'}
        ]

        if context.ux_level == UXLevel.BEGINNER:
            message = "⚡ Your Lightning Channels:\n\n"
            for i, channel in enumerate(channels, 1):
                status_emoji = "🟢" if channel['status'] == 'active' else "🟡"
                capacity_btc = channel['capacity'] / 100_000_000
                message += f"{status_emoji} Channel {i}: {capacity_btc:.3f} BTC capacity\n"
        else:
            message = "Channels:\n" + "\n".join([
                f"ID: {c['id']}, Capacity: {c['capacity']}, Status: {c['status']}"
                for c in channels
            ])

        return {
            'success': True,
            'message': message,
            'data': {'channels': channels}
        }

    async def _handle_transaction_history(self, parsed: ParsedCommand, context: UserContext) -> Dict[str, Any]:
        """Handle transaction history"""
        # Simulate transaction history
        transactions = [
            {'type': 'sent', 'amount': 5000, 'time': '2 hours ago'},
            {'type': 'received', 'amount': 10000, 'time': '1 day ago'},
            {'type': 'sent', 'amount': 2500, 'time': '3 days ago'}
        ]

        if context.ux_level == UXLevel.BEGINNER:
            message = "📜 Your Recent Payments:\n\n"
            for tx in transactions:
                emoji = "📤" if tx['type'] == 'sent' else "📥"
                action = "Sent" if tx['type'] == 'sent' else "Received"
                message += f"{emoji} {action} {tx['amount']:,} sats - {tx['time']}\n"
        else:
            message = "Transaction History:\n" + "\n".join([
                f"{tx['type'].upper()}: {tx['amount']} sats ({tx['time']})"
                for tx in transactions
            ])

        return {
            'success': True,
            'message': message,
            'data': {'transactions': transactions}
        }

    async def _handle_unknown_command(self, parsed: ParsedCommand, context: UserContext) -> Dict[str, Any]:
        """Handle unknown command"""
        message = "🤔 I'm not sure what you want to do. "

        if parsed.suggestions:
            message += f"Did you mean:\n• " + "\n• ".join(parsed.suggestions)
        else:
            message += "Try saying something like:\n"
            message += "• 'check my balance'\n"
            message += "• 'send 1000 sats'\n"
            message += "• 'create an invoice'\n"
            message += "• 'help'"

        return {
            'success': False,
            'message': message,
            'suggestions': parsed.suggestions
        }

    def _format_error_message(self, error: str, context: UserContext) -> str:
        """Format error message based on user level"""
        if context.ux_level == UXLevel.BEGINNER:
            return f"😅 Oops! Something went wrong: {error}\n\nDon't worry - your funds are safe. Try again or type 'help' for assistance."
        else:
            return f"Error: {error}"

    def get_conversation_stats(self, user_id: str) -> Dict[str, Any]:
        """Get conversation statistics"""
        context = self.get_user_context(user_id)
        history = self.conversation_history.get(user_id, [])

        return {
            'user_level': context.ux_level.value,
            'total_commands': len(context.last_commands),
            'success_rate': context.success_count / max(context.success_count + context.error_count, 1),
            'session_duration': (datetime.now() - context.session_start).total_seconds(),
            'conversation_length': len(history),
            'most_common_intent': self._get_most_common_intent(history)
        }

    def _get_most_common_intent(self, history: List[Dict]) -> str:
        """Get most common user intent"""
        if not history:
            return "none"

        intents = [msg['parsed_intent'] for msg in history]
        return max(set(intents), key=intents.count)


# Global conversational interface
conversational_interface = ConversationalInterface()


def get_conversational_interface() -> ConversationalInterface:
    """Get global conversational interface"""
    return conversational_interface


# Quick command processor for CLI
def quick_command(text: str) -> str:
    """Process quick command and return simple response"""
    nlp = NaturalLanguageProcessor()
    context = UserContext(user_id="cli_user", ux_level=UXLevel.INTERMEDIATE)
    parsed = nlp.parse_command(text, context)

    if parsed.intent == IntentType.BALANCE_INQUIRY:
        return "Balance: 150,000 sats"
    elif parsed.intent == IntentType.STATUS_CHECK:
        return "Status: Online | Channels: 5/6 active"
    elif parsed.intent == IntentType.HELP_REQUEST:
        return "Commands: balance, status, send, invoice, help"
    else:
        return f"Intent: {parsed.intent.value} (confidence: {parsed.confidence:.2f})"