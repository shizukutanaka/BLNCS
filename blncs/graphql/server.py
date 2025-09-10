#!/usr/bin/env python3
"""
GraphQL Server with Subscription Support for BLNCS
Implements comprehensive GraphQL API for Lightning Network operations with real-time subscriptions
"""

import asyncio
import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, AsyncGenerator, Callable, Union
import logging
from datetime import datetime

# GraphQL imports (would be installed via pip install graphene graphql-core)
try:
    import graphene
    from graphene import ObjectType, String, Int, Float, Boolean, List as GList, Field, Argument
    from graphene import Schema, Mutation, Subscription
    from graphql.execution.executors.asyncio import AsyncioExecutor
    from graphql import GraphQLError
    HAS_GRAPHQL = True
except ImportError:
    # Fallback implementation without graphene
    HAS_GRAPHQL = False
    logger = logging.getLogger(__name__)
    logger.warning("GraphQL dependencies not available. Using mock implementation.")

from blncs.core.async_memory_manager import track_async_task, lightning_operation_context
from blncs.core.exceptions import BLNCSError, LightningError
from blncs.lightning.async_safe_client import AsyncSafeLightningClient
from blncs.websocket.realtime_manager import RealTimeManager, MessageType

logger = logging.getLogger(__name__)

# GraphQL Schema Definitions
if HAS_GRAPHQL:
    
    # Scalar Types
    class DateTime(graphene.Scalar):
        """DateTime scalar type"""
        
        @staticmethod
        def serialize(dt):
            if isinstance(dt, datetime):
                return dt.isoformat()
            return dt
        
        @staticmethod
        def parse_literal(node):
            if isinstance(node.value, str):
                return datetime.fromisoformat(node.value)
            return None
        
        @staticmethod
        def parse_value(value):
            if isinstance(value, str):
                return datetime.fromisoformat(value)
            return value
    
    # Object Types
    class NodeInfo(ObjectType):
        """Lightning node information"""
        alias = String()
        identity_pubkey = String()
        network = String()
        version = String()
        num_channels = Int()
        num_peers = Int()
        block_height = Int()
        synced_to_chain = Boolean()
        synced_to_graph = Boolean()
    
    class Balance(ObjectType):
        """Node balance information"""
        total = Int(description="Total balance in satoshis")
        confirmed = Int(description="Confirmed balance in satoshis")
        unconfirmed = Int(description="Unconfirmed balance in satoshis")
        channel_local = Int(description="Local channel balance in satoshis")
        channel_remote = Int(description="Remote channel balance in satoshis")
    
    class Channel(ObjectType):
        """Lightning Network channel"""
        channel_id = String()
        capacity = Int(description="Channel capacity in satoshis")
        local_balance = Int(description="Local balance in satoshis")
        remote_balance = Int(description="Remote balance in satoshis")
        active = Boolean()
        remote_pubkey = String()
        private = Boolean()
        fee_base_msat = Int()
        fee_proportional_millionths = Int()
    
    class Payment(ObjectType):
        """Lightning Network payment"""
        payment_hash = String()
        amount = Int(description="Payment amount in satoshis")
        timestamp = DateTime()
        status = String()
        fee = Int(description="Payment fee in satoshis")
        destination = String()
        memo = String()
    
    class Invoice(ObjectType):
        """Lightning Network invoice"""
        payment_request = String()
        payment_hash = String()
        amount = Int(description="Invoice amount in satoshis")
        description = String()
        expiry = Int()
        settled = Boolean()
        settled_at = DateTime()
        created_at = DateTime()
    
    class MultiPathPayment(ObjectType):
        """Multi-path payment information"""
        payment_id = String()
        total_amount = Int()
        paid_amount = Int()
        total_fee = Int()
        status = String()
        path_count = Int()
        successful_paths = Int()
        created_at = DateTime()
        completed_at = DateTime()
    
    class PaymentPath(ObjectType):
        """Individual payment path"""
        path_id = String()
        amount = Int()
        probability = Float()
        expected_fee = Int()
        status = String()
        attempt_count = Int()
        failure_reason = String()
    
    class HealthStatus(ObjectType):
        """System health status"""
        status = String()
        uptime = Float()
        memory_usage = Float()
        cpu_usage = Float()
        disk_usage = Float()
        database_connected = Boolean()
        lightning_connected = Boolean()
        last_check = DateTime()
    
    class SystemStats(ObjectType):
        """System statistics"""
        total_payments_sent = Int()
        total_payments_received = Int()
        total_invoices_created = Int()
        total_channels = Int()
        total_capacity = Int()
        success_rate = Float()
        average_fee_rate = Float()
    
    # Input Types
    class PaymentInput(graphene.InputObjectType):
        """Payment input parameters"""
        payment_request = String(required=True)
        timeout_seconds = Int(default_value=60)
        max_fee_msat = Int()
        use_multipath = Boolean(default_value=False)
    
    class InvoiceInput(graphene.InputObjectType):
        """Invoice creation input parameters"""
        amount = Int(required=True, description="Invoice amount in satoshis")
        memo = String(default_value="")
        expiry = Int(default_value=3600)
    
    class ChannelInput(graphene.InputObjectType):
        """Channel opening input parameters"""
        node_pubkey = String(required=True)
        local_funding_amount = Int(required=True)
        push_sat = Int(default_value=0)
        private = Boolean(default_value=False)
    
    # Subscription Events
    class PaymentReceived(ObjectType):
        """Payment received event"""
        payment = Field(Payment)
        timestamp = DateTime()
    
    class PaymentSent(ObjectType):
        """Payment sent event"""
        payment = Field(Payment)
        timestamp = DateTime()
    
    class InvoiceSettled(ObjectType):
        """Invoice settled event"""
        invoice = Field(Invoice)
        timestamp = DateTime()
    
    class ChannelUpdate(ObjectType):
        """Channel update event"""
        channel = Field(Channel)
        update_type = String()  # opened, closed, updated
        timestamp = DateTime()
    
    class SystemAlert(ObjectType):
        """System alert event"""
        level = String()  # info, warning, error, critical
        message = String()
        component = String()
        timestamp = DateTime()

else:
    # Mock classes when GraphQL is not available
    class ObjectType:
        pass
    
    class Mutation:
        pass
    
    class Subscription:
        pass
    
    # Create mock versions of all GraphQL types
    NodeInfo = Balance = Channel = Payment = Invoice = ObjectType
    MultiPathPayment = PaymentPath = HealthStatus = SystemStats = ObjectType
    PaymentReceived = PaymentSent = InvoiceSettled = ChannelUpdate = SystemAlert = ObjectType

class GraphQLContext:
    """GraphQL execution context"""
    
    def __init__(self, lightning_client: Optional[AsyncSafeLightningClient] = None,
                 realtime_manager: Optional[RealTimeManager] = None,
                 user_id: Optional[str] = None,
                 permissions: List[str] = None):
        self.lightning_client = lightning_client
        self.realtime_manager = realtime_manager
        self.user_id = user_id
        self.permissions = permissions or []
        self.request_id = str(uuid.uuid4())

class PermissionError(GraphQLError):
    """GraphQL permission error"""
    pass

def require_permission(permission: str):
    """Decorator to require specific permission"""
    def decorator(func):
        async def wrapper(self, info, **kwargs):
            context = info.context
            if not context or permission not in context.permissions:
                raise PermissionError(f"Permission required: {permission}")
            return await func(self, info, **kwargs)
        return wrapper
    return decorator

if HAS_GRAPHQL:
    
    # Query Root
    class Query(ObjectType):
        """GraphQL Query root"""
        
        # Node information
        node_info = Field(NodeInfo, description="Get Lightning node information")
        balance = Field(Balance, description="Get node balance")
        
        # Channel operations
        channels = GList(Channel, description="List all channels")
        channel = Field(Channel, channel_id=String(required=True), description="Get specific channel")
        
        # Payment operations
        payments = GList(Payment, 
                        limit=Int(default_value=100),
                        offset=Int(default_value=0),
                        description="List payments")
        payment = Field(Payment, payment_hash=String(required=True), description="Get specific payment")
        
        # Invoice operations
        invoices = GList(Invoice,
                        limit=Int(default_value=100), 
                        offset=Int(default_value=0),
                        description="List invoices")
        invoice = Field(Invoice, payment_hash=String(required=True), description="Get specific invoice")
        
        # Multi-path payments
        multipath_payments = GList(MultiPathPayment, description="List multi-path payments")
        multipath_payment = Field(MultiPathPayment, payment_id=String(required=True), 
                                description="Get specific multi-path payment")
        
        # System information
        health = Field(HealthStatus, description="Get system health status")
        stats = Field(SystemStats, description="Get system statistics")
        
        @track_async_task("graphql_node_info")
        async def resolve_node_info(self, info):
            """Resolve node information"""
            context = info.context
            if not context.lightning_client:
                raise GraphQLError("Lightning client not available")
            
            try:
                node_info = await context.lightning_client.get_info()
                return NodeInfo(
                    alias=node_info.get('alias'),
                    identity_pubkey=node_info.get('identity_pubkey'),
                    network=node_info.get('network'),
                    version=node_info.get('version'),
                    num_channels=node_info.get('num_channels'),
                    num_peers=node_info.get('num_peers'),
                    block_height=node_info.get('block_height'),
                    synced_to_chain=node_info.get('synced_to_chain'),
                    synced_to_graph=node_info.get('synced_to_graph')
                )
            except Exception as e:
                raise GraphQLError(f"Failed to get node info: {e}")
        
        @track_async_task("graphql_balance")
        async def resolve_balance(self, info):
            """Resolve node balance"""
            context = info.context
            if not context.lightning_client:
                raise GraphQLError("Lightning client not available")
            
            try:
                balance_info = await context.lightning_client.get_balance()
                return Balance(
                    total=balance_info.get('total'),
                    confirmed=balance_info.get('confirmed'),
                    unconfirmed=balance_info.get('unconfirmed'),
                    channel_local=balance_info.get('channel_local'),
                    channel_remote=balance_info.get('channel_remote')
                )
            except Exception as e:
                raise GraphQLError(f"Failed to get balance: {e}")
        
        @track_async_task("graphql_channels")
        async def resolve_channels(self, info):
            """Resolve channels list"""
            context = info.context
            if not context.lightning_client:
                raise GraphQLError("Lightning client not available")
            
            try:
                channels_data = await context.lightning_client.list_channels()
                return [
                    Channel(
                        channel_id=ch.get('channel_id'),
                        capacity=ch.get('capacity'),
                        local_balance=ch.get('local_balance'),
                        remote_balance=ch.get('remote_balance'),
                        active=ch.get('active'),
                        remote_pubkey=ch.get('remote_pubkey'),
                        private=ch.get('private')
                    )
                    for ch in channels_data
                ]
            except Exception as e:
                raise GraphQLError(f"Failed to get channels: {e}")
        
        @track_async_task("graphql_channel")
        async def resolve_channel(self, info, channel_id):
            """Resolve specific channel"""
            context = info.context
            if not context.lightning_client:
                raise GraphQLError("Lightning client not available")
            
            try:
                channels_data = await context.lightning_client.list_channels()
                channel_data = next((ch for ch in channels_data if ch.get('channel_id') == channel_id), None)
                
                if not channel_data:
                    raise GraphQLError(f"Channel not found: {channel_id}")
                
                return Channel(
                    channel_id=channel_data.get('channel_id'),
                    capacity=channel_data.get('capacity'),
                    local_balance=channel_data.get('local_balance'),
                    remote_balance=channel_data.get('remote_balance'),
                    active=channel_data.get('active'),
                    remote_pubkey=channel_data.get('remote_pubkey'),
                    private=channel_data.get('private')
                )
            except Exception as e:
                raise GraphQLError(f"Failed to get channel: {e}")
        
        @track_async_task("graphql_health")
        @require_permission("system.read")
        async def resolve_health(self, info):
            """Resolve system health status"""
            try:
                # Mock health data - would integrate with actual health checker
                return HealthStatus(
                    status="healthy",
                    uptime=time.time(),
                    memory_usage=45.2,
                    cpu_usage=12.5,
                    disk_usage=67.8,
                    database_connected=True,
                    lightning_connected=True,
                    last_check=datetime.now()
                )
            except Exception as e:
                raise GraphQLError(f"Failed to get health status: {e}")
        
        @track_async_task("graphql_stats")
        @require_permission("system.read")
        async def resolve_stats(self, info):
            """Resolve system statistics"""
            try:
                # Mock statistics - would integrate with actual metrics
                return SystemStats(
                    total_payments_sent=1250,
                    total_payments_received=890,
                    total_invoices_created=2140,
                    total_channels=25,
                    total_capacity=15000000,  # satoshis
                    success_rate=0.982,
                    average_fee_rate=0.001
                )
            except Exception as e:
                raise GraphQLError(f"Failed to get statistics: {e}")
    
    # Mutation Root
    class Mutation(ObjectType):
        """GraphQL Mutation root"""
        
        # Payment operations
        send_payment = Field(Payment, input=PaymentInput(required=True))
        
        # Invoice operations
        create_invoice = Field(Invoice, input=InvoiceInput(required=True))
        
        # Channel operations
        open_channel = Field(Channel, input=ChannelInput(required=True))
        close_channel = Field(Boolean, channel_id=String(required=True), force=Boolean(default_value=False))
        
        @track_async_task("graphql_send_payment")
        @require_permission("payment.send")
        async def resolve_send_payment(self, info, input):
            """Send Lightning Network payment"""
            context = info.context
            if not context.lightning_client:
                raise GraphQLError("Lightning client not available")
            
            try:
                payment_result = await context.lightning_client.send_payment(
                    input.payment_request,
                    timeout=input.timeout_seconds
                )
                
                # Broadcast payment event
                if context.realtime_manager:
                    await context.realtime_manager.broadcast_payment_sent({
                        'payment_hash': payment_result.get('payment_hash'),
                        'amount': payment_result.get('amount'),
                        'fee': payment_result.get('fee'),
                        'status': payment_result.get('status'),
                        'user_id': context.user_id
                    })
                
                return Payment(
                    payment_hash=payment_result.get('payment_hash'),
                    amount=payment_result.get('amount'),
                    status=payment_result.get('status'),
                    fee=payment_result.get('fee'),
                    timestamp=datetime.now()
                )
                
            except Exception as e:
                raise GraphQLError(f"Failed to send payment: {e}")
        
        @track_async_task("graphql_create_invoice")
        @require_permission("invoice.create")
        async def resolve_create_invoice(self, info, input):
            """Create Lightning Network invoice"""
            context = info.context
            if not context.lightning_client:
                raise GraphQLError("Lightning client not available")
            
            try:
                invoice_result = await context.lightning_client.create_invoice(
                    input.amount,
                    input.memo
                )
                
                # Broadcast invoice creation event
                if context.realtime_manager:
                    await context.realtime_manager.broadcast_invoice_created({
                        'payment_request': invoice_result,
                        'amount': input.amount,
                        'memo': input.memo,
                        'user_id': context.user_id
                    })
                
                return Invoice(
                    payment_request=invoice_result,
                    amount=input.amount,
                    description=input.memo,
                    expiry=input.expiry,
                    settled=False,
                    created_at=datetime.now()
                )
                
            except Exception as e:
                raise GraphQLError(f"Failed to create invoice: {e}")
    
    # Subscription Root
    class Subscription(ObjectType):
        """GraphQL Subscription root"""
        
        # Payment subscriptions
        payment_received = Field(PaymentReceived, description="Subscribe to payment received events")
        payment_sent = Field(PaymentSent, description="Subscribe to payment sent events")
        
        # Invoice subscriptions
        invoice_settled = Field(InvoiceSettled, description="Subscribe to invoice settled events")
        
        # Channel subscriptions
        channel_updates = Field(ChannelUpdate, description="Subscribe to channel updates")
        
        # System subscriptions
        system_alerts = Field(SystemAlert, level=String(), description="Subscribe to system alerts")
        
        async def resolve_payment_received(self, info):
            """Subscribe to payment received events"""
            context = info.context
            if not context.realtime_manager:
                raise GraphQLError("Real-time manager not available")
            
            # Create async generator for payment events
            async def payment_stream():
                # This would integrate with the WebSocket manager
                # For demo, yield mock events
                while True:
                    await asyncio.sleep(10)  # Wait 10 seconds between events
                    
                    # Mock payment received event
                    yield PaymentReceived(
                        payment=Payment(
                            payment_hash=str(uuid.uuid4()),
                            amount=100000,  # 1000 sats
                            status="settled",
                            timestamp=datetime.now()
                        ),
                        timestamp=datetime.now()
                    )
            
            return payment_stream()
        
        async def resolve_system_alerts(self, info, level=None):
            """Subscribe to system alerts"""
            context = info.context
            if not context.realtime_manager:
                raise GraphQLError("Real-time manager not available")
            
            async def alert_stream():
                while True:
                    await asyncio.sleep(30)  # Wait 30 seconds between alerts
                    
                    yield SystemAlert(
                        level="info",
                        message="System health check completed",
                        component="health_monitor",
                        timestamp=datetime.now()
                    )
            
            return alert_stream()

else:
    # Mock implementations when GraphQL is not available
    class Query:
        pass
    
    class Mutation:
        pass
    
    class Subscription:
        pass

class GraphQLServer:
    """GraphQL server with subscription support"""
    
    def __init__(self, lightning_client: Optional[AsyncSafeLightningClient] = None,
                 realtime_manager: Optional[RealTimeManager] = None):
        self.lightning_client = lightning_client
        self.realtime_manager = realtime_manager
        
        if HAS_GRAPHQL:
            # Create GraphQL schema
            self.schema = Schema(
                query=Query,
                mutation=Mutation,
                subscription=Subscription
            )
        else:
            self.schema = None
            logger.warning("GraphQL schema not available - using mock implementation")
        
        # Statistics
        self.stats = {
            'queries_executed': 0,
            'mutations_executed': 0,
            'subscriptions_active': 0,
            'errors': 0
        }
    
    @track_async_task("execute_graphql_query")
    async def execute_query(self, query: str, variables: Optional[Dict[str, Any]] = None,
                           user_id: Optional[str] = None, permissions: List[str] = None) -> Dict[str, Any]:
        """Execute GraphQL query"""
        if not HAS_GRAPHQL or not self.schema:
            return {
                'errors': [{'message': 'GraphQL not available'}]
            }
        
        async with lightning_operation_context("graphql_query"):
            try:
                # Create context
                context = GraphQLContext(
                    lightning_client=self.lightning_client,
                    realtime_manager=self.realtime_manager,
                    user_id=user_id,
                    permissions=permissions or []
                )
                
                # Execute query
                result = await self.schema.execute_async(
                    query,
                    variables=variables,
                    context=context,
                    executor=AsyncioExecutor()
                )
                
                # Update statistics
                if 'mutation' in query.lower():
                    self.stats['mutations_executed'] += 1
                else:
                    self.stats['queries_executed'] += 1
                
                # Format result
                response = {}
                
                if result.data:
                    response['data'] = result.data
                
                if result.errors:
                    response['errors'] = [
                        {'message': str(error), 'path': getattr(error, 'path', None)}
                        for error in result.errors
                    ]
                    self.stats['errors'] += 1
                
                return response
                
            except Exception as e:
                self.stats['errors'] += 1
                logger.error(f"GraphQL execution error: {e}")
                return {
                    'errors': [{'message': f'Execution error: {e}'}]
                }
    
    async def execute_subscription(self, query: str, variables: Optional[Dict[str, Any]] = None,
                                 user_id: Optional[str] = None, permissions: List[str] = None) -> AsyncGenerator[Dict[str, Any], None]:
        """Execute GraphQL subscription"""
        if not HAS_GRAPHQL or not self.schema:
            yield {'errors': [{'message': 'GraphQL subscriptions not available'}]}
            return
        
        try:
            # Create context
            context = GraphQLContext(
                lightning_client=self.lightning_client,
                realtime_manager=self.realtime_manager,
                user_id=user_id,
                permissions=permissions or []
            )
            
            # Execute subscription
            result = await self.schema.execute_async(
                query,
                variables=variables,
                context=context,
                executor=AsyncioExecutor()
            )
            
            if result.errors:
                yield {
                    'errors': [
                        {'message': str(error), 'path': getattr(error, 'path', None)}
                        for error in result.errors
                    ]
                }
                return
            
            self.stats['subscriptions_active'] += 1
            
            try:
                # Stream subscription results
                async for subscription_result in result.data:
                    yield {'data': subscription_result}
                    
            finally:
                self.stats['subscriptions_active'] -= 1
                
        except Exception as e:
            logger.error(f"GraphQL subscription error: {e}")
            yield {'errors': [{'message': f'Subscription error: {e}'}]}
    
    def get_schema_definition(self) -> str:
        """Get GraphQL schema definition (SDL)"""
        if not HAS_GRAPHQL or not self.schema:
            return "# GraphQL schema not available"
        
        try:
            from graphql import print_schema
            return print_schema(self.schema.graphql_schema)
        except ImportError:
            return "# Schema printing not available"
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get GraphQL server statistics"""
        return {
            **self.stats,
            'schema_available': HAS_GRAPHQL and self.schema is not None,
            'lightning_client_available': self.lightning_client is not None,
            'realtime_manager_available': self.realtime_manager is not None
        }

# Factory function
async def create_graphql_server(lightning_client: Optional[AsyncSafeLightningClient] = None,
                               realtime_manager: Optional[RealTimeManager] = None) -> GraphQLServer:
    """Create GraphQL server"""
    server = GraphQLServer(lightning_client, realtime_manager)
    
    if HAS_GRAPHQL:
        logger.info("Created GraphQL server with full schema support")
    else:
        logger.warning("Created GraphQL server with mock implementation (install graphene for full support)")
    
    return server

# Example queries for documentation
EXAMPLE_QUERIES = {
    "node_info": """
    query GetNodeInfo {
        nodeInfo {
            alias
            identityPubkey
            network
            version
            numChannels
            numPeers
        }
    }
    """,
    
    "balance": """
    query GetBalance {
        balance {
            total
            confirmed
            channelLocal
            channelRemote
        }
    }
    """,
    
    "channels": """
    query ListChannels {
        channels {
            channelId
            capacity
            localBalance
            remoteBalance
            active
            remotePubkey
        }
    }
    """,
    
    "send_payment": """
    mutation SendPayment($input: PaymentInput!) {
        sendPayment(input: $input) {
            paymentHash
            amount
            status
            fee
            timestamp
        }
    }
    """,
    
    "create_invoice": """
    mutation CreateInvoice($input: InvoiceInput!) {
        createInvoice(input: $input) {
            paymentRequest
            amount
            description
            createdAt
        }
    }
    """,
    
    "payment_subscription": """
    subscription PaymentUpdates {
        paymentReceived {
            payment {
                paymentHash
                amount
                status
            }
            timestamp
        }
    }
    """
}

# Export main classes and functions
__all__ = [
    'GraphQLContext',
    'GraphQLServer',
    'create_graphql_server',
    'EXAMPLE_QUERIES',
    'HAS_GRAPHQL'
]