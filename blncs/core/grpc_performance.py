#!/usr/bin/env python3
"""
gRPC and Protocol Buffers Module
High-performance microservices communication
Based on 2024-2025 research on gRPC vs REST performance
"""

import logging
from typing import Dict, Any, Optional, List, Callable, TypeVar, Generic
from dataclasses import dataclass, field, asdict
from abc import ABC, abstractmethod
from enum import Enum
import struct
import zlib

logger = logging.getLogger(__name__)

T = TypeVar('T')


class CompressionType(Enum):
    """Compression algorithms for gRPC"""
    NONE = "none"
    GZIP = "gzip"
    DEFLATE = "deflate"


@dataclass
class GRPCMetadata:
    """gRPC message metadata"""
    message_id: str = ""
    timestamp: int = 0
    compression: CompressionType = CompressionType.NONE
    encoding: str = "utf-8"
    custom_metadata: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'message_id': self.message_id,
            'timestamp': self.timestamp,
            'compression': self.compression.value,
            'encoding': self.encoding,
            'custom_metadata': self.custom_metadata
        }


class ProtobufMessage(ABC):
    """
    Base class for Protocol Buffer messages
    Simulates protobuf serialization without actual protobuf dependency
    """

    @abstractmethod
    def serialize(self) -> bytes:
        """Serialize message to bytes"""
        pass

    @abstractmethod
    def deserialize(self, data: bytes) -> None:
        """Deserialize message from bytes"""
        pass

    @abstractmethod
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        pass

    def get_size(self) -> int:
        """Get serialized size"""
        return len(self.serialize())


class StreamMessage(ProtobufMessage):
    """
    Example Protocol Buffer message for streaming
    Demonstrates efficient binary serialization
    """

    def __init__(self, message_id: str = "", data: bytes = b"", sequence: int = 0):
        self.message_id = message_id
        self.data = data
        self.sequence = sequence

    def serialize(self) -> bytes:
        """Serialize using simple binary format"""
        # Field 1: message_id (variable length)
        msg_id_bytes = self.message_id.encode('utf-8')
        msg_id_len = len(msg_id_bytes)

        # Field 2: data (variable length)
        data_len = len(self.data)

        # Field 3: sequence (varint)
        seq_bytes = self._encode_varint(self.sequence)

        # Pack: [id_len][id_data][data_len][data][seq]
        return (
            struct.pack('>H', msg_id_len) + msg_id_bytes +
            struct.pack('>I', data_len) + self.data +
            seq_bytes
        )

    def deserialize(self, data: bytes) -> None:
        """Deserialize from bytes"""
        offset = 0

        # Read message_id
        msg_id_len = struct.unpack_from('>H', data, offset)[0]
        offset += 2
        self.message_id = data[offset:offset + msg_id_len].decode('utf-8')
        offset += msg_id_len

        # Read data
        data_len = struct.unpack_from('>I', data, offset)[0]
        offset += 4
        self.data = data[offset:offset + data_len]
        offset += data_len

        # Read sequence
        self.sequence, bytes_read = self._decode_varint(data[offset:])

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'message_id': self.message_id,
            'data': self.data.hex(),
            'sequence': self.sequence
        }

    @staticmethod
    def _encode_varint(value: int) -> bytes:
        """Encode integer as varint"""
        result = []
        while value > 127:
            result.append((value & 0x7f) | 0x80)
            value >>= 7
        result.append(value & 0x7f)
        return bytes(result)

    @staticmethod
    def _decode_varint(data: bytes) -> tuple:
        """Decode varint from bytes"""
        result = 0
        shift = 0
        for i, byte in enumerate(data):
            result |= (byte & 0x7f) << shift
            if not (byte & 0x80):
                return result, i + 1
            shift += 7
        return result, len(data)


class GRPCService(ABC, Generic[T]):
    """
    Base class for gRPC services
    Provides request/response handling with compression
    """

    def __init__(self, compression: CompressionType = CompressionType.GZIP):
        self.compression = compression
        self.request_count = 0
        self.bytes_sent = 0
        self.bytes_received = 0

    @abstractmethod
    async def handle_request(self, request: ProtobufMessage) -> ProtobufMessage:
        """Handle incoming request"""
        pass

    async def process_request(self, raw_request: bytes) -> bytes:
        """
        Process request with compression/decompression
        Simulates actual gRPC request handling
        """
        # Decompress if needed
        request_data = raw_request
        if self.compression == CompressionType.GZIP:
            request_data = zlib.decompress(raw_request)
        elif self.compression == CompressionType.DEFLATE:
            request_data = zlib.decompress(raw_request)

        self.bytes_received += len(raw_request)
        self.request_count += 1

        # Parse request (simplified)
        request = StreamMessage()
        request.deserialize(request_data)

        # Handle request
        response = await self.handle_request(request)

        # Serialize response
        response_data = response.serialize()

        # Compress if needed
        response_bytes = response_data
        if self.compression == CompressionType.GZIP:
            response_bytes = zlib.compress(response_data, level=6)
        elif self.compression == CompressionType.DEFLATE:
            response_bytes = zlib.compress(response_data, level=6)

        self.bytes_sent += len(response_bytes)
        return response_bytes

    def get_compression_ratio(self) -> float:
        """Get compression ratio"""
        if self.bytes_received == 0:
            return 0.0
        return (1 - self.bytes_sent / self.bytes_received) * 100

    def get_statistics(self) -> Dict[str, Any]:
        """Get service statistics"""
        return {
            'request_count': self.request_count,
            'bytes_received': self.bytes_received,
            'bytes_sent': self.bytes_sent,
            'compression_type': self.compression.value,
            'compression_ratio_percent': self.get_compression_ratio(),
            'avg_request_size': self.bytes_received / self.request_count if self.request_count > 0 else 0,
            'avg_response_size': self.bytes_sent / self.request_count if self.request_count > 0 else 0
        }


class UnaryService(GRPCService[StreamMessage]):
    """
    Unary gRPC service (single request/response)
    Optimized for latency-sensitive operations
    """

    async def handle_request(self, request: StreamMessage) -> StreamMessage:
        """Handle unary request"""
        logger.debug(f"Handling unary request: {request.message_id}")
        return StreamMessage(
            message_id=f"response_{request.message_id}",
            data=b"ACK",
            sequence=request.sequence + 1
        )


class StreamingService(GRPCService[StreamMessage]):
    """
    Streaming gRPC service (multiple requests/responses)
    Optimized for high-throughput scenarios
    """

    def __init__(self, compression: CompressionType = CompressionType.GZIP):
        super().__init__(compression)
        self.stream_buffers: Dict[str, List[StreamMessage]] = {}

    async def handle_stream(self, stream_id: str, messages: List[StreamMessage]) -> List[StreamMessage]:
        """Handle streaming messages"""
        if stream_id not in self.stream_buffers:
            self.stream_buffers[stream_id] = []

        responses = []
        for msg in messages:
            response = StreamMessage(
                message_id=f"response_{msg.message_id}",
                data=msg.data,
                sequence=msg.sequence + 1
            )
            responses.append(response)
            self.stream_buffers[stream_id].append(response)

        logger.debug(f"Processed {len(messages)} streaming messages")
        return responses

    async def handle_request(self, request: StreamMessage) -> StreamMessage:
        """Handle single request in stream"""
        return StreamMessage(
            message_id=f"response_{request.message_id}",
            data=request.data,
            sequence=request.sequence + 1
        )


class GRPCLoadBalancer:
    """
    Simple load balancer for gRPC service instances
    Distributes requests across multiple service replicas
    """

    def __init__(self):
        self.services: Dict[str, GRPCService] = {}
        self.request_counts: Dict[str, int] = {}
        self.total_requests = 0

    def register_service(self, service_id: str, service: GRPCService) -> None:
        """Register service instance"""
        self.services[service_id] = service
        self.request_counts[service_id] = 0
        logger.info(f"Registered service instance: {service_id}")

    def unregister_service(self, service_id: str) -> None:
        """Unregister service instance"""
        if service_id in self.services:
            del self.services[service_id]
            del self.request_counts[service_id]
            logger.info(f"Unregistered service instance: {service_id}")

    def get_least_loaded_service(self) -> Optional[str]:
        """Get service with least requests (round-robin based)"""
        if not self.services:
            return None

        # Find service with minimum requests
        min_service = min(self.request_counts.items(), key=lambda x: x[1])[0]
        return min_service

    async def route_request(self, request: bytes) -> bytes:
        """Route request to least loaded service"""
        service_id = self.get_least_loaded_service()
        if not service_id:
            raise RuntimeError("No services available")

        service = self.services[service_id]
        self.request_counts[service_id] += 1
        self.total_requests += 1

        response = await service.process_request(request)
        logger.debug(f"Routed request to {service_id}")
        return response

    def get_load_distribution(self) -> Dict[str, Any]:
        """Get load distribution across services"""
        return {
            'total_requests': self.total_requests,
            'service_loads': self.request_counts.copy(),
            'available_services': len(self.services)
        }


class ProtobufSchema:
    """
    Registry for Protocol Buffer schemas
    Manages message definitions and validation
    """

    def __init__(self):
        self.schemas: Dict[str, Dict[str, Any]] = {}

    def register_schema(self, name: str, schema: Dict[str, Any]) -> None:
        """Register a message schema"""
        self.schemas[name] = schema
        logger.debug(f"Registered schema: {name}")

    def validate_message(self, name: str, data: Dict[str, Any]) -> bool:
        """Validate message against schema"""
        if name not in self.schemas:
            logger.warning(f"Unknown schema: {name}")
            return False

        schema = self.schemas[name]
        # Simple validation: check required fields
        required_fields = schema.get('required_fields', [])
        return all(field in data for field in required_fields)

    def get_schema(self, name: str) -> Optional[Dict[str, Any]]:
        """Get schema definition"""
        return self.schemas.get(name)


__all__ = [
    'CompressionType',
    'GRPCMetadata',
    'ProtobufMessage',
    'StreamMessage',
    'GRPCService',
    'UnaryService',
    'StreamingService',
    'GRPCLoadBalancer',
    'ProtobufSchema',
]
