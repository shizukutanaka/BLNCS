#!/usr/bin/env python3
"""
Saga Pattern for Distributed Transactions
Implements distributed transaction management across microservices
Based on 2024-2025 research on microservices transaction patterns
"""

import logging
import uuid
from typing import Dict, List, Optional, Callable, Awaitable, Any
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class SagaState(Enum):
    """Saga execution state"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    COMPENSATING = "compensating"
    FAILED = "failed"


class StepStatus(Enum):
    """Individual step status"""
    PENDING = "pending"
    EXECUTING = "executing"
    COMPLETED = "completed"
    COMPENSATING = "compensating"
    COMPENSATED = "compensated"
    FAILED = "failed"


@dataclass
class SagaStep:
    """Represents a step in a saga"""
    name: str
    action: Callable[..., Awaitable[Any]]
    compensation: Callable[..., Awaitable[None]]
    timeout_seconds: int = 30
    retry_count: int = 3
    status: StepStatus = StepStatus.PENDING
    result: Optional[Any] = None
    error: Optional[str] = None
    executed_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    async def execute(self, context: Dict[str, Any]) -> Any:
        """Execute step with retry logic"""
        self.status = StepStatus.EXECUTING
        attempt = 0

        while attempt < self.retry_count:
            try:
                logger.info(f"Executing step '{self.name}' (attempt {attempt + 1}/{self.retry_count})")
                self.result = await self.action(**context)
                self.status = StepStatus.COMPLETED
                self.executed_at = datetime.utcnow()
                self.completed_at = datetime.utcnow()
                logger.info(f"Step '{self.name}' completed successfully")
                return self.result

            except Exception as e:
                attempt += 1
                self.error = str(e)
                logger.warning(f"Step '{self.name}' failed (attempt {attempt}): {e}")

                if attempt >= self.retry_count:
                    self.status = StepStatus.FAILED
                    raise

        raise RuntimeError(f"Step '{self.name}' failed after {self.retry_count} attempts")

    async def compensate(self, context: Dict[str, Any]) -> None:
        """Execute compensation (rollback)"""
        if self.status not in [StepStatus.COMPLETED, StepStatus.FAILED]:
            return

        self.status = StepStatus.COMPENSATING
        logger.info(f"Compensating step '{self.name}'")

        try:
            await self.compensation(**context)
            self.status = StepStatus.COMPENSATED
            logger.info(f"Step '{self.name}' compensated successfully")
        except Exception as e:
            logger.error(f"Compensation for step '{self.name}' failed: {e}")
            raise


@dataclass
class SagaExecution:
    """Record of saga execution"""
    saga_id: str
    state: SagaState = SagaState.PENDING
    steps_executed: List[str] = field(default_factory=list)
    steps_compensated: List[str] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None

    def get_duration_seconds(self) -> float:
        """Get saga execution duration"""
        end_time = self.completed_at or datetime.utcnow()
        return (end_time - self.started_at).total_seconds()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'saga_id': self.saga_id,
            'state': self.state.value,
            'steps_executed': self.steps_executed,
            'steps_compensated': self.steps_compensated,
            'error': self.error,
            'duration_seconds': self.get_duration_seconds(),
            'started_at': self.started_at.isoformat(),
            'completed_at': self.completed_at.isoformat() if self.completed_at else None
        }


class Saga:
    """
    Orchestration-based Saga
    Coordinates steps and compensations for distributed transactions
    """

    def __init__(self, saga_id: Optional[str] = None):
        self.saga_id = saga_id or str(uuid.uuid4())
        self.steps: List[SagaStep] = []
        self.execution: Optional[SagaExecution] = None

    def add_step(
        self,
        name: str,
        action: Callable[..., Awaitable[Any]],
        compensation: Callable[..., Awaitable[None]],
        timeout_seconds: int = 30,
        retry_count: int = 3
    ) -> None:
        """Add step to saga"""
        step = SagaStep(
            name=name,
            action=action,
            compensation=compensation,
            timeout_seconds=timeout_seconds,
            retry_count=retry_count
        )
        self.steps.append(step)
        logger.debug(f"Added step '{name}' to saga {self.saga_id}")

    async def execute(self, initial_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Execute saga with compensation on failure
        Implements compensating transaction pattern
        """
        self.execution = SagaExecution(
            saga_id=self.saga_id,
            context=initial_context or {}
        )

        self.execution.state = SagaState.IN_PROGRESS

        try:
            # Execute all steps in order
            for step in self.steps:
                try:
                    result = await step.execute(self.execution.context)
                    self.execution.steps_executed.append(step.name)
                    self.execution.context[f"{step.name}_result"] = result
                    logger.info(f"Saga {self.saga_id}: Step '{step.name}' succeeded")

                except Exception as e:
                    logger.error(f"Saga {self.saga_id}: Step '{step.name}' failed: {e}")
                    self.execution.error = str(e)
                    self.execution.state = SagaState.COMPENSATING

                    # Compensate in reverse order
                    await self._compensate_executed_steps()

                    self.execution.state = SagaState.FAILED
                    self.execution.completed_at = datetime.utcnow()
                    raise RuntimeError(f"Saga failed at step '{step.name}': {e}")

            # All steps succeeded
            self.execution.state = SagaState.COMPLETED
            self.execution.completed_at = datetime.utcnow()
            logger.info(f"Saga {self.saga_id} completed successfully")

            return self.execution.context

        except Exception as e:
            logger.error(f"Saga {self.saga_id} failed: {e}")
            raise

    async def _compensate_executed_steps(self) -> None:
        """Compensate all executed steps in reverse order"""
        for step in reversed(self.steps):
            if step.name not in self.execution.steps_executed:
                continue

            try:
                await step.compensate(self.execution.context)
                self.execution.steps_compensated.append(step.name)
                logger.info(f"Saga {self.saga_id}: Step '{step.name}' compensated")

            except Exception as e:
                logger.error(
                    f"Saga {self.saga_id}: Compensation for '{step.name}' failed: {e}"
                )
                # Continue compensating other steps

    def get_execution_status(self) -> Optional[Dict[str, Any]]:
        """Get saga execution status"""
        if not self.execution:
            return None
        return self.execution.to_dict()


class SagaOrchestrator:
    """
    Central orchestrator managing multiple sagas
    Tracks saga execution and provides recovery mechanisms
    """

    def __init__(self):
        self.sagas: Dict[str, Saga] = {}
        self.executions: Dict[str, SagaExecution] = {}
        self.total_executed: int = 0
        self.total_succeeded: int = 0
        self.total_failed: int = 0

    def create_saga(self, saga_id: Optional[str] = None) -> Saga:
        """Create new saga"""
        saga = Saga(saga_id)
        self.sagas[saga.saga_id] = saga
        logger.info(f"Created saga: {saga.saga_id}")
        return saga

    async def execute_saga(self, saga: Saga, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Execute saga and track execution"""
        self.total_executed += 1

        try:
            result = await saga.execute(context)
            self.total_succeeded += 1

            if saga.execution:
                self.executions[saga.saga_id] = saga.execution

            logger.info(f"Saga {saga.saga_id} succeeded")
            return result

        except Exception as e:
            self.total_failed += 1

            if saga.execution:
                self.executions[saga.saga_id] = saga.execution

            logger.error(f"Saga {saga.saga_id} failed: {e}")
            raise

    def get_saga(self, saga_id: str) -> Optional[Saga]:
        """Get saga by ID"""
        return self.sagas.get(saga_id)

    def get_execution(self, saga_id: str) -> Optional[SagaExecution]:
        """Get saga execution record"""
        return self.executions.get(saga_id)

    def get_statistics(self) -> Dict[str, Any]:
        """Get orchestrator statistics"""
        return {
            'total_sagas': len(self.sagas),
            'total_executed': self.total_executed,
            'total_succeeded': self.total_succeeded,
            'total_failed': self.total_failed,
            'success_rate': (
                self.total_succeeded / self.total_executed * 100
                if self.total_executed > 0 else 0
            ),
            'stored_executions': len(self.executions)
        }


class ChoreographySaga:
    """
    Choreography-based Saga
    Services publish events that trigger other services
    Event-driven approach for distributed transactions
    """

    def __init__(self, saga_id: Optional[str] = None):
        self.saga_id = saga_id or str(uuid.uuid4())
        self.event_handlers: Dict[str, Callable] = {}
        self.event_history: List[Dict[str, Any]] = []

    def subscribe(self, event_type: str, handler: Callable) -> None:
        """Subscribe to event type"""
        self.event_handlers[event_type] = handler
        logger.debug(f"Subscribed to event: {event_type}")

    async def publish_event(self, event_type: str, data: Dict[str, Any]) -> None:
        """Publish event for choreography"""
        self.event_history.append({
            'event_type': event_type,
            'data': data,
            'timestamp': datetime.utcnow().isoformat()
        })

        if event_type in self.event_handlers:
            handler = self.event_handlers[event_type]
            try:
                await handler(data)
                logger.info(f"Event '{event_type}' processed successfully")
            except Exception as e:
                logger.error(f"Event handler for '{event_type}' failed: {e}")
                raise

    def get_event_history(self) -> List[Dict[str, Any]]:
        """Get all published events"""
        return self.event_history.copy()


__all__ = [
    'SagaState',
    'StepStatus',
    'SagaStep',
    'SagaExecution',
    'Saga',
    'SagaOrchestrator',
    'ChoreographySaga',
]
