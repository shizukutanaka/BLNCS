#!/usr/bin/env python3
"""
Lightweight Workflow Optimizer - 軽量ワークフロー最適化
Simple workflow optimization without external dependencies
"""

import asyncio
import time
from typing import Dict, List, Any, Optional, Callable, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import logging
from collections import defaultdict

logger = logging.getLogger(__name__)


class WorkflowType(Enum):
    SEQUENTIAL = "sequential"
    PARALLEL = "parallel"
    CONDITIONAL = "conditional"


@dataclass
class WorkflowStep:
    """ワークフローステップ定義"""
    step_id: str
    name: str
    func: Callable
    args: tuple = ()
    kwargs: dict = field(default_factory=dict)
    dependencies: List[str] = field(default_factory=list)
    estimated_duration: float = 1.0
    retry_count: int = 3
    timeout: float = 60.0


@dataclass
class WorkflowResult:
    """ワークフロー実行結果"""
    workflow_id: str
    success: bool
    results: Dict[str, Any] = field(default_factory=dict)
    errors: Dict[str, str] = field(default_factory=dict)
    execution_time: float = 0.0
    steps_completed: int = 0
    steps_failed: int = 0


class LightweightWorkflow:
    """軽量ワークフロー実行エンジン"""
    
    def __init__(self, workflow_id: str, steps: List[WorkflowStep]):
        self.workflow_id = workflow_id
        self.steps = {step.step_id: step for step in steps}
        self.results: Dict[str, Any] = {}
        self.errors: Dict[str, str] = {}
        self.completed_steps = set()
        self.failed_steps = set()
        self.analysis = self._analyze_workflow()
    
    def _analyze_workflow(self) -> Dict[str, Any]:
        """ワークフローを分析"""
        total_steps = len(self.steps)
        total_deps = sum(len(step.dependencies) for step in self.steps.values())
        estimated_time = sum(step.estimated_duration for step in self.steps.values())
        
        # Find parallelizable steps
        parallelizable = []
        for step in self.steps.values():
            if not step.dependencies:
                parallelizable.append(step.step_id)
        
        return {
            'total_steps': total_steps,
            'total_dependencies': total_deps,
            'estimated_time': estimated_time,
            'parallelizable_steps': len(parallelizable),
            'complexity_score': (total_deps / max(total_steps, 1)) * 100,
            'optimization_potential': len(parallelizable) / max(total_steps, 1)
        }
    
    def _get_ready_steps(self) -> List[WorkflowStep]:
        """実行可能なステップを取得"""
        ready = []
        for step in self.steps.values():
            if (step.step_id not in self.completed_steps and 
                step.step_id not in self.failed_steps and
                all(dep in self.completed_steps for dep in step.dependencies)):
                ready.append(step)
        return ready
    
    async def _execute_step(self, step: WorkflowStep) -> bool:
        """単一ステップを実行"""
        try:
            start_time = time.time()
            
            # Execute the step function
            if asyncio.iscoroutinefunction(step.func):
                result = await step.func(*step.args, **step.kwargs)
            else:
                result = step.func(*step.args, **step.kwargs)
            
            execution_time = time.time() - start_time
            
            self.results[step.step_id] = {
                'result': result,
                'execution_time': execution_time,
                'timestamp': datetime.now().isoformat()
            }
            
            self.completed_steps.add(step.step_id)
            logger.info(f"✅ Step '{step.step_id}' completed in {execution_time:.3f}s")
            return True
            
        except Exception as e:
            self.errors[step.step_id] = str(e)
            self.failed_steps.add(step.step_id)
            logger.error(f"❌ Step '{step.step_id}' failed: {e}")
            return False
    
    async def execute(self) -> WorkflowResult:
        """ワークフロー実行"""
        start_time = time.time()
        logger.info(f"🚀 Starting workflow '{self.workflow_id}' with {len(self.steps)} steps")
        
        while True:
            ready_steps = self._get_ready_steps()
            
            if not ready_steps:
                # No more steps to execute
                break
            
            # Execute ready steps in parallel
            tasks = []
            for step in ready_steps:
                task = asyncio.create_task(self._execute_step(step))
                tasks.append(task)
            
            # Wait for all tasks to complete
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
        
        execution_time = time.time() - start_time
        success = len(self.failed_steps) == 0
        
        result = WorkflowResult(
            workflow_id=self.workflow_id,
            success=success,
            results=self.results,
            errors=self.errors,
            execution_time=execution_time,
            steps_completed=len(self.completed_steps),
            steps_failed=len(self.failed_steps)
        )
        
        logger.info(f"🏁 Workflow '{self.workflow_id}' completed in {execution_time:.3f}s")
        logger.info(f"   ✅ Success: {len(self.completed_steps)} steps")
        logger.info(f"   ❌ Failed: {len(self.failed_steps)} steps")
        
        return result


class LightweightWorkflowOptimizer:
    """軽量ワークフロー最適化エンジン"""
    
    def __init__(self):
        self.workflows: Dict[str, LightweightWorkflow] = {}
        self.execution_history: List[WorkflowResult] = []
        self.performance_metrics = defaultdict(list)
    
    def create_workflow(self, workflow_id: str, steps: List[WorkflowStep]) -> LightweightWorkflow:
        """ワークフロー作成"""
        # Simple optimization: sort steps by dependencies
        optimized_steps = self._optimize_step_order(steps)
        
        workflow = LightweightWorkflow(workflow_id, optimized_steps)
        self.workflows[workflow_id] = workflow
        
        logger.info(f"📋 Created workflow '{workflow_id}' with {len(steps)} steps")
        logger.info(f"   🔧 Optimization potential: {workflow.analysis['optimization_potential']:.1%}")
        
        return workflow
    
    def _optimize_step_order(self, steps: List[WorkflowStep]) -> List[WorkflowStep]:
        """ステップ順序を最適化"""
        # Simple topological sort for dependencies
        ordered = []
        remaining = steps.copy()
        
        while remaining:
            # Find steps with no unfulfilled dependencies
            ready = []
            for step in remaining:
                if all(dep in [s.step_id for s in ordered] for dep in step.dependencies):
                    ready.append(step)
            
            if not ready:
                # Add remaining steps (handle circular dependencies)
                ordered.extend(remaining)
                break
            
            # Sort by estimated duration (shortest first for better parallelization)
            ready.sort(key=lambda s: s.estimated_duration)
            ordered.extend(ready)
            
            for step in ready:
                remaining.remove(step)
        
        return ordered
    
    async def execute_workflow(self, workflow_id: str) -> WorkflowResult:
        """ワークフロー実行"""
        if workflow_id not in self.workflows:
            raise ValueError(f"Workflow '{workflow_id}' not found")
        
        workflow = self.workflows[workflow_id]
        result = await workflow.execute()
        
        # Store execution history for learning
        self.execution_history.append(result)
        self._update_performance_metrics(result)
        
        return result
    
    def _update_performance_metrics(self, result: WorkflowResult):
        """パフォーマンスメトリクス更新"""
        self.performance_metrics['execution_times'].append(result.execution_time)
        self.performance_metrics['success_rates'].append(1.0 if result.success else 0.0)
        self.performance_metrics['steps_completed'].append(result.steps_completed)
        self.performance_metrics['steps_failed'].append(result.steps_failed)
        
        # Keep only recent history (last 100 executions)
        for key in self.performance_metrics:
            if len(self.performance_metrics[key]) > 100:
                self.performance_metrics[key] = self.performance_metrics[key][-100:]
    
    def get_performance_report(self) -> Dict[str, Any]:
        """パフォーマンスレポート取得"""
        if not self.performance_metrics['execution_times']:
            return {'message': 'No execution history available'}
        
        exec_times = self.performance_metrics['execution_times']
        success_rates = self.performance_metrics['success_rates']
        
        return {
            'total_executions': len(self.execution_history),
            'average_execution_time': sum(exec_times) / len(exec_times),
            'success_rate': sum(success_rates) / len(success_rates),
            'total_workflows': len(self.workflows),
            'recent_performance': {
                'last_10_avg_time': sum(exec_times[-10:]) / min(len(exec_times), 10),
                'last_10_success_rate': sum(success_rates[-10:]) / min(len(success_rates), 10)
            }
        }


# Global instance
_optimizer = None
_lock = asyncio.Lock()


async def get_optimizer() -> LightweightWorkflowOptimizer:
    """グローバルオプティマイザー取得"""
    global _optimizer
    async with _lock:
        if _optimizer is None:
            _optimizer = LightweightWorkflowOptimizer()
        return _optimizer


async def optimize_workflow(workflow_id: str, steps: List[WorkflowStep]) -> LightweightWorkflow:
    """ワークフロー最適化 (便利関数)"""
    optimizer = await get_optimizer()
    return optimizer.create_workflow(workflow_id, steps)


async def execute_optimized_workflow(workflow_id: str, steps: List[WorkflowStep]) -> WorkflowResult:
    """最適化済みワークフロー実行 (便利関数)"""
    optimizer = await get_optimizer()
    workflow = optimizer.create_workflow(workflow_id, steps)
    return await optimizer.execute_workflow(workflow_id)