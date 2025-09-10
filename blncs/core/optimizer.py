"""
Optimizer - Backward compatibility wrapper
Redirects to the unified performance system.
"""

from .performance_unified import (
    get_optimizer,
    get_performance_monitor,
    get_performance_optimizer,
    get_lightning_optimizer,
    get_liquidity_optimizer,
    PerformanceOptimizer,
    PerformanceMonitor,
    LightningOptimizer,
    PerformanceMetrics,
    OptimizationRecommendation,
    OptimizationLevel
)

# Backward compatibility aliases
SystemOptimizer = PerformanceOptimizer
Optimizer = PerformanceOptimizer

__all__ = [
    'get_optimizer',
    'get_performance_monitor',
    'get_performance_optimizer', 
    'get_lightning_optimizer',
    'get_liquidity_optimizer',
    'PerformanceOptimizer',
    'PerformanceMonitor',
    'LightningOptimizer',
    'SystemOptimizer',
    'Optimizer',
    'PerformanceMetrics',
    'OptimizationRecommendation',
    'OptimizationLevel'
]