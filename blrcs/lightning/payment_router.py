import asyncio
import heapq
import time
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, NamedTuple
from enum import Enum
import networkx as nx
import logging

logger = logging.getLogger(__name__)

class RouteMetric(Enum):
    LOWEST_FEE = "lowest_fee"
    FASTEST = "fastest"
    HIGHEST_SUCCESS = "highest_success"
    BALANCED = "balanced"

@dataclass
class ChannelEdge:
    channel_id: str
    node1: str
    node2: str
    capacity: int
    fee_base_msat: int
    fee_rate_millimsat: int
    time_lock_delta: int
    min_htlc: int
    max_htlc_msat: int
    last_update: datetime
    active: bool
    disabled: bool
    success_rate: float = 1.0
    avg_response_time: float = 0.0
    liquidity_estimate: float = 0.5

@dataclass
class PaymentRoute:
    hops: List[str]
    channels: List[str]
    total_fee_msat: int
    total_time_lock: int
    probability: float
    estimated_time: float
    risk_score: float

class PaymentPathfinder:
    def __init__(self, max_routes: int = 10):
        self.graph = nx.DiGraph()
        self.max_routes = max_routes
        self.channel_edges: Dict[str, ChannelEdge] = {}
        self.payment_history: List[Dict] = []
        self.node_reliability: Dict[str, float] = {}
        
    def update_graph(self, channels: List[ChannelEdge]):
        """ネットワークグラフを更新"""
        self.graph.clear()
        self.channel_edges.clear()
        
        for channel in channels:
            if not channel.active or channel.disabled:
                continue
                
            self.channel_edges[channel.channel_id] = channel
            
            # 双方向エッジを追加
            self.graph.add_edge(
                channel.node1, 
                channel.node2,
                channel_id=channel.channel_id,
                weight=self._calculate_edge_weight(channel, "forward")
            )
            self.graph.add_edge(
                channel.node2,
                channel.node1, 
                channel_id=channel.channel_id,
                weight=self._calculate_edge_weight(channel, "reverse")
            )
    
    def _calculate_edge_weight(self, channel: ChannelEdge, direction: str) -> float:
        """エッジの重みを計算（複数の要因を考慮）"""
        base_weight = 1.0
        
        # 手数料コスト
        fee_weight = (channel.fee_base_msat + channel.fee_rate_millimsat) / 1000000
        
        # 成功率
        success_weight = 1.0 - channel.success_rate
        
        # 応答時間
        time_weight = channel.avg_response_time / 1000
        
        # 流動性推定
        liquidity_weight = 1.0 - channel.liquidity_estimate
        
        return base_weight + fee_weight + success_weight + time_weight + liquidity_weight
    
    async def find_routes(self, source: str, target: str, amount_msat: int, 
                         metric: RouteMetric = RouteMetric.BALANCED) -> List[PaymentRoute]:
        """最適な支払いルートを検索"""
        if source not in self.graph or target not in self.graph:
            return []
        
        routes = []
        
        try:
            # K-shortest pathアルゴリズムを使用
            k_paths = list(nx.shortest_simple_paths(
                self.graph, source, target, weight='weight'
            ))[:self.max_routes]
            
            for path in k_paths:
                route = await self._path_to_route(path, amount_msat, metric)
                if route and self._validate_route(route, amount_msat):
                    routes.append(route)
            
            # メトリクスに基づいてソート
            routes.sort(key=lambda r: self._route_score(r, metric))
            
        except nx.NetworkXNoPath:
            logger.warning(f"No path found from {source} to {target}")
        
        return routes[:5]  # トップ5ルートを返す
    
    async def _path_to_route(self, path: List[str], amount_msat: int, 
                           metric: RouteMetric) -> Optional[PaymentRoute]:
        """ノードパスをPaymentRouteに変換"""
        if len(path) < 2:
            return None
        
        channels = []
        total_fee = 0
        total_time_lock = 0
        probability = 1.0
        estimated_time = 0.0
        risk_score = 0.0
        
        for i in range(len(path) - 1):
            node1, node2 = path[i], path[i + 1]
            edge_data = self.graph[node1][node2]
            channel_id = edge_data['channel_id']
            
            if channel_id not in self.channel_edges:
                return None
            
            channel = self.channel_edges[channel_id]
            channels.append(channel_id)
            
            # 手数料計算
            hop_fee = channel.fee_base_msat + (amount_msat * channel.fee_rate_millimsat // 1000000)
            total_fee += hop_fee
            
            # タイムロック
            total_time_lock += channel.time_lock_delta
            
            # 成功確率
            probability *= channel.success_rate
            
            # 推定時間
            estimated_time += channel.avg_response_time
            
            # リスクスコア
            risk_score += (1.0 - channel.success_rate) + (1.0 - channel.liquidity_estimate)
        
        return PaymentRoute(
            hops=path,
            channels=channels,
            total_fee_msat=total_fee,
            total_time_lock=total_time_lock,
            probability=probability,
            estimated_time=estimated_time,
            risk_score=risk_score
        )
    
    def _validate_route(self, route: PaymentRoute, amount_msat: int) -> bool:
        """ルートの有効性を検証"""
        for channel_id in route.channels:
            if channel_id not in self.channel_edges:
                return False
            
            channel = self.channel_edges[channel_id]
            
            # 容量チェック
            if amount_msat > channel.max_htlc_msat:
                return False
            
            if amount_msat < channel.min_htlc:
                return False
        
        return True
    
    def _route_score(self, route: PaymentRoute, metric: RouteMetric) -> float:
        """メトリクスに基づくルートスコア"""
        if metric == RouteMetric.LOWEST_FEE:
            return route.total_fee_msat
        elif metric == RouteMetric.FASTEST:
            return route.estimated_time
        elif metric == RouteMetric.HIGHEST_SUCCESS:
            return -route.probability  # 高い成功率が良い
        else:  # BALANCED
            # 正規化されたスコアの組み合わせ
            fee_score = route.total_fee_msat / 100000  # msat to normalized
            time_score = route.estimated_time / 1000   # ms to normalized
            success_score = (1.0 - route.probability) * 100
            risk_score = route.risk_score * 10
            
            return fee_score + time_score + success_score + risk_score

class PaymentOptimizer:
    def __init__(self, pathfinder: PaymentPathfinder):
        self.pathfinder = pathfinder
        self.payment_cache: Dict[str, List[PaymentRoute]] = {}
        self.cache_ttl = 300  # 5分
        self.cache_timestamps: Dict[str, float] = {}
        
    async def optimize_payment(self, source: str, target: str, amount_msat: int,
                              max_fee_msat: int = None, 
                              timeout_seconds: int = 30) -> Optional[PaymentRoute]:
        """支払いを最適化"""
        cache_key = f"{source}-{target}-{amount_msat}"
        
        # キャッシュチェック
        if self._is_cache_valid(cache_key):
            routes = self.payment_cache[cache_key]
        else:
            routes = await self.pathfinder.find_routes(source, target, amount_msat)
            self._update_cache(cache_key, routes)
        
        # 制約フィルタリング
        valid_routes = []
        for route in routes:
            if max_fee_msat and route.total_fee_msat > max_fee_msat:
                continue
            if route.estimated_time > timeout_seconds * 1000:
                continue
            valid_routes.append(route)
        
        return valid_routes[0] if valid_routes else None
    
    def _is_cache_valid(self, cache_key: str) -> bool:
        """キャッシュの有効性チェック"""
        if cache_key not in self.cache_timestamps:
            return False
        return time.time() - self.cache_timestamps[cache_key] < self.cache_ttl
    
    def _update_cache(self, cache_key: str, routes: List[PaymentRoute]):
        """キャッシュ更新"""
        self.payment_cache[cache_key] = routes
        self.cache_timestamps[cache_key] = time.time()

class MultiPathPayment:
    def __init__(self, optimizer: PaymentOptimizer, max_parts: int = 5):
        self.optimizer = optimizer
        self.max_parts = max_parts
        
    async def split_payment(self, source: str, target: str, total_amount_msat: int) -> List[Tuple[PaymentRoute, int]]:
        """支払いを複数パスに分割"""
        parts = []
        remaining = total_amount_msat
        
        # 初期分割サイズを決定
        part_size = total_amount_msat // self.max_parts
        
        for i in range(self.max_parts):
            if remaining <= 0:
                break
            
            amount = min(part_size, remaining)
            
            route = await self.optimizer.optimize_payment(source, target, amount)
            if route:
                parts.append((route, amount))
                remaining -= amount
            else:
                # ルートが見つからない場合、サイズを調整
                if amount > 10000:  # 10 satより大きい場合
                    amount = amount // 2
                    route = await self.optimizer.optimize_payment(source, target, amount)
                    if route:
                        parts.append((route, amount))
                        remaining -= amount
        
        return parts

class PaymentRouter:
    def __init__(self, lnd_connector):
        self.lnd_connector = lnd_connector
        self.pathfinder = PaymentPathfinder()
        self.optimizer = PaymentOptimizer(self.pathfinder)
        self.multipath = MultiPathPayment(self.optimizer)
        self.running = False
        
    async def start(self):
        """ルーター開始"""
        self.running = True
        await self._update_network_graph()
        
        # 定期的なグラフ更新
        asyncio.create_task(self._periodic_graph_update())
        
    async def stop(self):
        """ルーター停止"""
        self.running = False
        
    async def route_payment(self, target: str, amount_msat: int, 
                           use_multipath: bool = True,
                           max_fee_msat: int = None) -> Dict:
        """支払いをルーティング"""
        try:
            source = await self.lnd_connector.get_node_info()
            source_pubkey = source['identity_pubkey']
            
            if use_multipath and amount_msat > 1000000:  # 1000 sat以上でマルチパス
                parts = await self.multipath.split_payment(source_pubkey, target, amount_msat)
                if parts:
                    return {
                        'type': 'multipath',
                        'parts': len(parts),
                        'routes': [part[0] for part in parts],
                        'amounts': [part[1] for part in parts],
                        'total_fee': sum(part[0].total_fee_msat for part in parts),
                        'success_probability': min(part[0].probability for part in parts)
                    }
            
            # シングルパス支払い
            route = await self.optimizer.optimize_payment(
                source_pubkey, target, amount_msat, max_fee_msat
            )
            
            if route:
                return {
                    'type': 'single',
                    'route': route,
                    'total_fee': route.total_fee_msat,
                    'success_probability': route.probability
                }
            
            return {'error': 'No route found'}
            
        except Exception as e:
            logger.error(f"Payment routing error: {e}")
            return {'error': str(e)}
    
    async def _update_network_graph(self):
        """ネットワークグラフを更新"""
        try:
            channels_data = await self.lnd_connector.describe_graph()
            channels = []
            
            for edge in channels_data.get('edges', []):
                channel = ChannelEdge(
                    channel_id=edge['channel_id'],
                    node1=edge['node1_pub'],
                    node2=edge['node2_pub'],
                    capacity=int(edge['capacity']),
                    fee_base_msat=int(edge['node1_policy']['fee_base_msat']),
                    fee_rate_millimsat=int(edge['node1_policy']['fee_rate_milli_msat']),
                    time_lock_delta=int(edge['node1_policy']['time_lock_delta']),
                    min_htlc=int(edge['node1_policy']['min_htlc']),
                    max_htlc_msat=int(edge['node1_policy']['max_htlc_msat']),
                    last_update=datetime.fromtimestamp(int(edge['last_update'])),
                    active=not edge['node1_policy']['disabled'],
                    disabled=edge['node1_policy']['disabled']
                )
                channels.append(channel)
            
            self.pathfinder.update_graph(channels)
            logger.info(f"Updated network graph with {len(channels)} channels")
            
        except Exception as e:
            logger.error(f"Failed to update network graph: {e}")
    
    async def _periodic_graph_update(self):
        """定期的なグラフ更新"""
        while self.running:
            await asyncio.sleep(600)  # 10分間隔
            await self._update_network_graph()
    
    async def get_routing_stats(self) -> Dict:
        """ルーティング統計を取得"""
        return {
            'nodes_count': self.pathfinder.graph.number_of_nodes(),
            'channels_count': len(self.pathfinder.channel_edges),
            'cache_size': len(self.optimizer.payment_cache),
            'avg_success_rate': sum(
                channel.success_rate for channel in self.pathfinder.channel_edges.values()
            ) / max(len(self.pathfinder.channel_edges), 1)
        }