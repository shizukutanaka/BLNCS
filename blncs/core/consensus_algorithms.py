#!/usr/bin/env python3
"""
Consensus Algorithms Module
Implements Raft and simplified Paxos for distributed systems
Based on 2025 research on distributed consensus for Bitcoin L2 solutions
"""

import logging
import time
from typing import Dict, List, Optional, Set, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
from abc import ABC, abstractmethod
import random

logger = logging.getLogger(__name__)


class NodeState(Enum):
    """Raft node states"""
    FOLLOWER = "follower"
    CANDIDATE = "candidate"
    LEADER = "leader"


@dataclass
class LogEntry:
    """Entry in consensus log"""
    term: int
    command: str
    data: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class NodeMetadata:
    """Metadata for a consensus node"""
    node_id: str
    state: NodeState = NodeState.FOLLOWER
    current_term: int = 0
    voted_for: Optional[str] = None
    log: List[LogEntry] = field(default_factory=list)
    commit_index: int = 0
    last_applied: int = 0
    last_heartbeat: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'node_id': self.node_id,
            'state': self.state.value,
            'current_term': self.current_term,
            'voted_for': self.voted_for,
            'log_size': len(self.log),
            'commit_index': self.commit_index,
            'last_applied': self.last_applied
        }


class RaftConsensus:
    """
    Raft consensus algorithm implementation
    Simpler and more understandable than Paxos
    """

    def __init__(self, node_id: str, peers: Set[str]):
        """
        Initialize Raft node

        Args:
            node_id: Unique node identifier
            peers: Set of peer node IDs (excluding self)
        """
        self.node = NodeMetadata(node_id=node_id)
        self.peers = peers
        self.all_nodes = peers | {node_id}

        # Raft timeouts
        self.election_timeout = random.uniform(1.5, 3.0)
        self.heartbeat_interval = 0.5
        self.last_election_time = time.time()

        # State machine
        self.state_machine: Dict[str, Any] = {}

        logger.info(f"Raft node {node_id} initialized")

    def append_log_entry(self, command: str, data: Dict[str, Any]) -> bool:
        """
        Client: Append entry to log (only leader can)

        Returns:
            True if successfully appended
        """
        if self.node.state != NodeState.LEADER:
            logger.warning(f"Non-leader cannot append: {self.node.node_id}")
            return False

        entry = LogEntry(
            term=self.node.current_term,
            command=command,
            data=data
        )

        self.node.log.append(entry)
        logger.info(f"Appended log entry: {command}")
        return True

    def request_vote(self, candidate_id: str, term: int) -> bool:
        """
        RPC: Handle vote request from candidate

        Returns:
            True if vote granted
        """
        # Reject if requesting term is older
        if term < self.node.current_term:
            return False

        # Update term
        if term > self.node.current_term:
            self.node.current_term = term
            self.node.voted_for = None

        # Grant vote if haven't voted or vote was for this candidate
        if self.node.voted_for is None or self.node.voted_for == candidate_id:
            self.node.voted_for = candidate_id
            self.last_election_time = time.time()
            logger.debug(f"Granted vote to {candidate_id}")
            return True

        return False

    def start_election(self) -> None:
        """Start election process"""
        if self.node.state == NodeState.LEADER:
            return

        # Increment term
        self.node.current_term += 1
        self.node.state = NodeState.CANDIDATE
        self.node.voted_for = self.node.node_id

        logger.info(f"Node {self.node.node_id} starting election (term {self.node.current_term})")

        # Count votes (including self)
        votes = 1

        # Request votes from peers (simulated)
        for peer in self.peers:
            if self.request_vote(self.node.node_id, self.node.current_term):
                votes += 1

        # Check if won election (majority)
        if votes > len(self.all_nodes) / 2:
            self.become_leader()
        else:
            self.node.state = NodeState.FOLLOWER

    def become_leader(self) -> None:
        """Transition to leader state"""
        self.node.state = NodeState.LEADER
        self.node.voted_for = None
        logger.info(f"Node {self.node.node_id} became LEADER (term {self.node.current_term})")

    def send_heartbeat(self) -> None:
        """Send heartbeat to all peers"""
        if self.node.state != NodeState.LEADER:
            return

        for peer in self.peers:
            logger.debug(f"Sending heartbeat to {peer}")

    def receive_heartbeat(self, leader_id: str, term: int) -> None:
        """Receive heartbeat from leader"""
        if term > self.node.current_term:
            self.node.current_term = term
            self.node.voted_for = None

        if term >= self.node.current_term:
            self.node.state = NodeState.FOLLOWER
            self.last_election_time = time.time()
            logger.debug(f"Received heartbeat from {leader_id}")

    def check_election_timeout(self) -> None:
        """Check if election timeout has elapsed"""
        elapsed = time.time() - self.last_election_time

        if elapsed > self.election_timeout:
            self.start_election()
            self.election_timeout = random.uniform(1.5, 3.0)

    def get_state(self) -> Dict[str, Any]:
        """Get node state for monitoring"""
        return self.node.to_dict()


class PaxosConsensus:
    """
    Simplified Paxos consensus algorithm
    More complex but can handle more scenarios than Raft
    """

    def __init__(self, node_id: str, acceptors: Set[str]):
        """
        Initialize Paxos node

        Args:
            node_id: Unique node identifier
            acceptors: Set of acceptor IDs
        """
        self.node_id = node_id
        self.acceptors = acceptors
        self.proposal_number = 0

        # Acceptor state
        self.promised_number = -1
        self.accepted_number = -1
        self.accepted_value: Optional[str] = None

        # Learner state
        self.accepted_proposals: Dict[int, List[Any]] = {}

        logger.info(f"Paxos node {node_id} initialized")

    def prepare(self, proposal_number: int) -> Tuple[bool, Dict[str, Any]]:
        """
        Phase 1: Prepare request
        Proposer sends prepare request to acceptors

        Returns:
            (accepted, {promised_number, accepted_number, accepted_value})
        """
        if proposal_number <= self.promised_number:
            logger.debug(f"Prepare rejected: proposal_number {proposal_number}")
            return False, {}

        self.promised_number = proposal_number

        return True, {
            'promised_number': self.promised_number,
            'accepted_number': self.accepted_number,
            'accepted_value': self.accepted_value
        }

    def accept(self, proposal_number: int, value: str) -> bool:
        """
        Phase 2: Accept request
        Proposer sends accept request to acceptors

        Returns:
            True if accepted
        """
        if proposal_number < self.promised_number:
            logger.debug(f"Accept rejected: {proposal_number} < {self.promised_number}")
            return False

        self.accepted_number = proposal_number
        self.accepted_value = value

        logger.debug(f"Accepted proposal {proposal_number}: {value}")
        return True

    def learn(self, proposal_number: int, value: str, proposer: str) -> None:
        """
        Learner: Record accepted proposal

        Args:
            proposal_number: Proposal number
            value: Accepted value
            proposer: Proposer ID
        """
        if proposal_number not in self.accepted_proposals:
            self.accepted_proposals[proposal_number] = []

        self.accepted_proposals[proposal_number].append({
            'value': value,
            'proposer': proposer,
            'timestamp': datetime.utcnow().isoformat()
        })

        logger.debug(f"Learned proposal {proposal_number}: {value}")

    def get_accepted_value(self) -> Optional[str]:
        """Get currently accepted value"""
        return self.accepted_value

    def get_state(self) -> Dict[str, Any]:
        """Get node state for monitoring"""
        return {
            'node_id': self.node_id,
            'promised_number': self.promised_number,
            'accepted_number': self.accepted_number,
            'accepted_value': self.accepted_value,
            'learned_count': len(self.accepted_proposals)
        }


class ConsensusMetrics:
    """Track consensus performance"""

    def __init__(self):
        """Initialize metrics"""
        self.elections_started = 0
        self.leaders_elected = 0
        self.proposals_submitted = 0
        self.proposals_accepted = 0
        self.log_entries_committed = 0
        self.startup_time = datetime.utcnow()

    def record_election_start(self) -> None:
        """Record election start"""
        self.elections_started += 1

    def record_leader_election(self) -> None:
        """Record successful leader election"""
        self.leaders_elected += 1

    def record_proposal(self, accepted: bool) -> None:
        """Record proposal"""
        self.proposals_submitted += 1
        if accepted:
            self.proposals_accepted += 1

    def record_commit(self) -> None:
        """Record log entry commit"""
        self.log_entries_committed += 1

    def get_metrics(self) -> Dict[str, Any]:
        """Get metrics"""
        uptime = (datetime.utcnow() - self.startup_time).total_seconds()

        return {
            'elections_started': self.elections_started,
            'leaders_elected': self.leaders_elected,
            'proposals_submitted': self.proposals_submitted,
            'proposals_accepted': self.proposals_accepted,
            'proposal_acceptance_rate': (
                (self.proposals_accepted / self.proposals_submitted * 100)
                if self.proposals_submitted > 0 else 0
            ),
            'log_entries_committed': self.log_entries_committed,
            'uptime_seconds': uptime
        }


class ConsensusCluster:
    """Manages a cluster of consensus nodes"""

    def __init__(self, algorithm: str = "raft"):
        """
        Initialize cluster

        Args:
            algorithm: "raft" or "paxos"
        """
        self.algorithm = algorithm
        self.nodes: Dict[str, Any] = {}
        self.metrics = ConsensusMetrics()

    def add_node(self, node_id: str, peers: Optional[Set[str]] = None) -> None:
        """Add node to cluster"""
        if peers is None:
            peers = set(self.nodes.keys())

        if self.algorithm == "raft":
            self.nodes[node_id] = RaftConsensus(node_id, peers)

        elif self.algorithm == "paxos":
            self.nodes[node_id] = PaxosConsensus(node_id, peers)

        logger.info(f"Added {self.algorithm.upper()} node: {node_id}")

    def get_node(self, node_id: str) -> Optional[Any]:
        """Get node by ID"""
        return self.nodes.get(node_id)

    def get_metrics(self) -> Dict[str, Any]:
        """Get cluster metrics"""
        return {
            'algorithm': self.algorithm,
            'node_count': len(self.nodes),
            'nodes': {
                node_id: node.get_state()
                for node_id, node in self.nodes.items()
            },
            'cluster_metrics': self.metrics.get_metrics()
        }

    def simulate_step(self) -> None:
        """Simulate one consensus step"""
        if self.algorithm == "raft":
            for node in self.nodes.values():
                node.check_election_timeout()
                if node.node.state == NodeState.LEADER:
                    node.send_heartbeat()


__all__ = [
    'NodeState',
    'LogEntry',
    'NodeMetadata',
    'RaftConsensus',
    'PaxosConsensus',
    'ConsensusMetrics',
    'ConsensusCluster',
]
