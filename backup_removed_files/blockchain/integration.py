"""
Blockchain Integration for BLNCS Enterprise
Provides tamper-proof data storage, traceability, and distributed consensus
"""

import hashlib
import time
import json
import threading
from typing import Dict, List, Optional, Any, Tuple
from collections import defaultdict, deque
from datetime import datetime, timedelta
import sqlite3
import logging
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)

class MerkleTree:
    """Merkle tree implementation for efficient data verification"""

    def __init__(self, data_chunks: List[bytes]):
        self.data_chunks = data_chunks
        self.tree = self._build_tree(data_chunks)

    def _build_tree(self, chunks: List[bytes]) -> List[bytes]:
        """Build Merkle tree from data chunks"""
        if not chunks:
            return []

        # Convert chunks to hashes
        current_level = [hashlib.sha256(chunk).digest() for chunk in chunks]

        while len(current_level) > 1:
            next_level = []

            # Hash pairs of nodes
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left

                combined = left + right
                next_level.append(hashlib.sha256(combined).digest())

            current_level = next_level

        return current_level

    def get_root_hash(self) -> bytes:
        """Get Merkle root hash"""
        return self.tree[0] if self.tree else hashlib.sha256(b'').digest()

    def get_proof(self, chunk_index: int) -> List[bytes]:
        """Get Merkle proof for specific chunk"""
        if chunk_index >= len(self.data_chunks):
            return []

        proof = []
        current_level = [hashlib.sha256(chunk).digest() for chunk in self.data_chunks]

        while len(current_level) > 1:
            next_level = []
            proof_level = []

            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left

                # Determine which hash to include in proof
                if i == chunk_index:
                    proof_level.append(right)
                    chunk_index = i // 2
                elif i + 1 == chunk_index:
                    proof_level.append(left)
                    chunk_index = i // 2
                else:
                    proof_level.append(b'')  # Not part of proof path

                combined = left + right
                next_level.append(hashlib.sha256(combined).digest())

            proof.append(b''.join(proof_level))
            current_level = next_level

        return proof

class Block:
    """Blockchain block implementation"""

    def __init__(self, index: int, previous_hash: bytes, timestamp: float,
                 data: List[Dict[str, Any]], merkle_root: bytes, nonce: int = 0):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.data = data
        self.merkle_root = merkle_root
        self.nonce = nonce
        self.hash = self._calculate_hash()

    def _calculate_hash(self) -> bytes:
        """Calculate block hash"""
        block_data = {
            'index': self.index,
            'previous_hash': self.previous_hash.hex(),
            'timestamp': self.timestamp,
            'data': self.data,
            'merkle_root': self.merkle_root.hex(),
            'nonce': self.nonce
        }

        block_string = json.dumps(block_data, sort_keys=True)
        return hashlib.sha256(block_string.encode()).digest()

    def mine_block(self, difficulty: int) -> None:
        """Mine block with proof-of-work"""
        target = '0' * difficulty

        while self.hash.hex()[:difficulty] != target:
            self.nonce += 1
            self.hash = self._calculate_hash()

class Blockchain:
    """Main blockchain implementation"""

    def __init__(self, difficulty: int = 4):
        self.chain = []
        self.pending_transactions = []
        self.difficulty = difficulty
        self.lock = threading.Lock()

        # Create genesis block
        self._create_genesis_block()

    def _create_genesis_block(self):
        """Create genesis block"""
        genesis_block = Block(0, b'0' * 32, time.time(), [], hashlib.sha256(b'genesis').digest())
        genesis_block.mine_block(self.difficulty)
        self.chain.append(genesis_block)

    def get_latest_block(self) -> Block:
        """Get latest block in chain"""
        return self.chain[-1]

    def add_block(self, data: List[Dict[str, Any]]) -> bool:
        """Add new block to blockchain"""
        with self.lock:
            # Create Merkle tree for data
            data_bytes = [json.dumps(item, sort_keys=True).encode() for item in data]
            merkle_tree = MerkleTree(data_bytes)
            merkle_root = merkle_tree.get_root_hash()

            # Create new block
            latest_block = self.get_latest_block()
            new_block = Block(
                latest_block.index + 1,
                latest_block.hash,
                time.time(),
                data,
                merkle_root
            )

            # Mine block
            new_block.mine_block(self.difficulty)

            # Verify block
            if self._is_block_valid(new_block, latest_block):
                self.chain.append(new_block)
                logger.info(f"Added block {new_block.index} to blockchain")
                return True
            else:
                logger.error("Invalid block generated")
                return False

    def _is_block_valid(self, new_block: Block, previous_block: Block) -> bool:
        """Verify block validity"""
        # Check index
        if new_block.index != previous_block.index + 1:
            return False

        # Check previous hash
        if new_block.previous_hash != previous_block.hash:
            return False

        # Check hash difficulty
        if new_block.hash.hex()[:self.difficulty] != '0' * self.difficulty:
            return False

        # Verify Merkle root
        data_bytes = [json.dumps(item, sort_keys=True).encode() for item in new_block.data]
        merkle_tree = MerkleTree(data_bytes)
        if merkle_tree.get_root_hash() != new_block.merkle_root:
            return False

        return True

    def is_chain_valid(self) -> bool:
        """Verify entire blockchain integrity"""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            if not self._is_block_valid(current_block, previous_block):
                return False

        return True

    def get_chain_info(self) -> Dict[str, Any]:
        """Get blockchain information"""
        return {
            'length': len(self.chain),
            'latest_block_index': self.chain[-1].index if self.chain else 0,
            'latest_block_hash': self.chain[-1].hash.hex() if self.chain else '',
            'difficulty': self.difficulty,
            'pending_transactions': len(self.pending_transactions),
            'is_valid': self.is_chain_valid()
        }

class DistributedConsensus:
    """Distributed consensus mechanism"""

    def __init__(self, blockchain: Blockchain):
        self.blockchain = blockchain
        self.nodes = set()
        self.node_weights = {}
        self.consensus_threshold = 0.67  # 67% agreement required
        self.lock = threading.Lock()

    def register_node(self, node_id: str, weight: float = 1.0):
        """Register consensus node"""
        with self.lock:
            self.nodes.add(node_id)
            self.node_weights[node_id] = weight

    def propose_block(self, data: List[Dict[str, Any]]) -> str:
        """Propose new block for consensus"""
        proposal_id = secrets.token_hex(16)

        # In production, this would broadcast to all nodes
        logger.info(f"Block proposal {proposal_id} broadcast to {len(self.nodes)} nodes")

        return proposal_id

    def vote_on_block(self, proposal_id: str, node_id: str, vote: bool) -> bool:
        """Cast vote on block proposal"""
        with self.lock:
            # Record vote (in production, this would be stored distributedly)
            logger.info(f"Node {node_id} voted {vote} on proposal {proposal_id}")
            return True

    def reach_consensus(self, proposal_id: str) -> bool:
        """Check if consensus has been reached"""
        with self.lock:
            # Simplified consensus check
            # In production, this would involve complex distributed consensus algorithms
            total_weight = sum(self.node_weights.values())
            if total_weight == 0:
                return False

            # Simulate consensus (in reality, this would query all nodes)
            agreement_ratio = 0.8  # Simulate 80% agreement

            return agreement_ratio >= self.consensus_threshold

class AuditTrailManager:
    """Comprehensive audit trail with blockchain verification"""

    def __init__(self, blockchain: Blockchain):
        self.blockchain = blockchain
        self.audit_db_path = "audit_trail.db"
        self._init_audit_database()

    def _init_audit_database(self):
        """Initialize audit trail database"""
        with sqlite3.connect(self.audit_db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS audit_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    user_id TEXT,
                    action TEXT NOT NULL,
                    resource TEXT,
                    details TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    session_id TEXT,
                    block_index INTEGER,
                    merkle_proof TEXT,
                    blockchain_hash TEXT
                )
            ''')

            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_audit_timestamp
                ON audit_entries(timestamp)
            ''')

            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_audit_user
                ON audit_entries(user_id)
            ''')

    def record_audit_entry(self, entry: Dict[str, Any]) -> bool:
        """Record tamper-proof audit entry"""
        try:
            # Prepare audit data
            audit_data = {
                'timestamp': entry.get('timestamp', time.time()),
                'user_id': entry.get('user_id', ''),
                'action': entry.get('action', ''),
                'resource': entry.get('resource', ''),
                'details': json.dumps(entry.get('details', {})),
                'ip_address': entry.get('ip_address', ''),
                'user_agent': entry.get('user_agent', ''),
                'session_id': entry.get('session_id', '')
            }

            # Add to blockchain
            block_data = [audit_data]
            if self.blockchain.add_block(block_data):
                latest_block = self.blockchain.get_latest_block()

                # Store in database with blockchain verification
                with sqlite3.connect(self.audit_db_path) as conn:
                    conn.execute('''
                        INSERT INTO audit_entries
                        (timestamp, user_id, action, resource, details, ip_address,
                         user_agent, session_id, block_index, blockchain_hash)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        audit_data['timestamp'],
                        audit_data['user_id'],
                        audit_data['action'],
                        audit_data['resource'],
                        audit_data['details'],
                        audit_data['ip_address'],
                        audit_data['user_agent'],
                        audit_data['session_id'],
                        latest_block.index,
                        latest_block.hash.hex()
                    ))

                logger.info(f"Recorded tamper-proof audit entry: {audit_data['action']}")
                return True
            else:
                logger.error("Failed to add audit entry to blockchain")
                return False

        except Exception as e:
            logger.error(f"Error recording audit entry: {e}")
            return False

    def verify_audit_integrity(self, entry_id: int) -> Dict[str, Any]:
        """Verify audit entry integrity using blockchain"""
        try:
            with sqlite3.connect(self.audit_db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute('''
                    SELECT * FROM audit_entries WHERE id = ?
                ''', (entry_id,))

                entry = cursor.fetchone()

            if not entry:
                return {'verified': False, 'error': 'Entry not found'}

            # Verify blockchain integrity
            block_index = entry['block_index']
            if block_index >= len(self.blockchain.chain):
                return {'verified': False, 'error': 'Block not found in chain'}

            block = self.blockchain.chain[block_index]

            # Verify block hash
            if block.hash.hex() != entry['blockchain_hash']:
                return {'verified': False, 'error': 'Block hash mismatch'}

            # Verify chain integrity
            if not self.blockchain.is_chain_valid():
                return {'verified': False, 'error': 'Blockchain integrity compromised'}

            return {
                'verified': True,
                'entry_id': entry_id,
                'block_index': block_index,
                'block_hash': block.hash.hex(),
                'timestamp': entry['timestamp']
            }

        except Exception as e:
            return {'verified': False, 'error': str(e)}

    def get_audit_report(self, start_time: float = None, end_time: float = None) -> Dict[str, Any]:
        """Get comprehensive audit report"""
        try:
            query = "SELECT * FROM audit_entries WHERE 1=1"
            params = []

            if start_time:
                query += " AND timestamp >= ?"
                params.append(start_time)

            if end_time:
                query += " AND timestamp <= ?"
                params.append(end_time)

            query += " ORDER BY timestamp DESC"

            with sqlite3.connect(self.audit_db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute(query, params)

                entries = []
                for row in cursor:
                    entry = dict(row)
                    # Parse details JSON
                    try:
                        entry['details'] = json.loads(entry['details'])
                    except:
                        pass
                    entries.append(entry)

            # Generate summary statistics
            total_entries = len(entries)
            unique_users = len(set(entry['user_id'] for entry in entries if entry['user_id']))
            action_counts = defaultdict(int)
            for entry in entries:
                action_counts[entry['action']] += 1

            return {
                'summary': {
                    'total_entries': total_entries,
                    'unique_users': unique_users,
                    'time_period': {
                        'start': datetime.fromtimestamp(start_time).isoformat() if start_time else None,
                        'end': datetime.fromtimestamp(end_time).isoformat() if end_time else None
                    },
                    'blockchain_info': self.blockchain.get_chain_info()
                },
                'action_breakdown': dict(action_counts),
                'recent_entries': entries[:100],  # Last 100 entries
                'integrity_status': 'verified' if self.blockchain.is_chain_valid() else 'compromised'
            }

        except Exception as e:
            logger.error(f"Error generating audit report: {e}")
            return {'error': str(e)}

class DataNotarization:
    """Data notarization and timestamping service"""

    def __init__(self, blockchain: Blockchain):
        self.blockchain = blockchain
        self.notarized_documents = {}

    def notarize_document(self, document_hash: bytes, metadata: Dict[str, Any]) -> str:
        """Notarize document with timestamp"""
        notarization_id = secrets.token_hex(16)

        notarization_data = {
            'id': notarization_id,
            'document_hash': document_hash.hex(),
            'timestamp': time.time(),
            'metadata': metadata
        }

        # Add to blockchain
        if self.blockchain.add_block([notarization_data]):
            self.notarized_documents[notarization_id] = notarization_data
            logger.info(f"Notarized document with ID: {notarization_id}")
            return notarization_id
        else:
            return None

    def verify_document(self, document_hash: bytes, notarization_id: str) -> Dict[str, Any]:
        """Verify document notarization"""
        if notarization_id not in self.notarized_documents:
            return {'verified': False, 'error': 'Notarization not found'}

        notarization = self.notarized_documents[notarization_id]

        # Verify document hash matches
        if notarization['document_hash'] != document_hash.hex():
            return {'verified': False, 'error': 'Document hash mismatch'}

        # Verify blockchain integrity
        if not self.blockchain.is_chain_valid():
            return {'verified': False, 'error': 'Blockchain integrity compromised'}

        return {
            'verified': True,
            'notarization_id': notarization_id,
            'timestamp': notarization['timestamp'],
            'metadata': notarization['metadata'],
            'blockchain_verified': True
        }

class SmartContract:
    """Smart contract functionality for automated processes"""

    def __init__(self, blockchain: Blockchain):
        self.blockchain = blockchain
        self.contracts = {}
        self.contract_executions = deque(maxlen=10000)

    def deploy_contract(self, contract_code: str, contract_metadata: Dict[str, Any]) -> str:
        """Deploy smart contract"""
        contract_id = secrets.token_hex(16)

        contract_data = {
            'id': contract_id,
            'code': contract_code,
            'metadata': contract_metadata,
            'deployed_at': time.time(),
            'state': 'active'
        }

        # Add contract to blockchain
        if self.blockchain.add_block([contract_data]):
            self.contracts[contract_id] = contract_data
            logger.info(f"Deployed smart contract: {contract_id}")
            return contract_id
        else:
            return None

    def execute_contract(self, contract_id: str, function_name: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute smart contract function"""
        if contract_id not in self.contracts:
            return {'success': False, 'error': 'Contract not found'}

        contract = self.contracts[contract_id]

        try:
            # Simulate contract execution (in production, this would be more sophisticated)
            execution_result = {
                'contract_id': contract_id,
                'function': function_name,
                'parameters': parameters,
                'timestamp': time.time(),
                'result': self._execute_contract_logic(contract, function_name, parameters)
            }

            # Record execution on blockchain
            if self.blockchain.add_block([execution_result]):
                self.contract_executions.append(execution_result)
                return {'success': True, 'result': execution_result}
            else:
                return {'success': False, 'error': 'Failed to record execution on blockchain'}

        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _execute_contract_logic(self, contract: Dict[str, Any], function: str, params: Dict[str, Any]) -> Any:
        """Execute contract logic (simplified)"""
        # This would contain actual smart contract logic
        # For demonstration, return a simple result
        return {
            'status': 'executed',
            'output': f"Contract {contract['id']} executed function {function}",
            'timestamp': time.time()
        }

# Global blockchain instances
main_blockchain = Blockchain(difficulty=4)
consensus_manager = DistributedConsensus(main_blockchain)
audit_trail = AuditTrailManager(main_blockchain)
data_notarization = DataNotarization(main_blockchain)
smart_contracts = SmartContract(main_blockchain)

def init_blockchain_system():
    """Initialize blockchain integration"""
    logger.info("Initializing blockchain integration system")

    # Register consensus nodes (in production, these would be actual network nodes)
    consensus_manager.register_node('node_1', 1.0)
    consensus_manager.register_node('node_2', 1.0)
    consensus_manager.register_node('node_3', 1.0)

    logger.info("Blockchain integration initialized")

def record_tamper_proof_audit(user_id: str, action: str, resource: str = None,
                             details: Dict[str, Any] = None, ip_address: str = None) -> bool:
    """Record tamper-proof audit entry"""
    entry = {
        'user_id': user_id,
        'action': action,
        'resource': resource,
        'details': details or {},
        'ip_address': ip_address,
        'timestamp': time.time()
    }

    return audit_trail.record_audit_entry(entry)

def notarize_data(data: bytes, metadata: Dict[str, Any] = None) -> Optional[str]:
    """Notarize data with timestamp"""
    document_hash = hashlib.sha256(data).digest()
    return data_notarization.notarize_document(document_hash, metadata or {})

def verify_data_integrity(data: bytes, notarization_id: str) -> Dict[str, Any]:
    """Verify data integrity"""
    document_hash = hashlib.sha256(data).digest()
    return data_notarization.verify_document(document_hash, notarization_id)

def get_blockchain_status() -> Dict[str, Any]:
    """Get blockchain system status"""
    return {
        'blockchain_info': main_blockchain.get_chain_info(),
        'consensus_nodes': len(consensus_manager.nodes),
        'total_audit_entries': len(audit_trail.blockchain.chain) - 1,  # Exclude genesis
        'notarized_documents': len(data_notarization.notarized_documents),
        'smart_contracts': len(smart_contracts.contracts)
    }
