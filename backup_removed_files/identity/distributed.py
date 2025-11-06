"""
Distributed Identity Framework for BLNCS Enterprise
Provides self-sovereign identity management, decentralized identifiers, and verifiable credentials
"""

import hashlib
import secrets
import time
import json
import threading
from typing import Dict, List, Optional, Any, Tuple
from collections import defaultdict, deque
from datetime import datetime, timedelta
import base64
import logging
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)

class DecentralizedIdentifier:
    """Decentralized Identifier (DID) implementation"""

    def __init__(self, did_string: str):
        self.did = did_string
        self.method = did_string.split(':')[1] if ':' in did_string else 'unknown'
        self.identifier = did_string.split(':')[-1] if ':' in did_string else did_string

    def to_dict(self) -> Dict[str, str]:
        """Convert DID to dictionary representation"""
        return {
            'did': self.did,
            'method': self.method,
            'identifier': self.identifier
        }

class DIDRegistry:
    """Decentralized Identifier registry"""

    def __init__(self):
        self.dids = {}
        self.did_documents = {}
        self.resolvers = {}
        self.lock = threading.Lock()

    def register_did(self, did: str, document: Dict[str, Any], private_key_pem: bytes) -> bool:
        """Register DID with associated document"""
        try:
            with self.lock:
                self.dids[did] = {
                    'document': document,
                    'registered_at': time.time(),
                    'status': 'active'
                }

                self.did_documents[did] = document

                logger.info(f"Registered DID: {did}")
                return True

        except Exception as e:
            logger.error(f"Failed to register DID {did}: {e}")
            return False

    def resolve_did(self, did: str) -> Optional[Dict[str, Any]]:
        """Resolve DID to DID document"""
        with self.lock:
            if did in self.dids:
                entry = self.dids[did]
                if entry['status'] == 'active':
                    return entry['document']

        return None

    def update_did_document(self, did: str, updates: Dict[str, Any],
                           signature: bytes) -> bool:
        """Update DID document with signature verification"""
        with self.lock:
            if did not in self.dids:
                return False

            # Verify signature (simplified)
            current_doc = self.dids[did]['document']
            if self._verify_document_signature(current_doc, updates, signature):
                # Apply updates
                self._apply_document_updates(current_doc, updates)
                self.dids[did]['document'] = current_doc
                self.did_documents[did] = current_doc

                logger.info(f"Updated DID document: {did}")
                return True

        return False

    def _verify_document_signature(self, current_doc: Dict[str, Any],
                                  updates: Dict[str, Any], signature: bytes) -> bool:
        """Verify DID document update signature"""
        # Simplified signature verification
        # In production, use proper cryptographic verification
        doc_hash = hashlib.sha256(json.dumps(current_doc, sort_keys=True).encode()).digest()
        update_hash = hashlib.sha256(json.dumps(updates, sort_keys=True).encode()).digest()

        combined = doc_hash + update_hash
        expected_signature = hashlib.sha256(combined).digest()

        return signature == expected_signature

    def _apply_document_updates(self, document: Dict[str, Any], updates: Dict[str, Any]):
        """Apply updates to DID document"""
        for key, value in updates.items():
            if key == 'remove':
                # Remove specified keys
                for remove_key in value:
                    if remove_key in document:
                        del document[remove_key]
            else:
                # Update/add key
                document[key] = value

class VerifiableCredential:
    """Verifiable Credential implementation"""

    def __init__(self, credential_data: Dict[str, Any]):
        self.credential = credential_data
        self.issuer = credential_data.get('issuer', '')
        self.subject = credential_data.get('credentialSubject', {})
        self.issuance_date = credential_data.get('issuanceDate', '')
        self.expiration_date = credential_data.get('expirationDate', '')
        self.proof = credential_data.get('proof', {})

    def verify(self, issuer_public_key: bytes) -> bool:
        """Verify credential authenticity"""
        try:
            # Extract proof
            proof = self.proof
            if not proof:
                return False

            # Reconstruct credential without proof
            credential_copy = self.credential.copy()
            del credential_copy['proof']

            # Create canonical form
            canonical_credential = json.dumps(credential_copy, sort_keys=True, separators=(',', ':'))

            # Verify signature
            credential_hash = hashlib.sha256(canonical_credential.encode()).digest()

            # In production, verify actual cryptographic signature
            # For simulation, use hash comparison
            proof_hash = hashlib.sha256((credential_hash + issuer_public_key).hex().encode()).hexdigest()

            return proof.get('signatureValue', '').startswith(proof_hash[:16])

        except Exception as e:
            logger.error(f"Credential verification failed: {e}")
            return False

class CredentialWallet:
    """Digital wallet for storing and managing verifiable credentials"""

    def __init__(self, owner_did: str):
        self.owner_did = owner_did
        self.credentials = {}
        self.credential_index = defaultdict(list)
        self.lock = threading.Lock()

    def store_credential(self, credential_id: str, credential: VerifiableCredential) -> bool:
        """Store verifiable credential in wallet"""
        try:
            with self.lock:
                self.credentials[credential_id] = {
                    'credential': credential.credential,
                    'stored_at': time.time(),
                    'status': 'active'
                }

                # Update index
                subject_id = credential.subject.get('id', '')
                if subject_id:
                    self.credential_index[subject_id].append(credential_id)

                credential_type = credential.credential.get('type', [])
                for cred_type in credential_type:
                    if cred_type != 'VerifiableCredential':
                        self.credential_index[cred_type].append(credential_id)

                logger.info(f"Stored credential {credential_id} in wallet {self.owner_did}")
                return True

        except Exception as e:
            logger.error(f"Failed to store credential: {e}")
            return False

    def get_credentials_by_type(self, credential_type: str) -> List[Dict[str, Any]]:
        """Get credentials by type"""
        with self.lock:
            credential_ids = self.credential_index.get(credential_type, [])
            return [self.credentials[cid] for cid in credential_ids
                   if cid in self.credentials and self.credentials[cid]['status'] == 'active']

    def present_credentials(self, required_claims: List[str],
                           verifier_did: str) -> Dict[str, Any]:
        """Present credentials for verification"""
        with self.lock:
            presentation = {
                'holder': self.owner_did,
                'verifier': verifier_did,
                'credentials': [],
                'timestamp': time.time()
            }

            # Find matching credentials
            for claim in required_claims:
                matching_credentials = self._find_credentials_for_claim(claim)
                presentation['credentials'].extend(matching_credentials)

            return presentation

    def _find_credentials_for_claim(self, claim: str) -> List[Dict[str, Any]]:
        """Find credentials that satisfy claim"""
        # Simplified claim matching
        # In production, use sophisticated claim matching algorithms
        matching = []

        for cred_id, cred_data in self.credentials.items():
            if cred_data['status'] == 'active':
                credential = cred_data['credential']
                subject = credential.get('credentialSubject', {})

                # Check if credential contains required claim
                if claim in str(subject):
                    matching.append(credential)

        return matching

class SelfSovereignIdentity:
    """Self-sovereign identity management system"""

    def __init__(self):
        self.did_registry = DIDRegistry()
        self.credential_schemas = {}
        self.identity_hubs = {}
        self.consent_records = {}
        self.lock = threading.Lock()

    def create_identity(self, user_info: Dict[str, Any]) -> Tuple[str, bytes]:
        """Create self-sovereign identity"""
        # Generate DID
        did_method = 'blncs'
        timestamp = str(int(time.time()))
        random_suffix = secrets.token_hex(8)
        did = f"did:{did_method}:{timestamp}:{random_suffix}"

        # Generate keypair
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        # Create DID document
        did_document = {
            '@context': 'https://www.w3.org/ns/did/v1',
            'id': did,
            'verificationMethod': [{
                'id': f'{did}#keys-1',
                'type': 'Ed25519VerificationKey2020',
                'controller': did,
                'publicKeyMultibase': self._encode_public_key(public_key)
            }],
            'authentication': [f'{did}#keys-1'],
            'created': datetime.now().isoformat()
        }

        # Register DID
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        if self.did_registry.register_did(did, did_document, private_key_pem):
            logger.info(f"Created self-sovereign identity: {did}")
            return did, private_key_pem

        return None, None

    def _encode_public_key(self, public_key) -> str:
        """Encode public key in multibase format"""
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        # Simplified multibase encoding
        return base64.b64encode(public_bytes).decode()

    def issue_credential(self, issuer_did: str, subject_did: str,
                        credential_data: Dict[str, Any], issuer_private_key: bytes) -> str:
        """Issue verifiable credential"""
        credential_id = f"credential_{secrets.token_hex(16)}"

        # Load issuer private key
        private_key = serialization.load_pem_private_key(issuer_private_key, password=None)

        # Create credential
        credential = {
            '@context': ['https://www.w3.org/2018/credentials/v1'],
            'id': credential_id,
            'type': ['VerifiableCredential'],
            'issuer': issuer_did,
            'issuanceDate': datetime.now().isoformat(),
            'credentialSubject': {
                'id': subject_did,
                **credential_data
            }
        }

        # Create proof
        credential_copy = credential.copy()
        canonical_credential = json.dumps(credential_copy, sort_keys=True, separators=(',', ':'))
        credential_hash = hashlib.sha256(canonical_credential.encode()).digest()

        # Sign credential
        signature = private_key.sign(credential_hash)

        credential['proof'] = {
            'type': 'Ed25519Signature2020',
            'created': datetime.now().isoformat(),
            'verificationMethod': f'{issuer_did}#keys-1',
            'signatureValue': base64.b64encode(signature).decode()
        }

        vc = VerifiableCredential(credential)

        # Store in subject's wallet (simplified)
        # In production, this would be stored in the subject's identity hub
        logger.info(f"Issued credential {credential_id} from {issuer_did} to {subject_did}")

        return credential_id

    def verify_presentation(self, presentation: Dict[str, Any],
                           verifier_did: str) -> Dict[str, Any]:
        """Verify credential presentation"""
        verification_result = {
            'valid': True,
            'verified_credentials': [],
            'failed_credentials': [],
            'warnings': []
        }

        credentials = presentation.get('credentials', [])

        for credential_data in credentials:
            try:
                vc = VerifiableCredential(credential_data)

                # Get issuer's public key from DID document
                issuer_did = vc.issuer
                issuer_document = self.did_registry.resolve_did(issuer_did)

                if not issuer_document:
                    verification_result['failed_credentials'].append({
                        'credential_id': credential_data.get('id', 'unknown'),
                        'reason': 'Issuer DID not found'
                    })
                    verification_result['valid'] = False
                    continue

                # Extract public key from DID document
                public_key_data = issuer_document.get('verificationMethod', [{}])[0]
                if 'publicKeyMultibase' not in public_key_data:
                    verification_result['failed_credentials'].append({
                        'credential_id': credential_data.get('id', 'unknown'),
                        'reason': 'Public key not found in DID document'
                    })
                    verification_result['valid'] = False
                    continue

                # Decode public key
                public_key_pem = base64.b64decode(public_key_data['publicKeyMultibase'])

                # Verify credential
                if vc.verify(public_key_pem):
                    verification_result['verified_credentials'].append(credential_data)
                else:
                    verification_result['failed_credentials'].append({
                        'credential_id': credential_data.get('id', 'unknown'),
                        'reason': 'Signature verification failed'
                    })
                    verification_result['valid'] = False

            except Exception as e:
                verification_result['failed_credentials'].append({
                    'credential_id': credential_data.get('id', 'unknown'),
                    'reason': f'Verification error: {str(e)}'
                })
                verification_result['valid'] = False

        return verification_result

    def manage_consent(self, subject_did: str, data_processor_did: str,
                      consent_data: Dict[str, Any]) -> str:
        """Manage data consent and preferences"""
        consent_id = f"consent_{secrets.token_hex(16)}"

        consent_record = {
            'id': consent_id,
            'subject': subject_did,
            'data_processor': data_processor_did,
            'consent_given': consent_data.get('consent_given', True),
            'data_types': consent_data.get('data_types', []),
            'purposes': consent_data.get('purposes', []),
            'granted_at': time.time(),
            'expires_at': consent_data.get('expires_at', time.time() + 365 * 24 * 3600),  # 1 year
            'withdrawn': False,
            'withdrawal_reason': None
        }

        with self.lock:
            self.consent_records[consent_id] = consent_record

        logger.info(f"Recorded consent {consent_id} for {subject_did}")
        return consent_id

    def check_consent(self, subject_did: str, data_processor_did: str,
                     data_type: str) -> bool:
        """Check if consent exists for data processing"""
        with self.lock:
            for consent_id, consent in self.consent_records.items():
                if (consent['subject'] == subject_did and
                    consent['data_processor'] == data_processor_did and
                    not consent['withdrawn'] and
                    time.time() < consent['expires_at']):

                    if data_type in consent['data_types']:
                        return True

        return False

class IdentityHub:
    """Personal data store and identity hub"""

    def __init__(self, owner_did: str):
        self.owner_did = owner_did
        self.personal_data = {}
        self.connections = {}
        self.data_sharing_agreements = {}
        self.lock = threading.Lock()

    def store_personal_data(self, data_category: str, data: Dict[str, Any],
                           encryption_key: bytes) -> str:
        """Store personal data with encryption"""
        data_id = f"data_{secrets.token_hex(16)}"

        # Encrypt data
        data_json = json.dumps(data)
        encrypted_data = self._encrypt_data(data_json.encode(), encryption_key)

        with self.lock:
            self.personal_data[data_id] = {
                'category': data_category,
                'data': encrypted_data,
                'stored_at': time.time(),
                'encryption_key_hash': hashlib.sha256(encryption_key).hexdigest()
            }

        logger.info(f"Stored personal data {data_id} in hub {self.owner_did}")
        return data_id

    def _encrypt_data(self, data: bytes, key: bytes) -> bytes:
        """Encrypt data using symmetric encryption"""
        # Simplified encryption - in production, use proper AEAD
        combined = data + key
        return hashlib.sha3_512(combined).digest()

    def retrieve_personal_data(self, data_id: str, decryption_key: bytes) -> Optional[Dict[str, Any]]:
        """Retrieve and decrypt personal data"""
        with self.lock:
            if data_id not in self.personal_data:
                return None

            data_entry = self.personal_data[data_id]

            # Verify decryption key
            if hashlib.sha256(decryption_key).hexdigest() != data_entry['encryption_key_hash']:
                return None

            # Decrypt data
            decrypted_data = self._decrypt_data(data_entry['data'], decryption_key)

            try:
                return json.loads(decrypted_data)
            except:
                return None

    def _decrypt_data(self, encrypted_data: bytes, key: bytes) -> bytes:
        """Decrypt data"""
        # Simplified decryption - reverse of encryption
        # In production, use proper decryption
        return encrypted_data  # Placeholder

    def create_connection(self, connection_did: str, connection_data: Dict[str, Any]) -> str:
        """Create connection with another identity"""
        connection_id = f"connection_{secrets.token_hex(16)}"

        connection = {
            'id': connection_id,
            'connected_did': connection_did,
            'connection_data': connection_data,
            'created_at': time.time(),
            'status': 'active'
        }

        with self.lock:
            self.connections[connection_id] = connection

        logger.info(f"Created connection {connection_id} between {self.owner_did} and {connection_did}")
        return connection_id

class DistributedIdentityManager:
    """Main distributed identity management system"""

    def __init__(self):
        self.ssi_system = SelfSovereignIdentity()
        self.identity_hubs = {}
        self.data_processors = {}
        self.identity_governance = {}
        self.lock = threading.Lock()

    def create_user_identity(self, user_info: Dict[str, Any]) -> Tuple[Optional[str], Optional[bytes]]:
        """Create complete identity for user"""
        # Create self-sovereign identity
        did, private_key = self.ssi_system.create_identity(user_info)

        if did and private_key:
            # Create identity hub
            hub = IdentityHub(did)
            with self.lock:
                self.identity_hubs[did] = hub

            logger.info(f"Created complete identity for user: {did}")
            return did, private_key

        return None, None

    def issue_identity_credential(self, issuer_did: str, subject_did: str,
                                 credential_type: str, credential_data: Dict[str, Any],
                                 issuer_private_key: bytes) -> Optional[str]:
        """Issue identity-related credential"""
        # Get issuer's private key for signing
        # In production, this would be securely managed

        return self.ssi_system.issue_credential(issuer_did, subject_did, {
            'type': credential_type,
            **credential_data
        }, issuer_private_key)

    def verify_identity_claims(self, subject_did: str, required_claims: List[str],
                              verifier_did: str) -> Dict[str, Any]:
        """Verify identity claims and credentials"""
        # Get subject's identity hub
        if subject_did not in self.identity_hubs:
            return {'valid': False, 'error': 'Identity hub not found'}

        hub = self.identity_hubs[subject_did]

        # Create credential presentation
        presentation = hub.wallet.present_credentials(required_claims, verifier_did)

        # Verify presentation
        return self.ssi_system.verify_presentation(presentation, verifier_did)

    def manage_data_consent(self, subject_did: str, processor_did: str,
                           consent_info: Dict[str, Any]) -> Optional[str]:
        """Manage data processing consent"""
        return self.ssi_system.manage_consent(subject_did, processor_did, consent_info)

    def check_data_processing_consent(self, subject_did: str, processor_did: str,
                                     data_type: str) -> bool:
        """Check if data processing is consented"""
        return self.ssi_system.check_consent(subject_did, processor_did, data_type)

    def get_identity_status(self, did: str) -> Dict[str, Any]:
        """Get comprehensive identity status"""
        with self.lock:
            hub = self.identity_hubs.get(did)
            did_document = self.ssi_system.did_registry.resolve_did(did)

        if not hub or not did_document:
            return {'error': 'Identity not found'}

        return {
            'did': did,
            'did_document': did_document,
            'hub_exists': True,
            'credentials_count': len(hub.wallet.credentials),
            'connections_count': len(hub.connections),
            'consent_records': len([c for c in self.ssi_system.consent_records.values()
                                   if c['subject'] == did])
        }

# Global distributed identity instances
distributed_identity = DistributedIdentityManager()

def init_distributed_identity():
    """Initialize distributed identity system"""
    logger.info("Initializing distributed identity system")

    # Register credential schemas
    distributed_identity.ssi_system.credential_schemas['identity_verification'] = {
        'type': 'IdentityVerificationCredential',
        'properties': {
            'givenName': {'type': 'string'},
            'familyName': {'type': 'string'},
            'birthDate': {'type': 'string', 'format': 'date'},
            'nationality': {'type': 'string'}
        }
    }

    distributed_identity.ssi_system.credential_schemas['access_credential'] = {
        'type': 'AccessCredential',
        'properties': {
            'clearanceLevel': {'type': 'string', 'enum': ['public', 'internal', 'confidential', 'secret']},
            'validFrom': {'type': 'string', 'format': 'date-time'},
            'validUntil': {'type': 'string', 'format': 'date-time'}
        }
    }

    logger.info("Distributed identity system initialized")

def create_user_identity(user_info: Dict[str, Any]) -> Tuple[Optional[str], Optional[bytes]]:
    """Create user identity"""
    return distributed_identity.create_user_identity(user_info)

def issue_credential(issuer_did: str, subject_did: str, credential_type: str,
                    credential_data: Dict[str, Any], issuer_private_key: bytes) -> Optional[str]:
    """Issue credential"""
    return distributed_identity.issue_identity_credential(issuer_did, subject_did, credential_type,
                                                          credential_data, issuer_private_key)

def verify_identity(did: str, required_claims: List[str], verifier_did: str) -> Dict[str, Any]:
    """Verify identity claims"""
    return distributed_identity.verify_identity_claims(did, required_claims, verifier_did)

def get_identity_status(did: str) -> Dict[str, Any]:
    """Get identity status"""
    return distributed_identity.get_identity_status(did)
