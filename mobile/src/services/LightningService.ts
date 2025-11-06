/**
 * Lightning Network Service
 * Handles all Lightning Network operations and API communication
 */

import AsyncStorage from '@react-native-async-storage/async-storage';
import io, { Socket } from 'socket.io-client';
import CryptoJS from 'react-native-crypto-js';

import { ApiClient } from './ApiClient';
import { CryptoService } from './CryptoService';
import { NotificationService } from './NotificationService';

export interface LightningNode {
  id: string;
  alias: string;
  pubkey: string;
  color: string;
  address: string;
  port: number;
  status: 'online' | 'offline' | 'syncing' | 'error';
  version: string;
  network: 'mainnet' | 'testnet' | 'regtest';
  blockHeight: number;
  syncedToChain: boolean;
  balance: {
    confirmed: number;
    unconfirmed: number;
    total: number;
  };
  channels: {
    active: number;
    pending: number;
    inactive: number;
    total: number;
  };
  peers: number;
  createdAt: string;
  updatedAt: string;
}

export interface LightningChannel {
  id: string;
  channelId: string;
  fundingTxId: string;
  nodeId: string;
  remotePubkey: string;
  remoteAlias: string;
  capacity: number;
  localBalance: number;
  remoteBalance: number;
  status: 'open' | 'pending_open' | 'pending_close' | 'force_close' | 'closed';
  isActive: boolean;
  isPrivate: boolean;
  feeRate: number;
  baseFee: number;
  csvDelay: number;
  minHtlcMsat: number;
  maxHtlcMsat: number;
  totalSatoshisSent: number;
  totalSatoshisReceived: number;
  numUpdates: number;
  createdAt: string;
  updatedAt: string;
}

export interface LightningPayment {
  id: string;
  paymentHash: string;
  paymentPreimage?: string;
  amount: number;
  fee: number;
  description: string;
  destination: string;
  status: 'pending' | 'succeeded' | 'failed' | 'cancelled';
  failureReason?: string;
  creationDate: string;
  settleDate?: string;
  paymentRequest?: string;
  htlcs: any[];
}

export interface LightningInvoice {
  id: string;
  paymentHash: string;
  paymentRequest: string;
  amount: number;
  description: string;
  memo: string;
  expiry: number;
  status: 'open' | 'settled' | 'cancelled' | 'expired';
  settled: boolean;
  settleDate?: string;
  amountPaid?: number;
  createdAt: string;
  expiresAt: string;
}

export interface SendPaymentRequest {
  paymentRequest?: string;
  destination?: string;
  amount: number;
  description?: string;
  feeLimit?: number;
  timeoutSeconds?: number;
}

export interface CreateInvoiceRequest {
  amount: number;
  description: string;
  memo?: string;
  expiry?: number;
}

export interface OpenChannelRequest {
  nodePubkey: string;
  localFundingAmount: number;
  pushSat?: number;
  targetConf?: number;
  satPerByte?: number;
  private?: boolean;
  minHtlcMsat?: number;
  remoteCsvDelay?: number;
}

export class LightningService {
  private static instance: LightningService;
  private apiClient: ApiClient;
  private socket: Socket | null = null;
  private isConnected = false;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private eventListeners: Map<string, Set<Function>> = new Map();

  private constructor() {
    this.apiClient = ApiClient.getInstance();
  }

  public static getInstance(): LightningService {
    if (!LightningService.instance) {
      LightningService.instance = new LightningService();
    }
    return LightningService.instance;
  }

  public static async initialize(): Promise<void> {
    const service = LightningService.getInstance();
    await service.connect();
  }

  public async connect(): Promise<void> {
    try {
      const baseUrl = await this.apiClient.getBaseUrl();
      const token = await this.apiClient.getAuthToken();

      if (!token) {
        throw new Error('No authentication token available');
      }

      this.socket = io(`${baseUrl}`, {
        auth: { token },
        transports: ['websocket'],
        reconnection: true,
        reconnectionDelay: 2000,
        reconnectionAttempts: this.maxReconnectAttempts,
      });

      this.setupSocketListeners();
      this.isConnected = true;

    } catch (error) {
      console.error('Failed to connect to Lightning service:', error);
      throw error;
    }
  }

  public disconnect(): void {
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
    }
    this.isConnected = false;
    this.reconnectAttempts = 0;
  }

  private setupSocketListeners(): void {
    if (!this.socket) return;

    this.socket.on('connect', () => {
      console.log('Connected to Lightning service');
      this.isConnected = true;
      this.reconnectAttempts = 0;
      this.emit('connection', { status: 'connected' });
    });

    this.socket.on('disconnect', () => {
      console.log('Disconnected from Lightning service');
      this.isConnected = false;
      this.emit('connection', { status: 'disconnected' });
    });

    this.socket.on('connect_error', (error) => {
      console.error('Connection error:', error);
      this.reconnectAttempts++;
      this.emit('connection', {
        status: 'error',
        error: error.message,
        attempts: this.reconnectAttempts
      });
    });

    // Lightning Network events
    this.socket.on('node_status_changed', (data) => {
      this.emit('nodeStatusChanged', data);
    });

    this.socket.on('channel_opened', (data) => {
      this.emit('channelOpened', data);
      NotificationService.showNotification(
        'Channel Opened',
        `Channel with ${data.remoteAlias} is now active`
      );
    });

    this.socket.on('channel_closed', (data) => {
      this.emit('channelClosed', data);
      NotificationService.showNotification(
        'Channel Closed',
        `Channel with ${data.remoteAlias} has been closed`
      );
    });

    this.socket.on('payment_received', (data) => {
      this.emit('paymentReceived', data);
      NotificationService.showNotification(
        'Payment Received',
        `Received ${data.amount} sats`
      );
    });

    this.socket.on('payment_sent', (data) => {
      this.emit('paymentSent', data);
      NotificationService.showNotification(
        'Payment Sent',
        `Sent ${data.amount} sats successfully`
      );
    });

    this.socket.on('payment_failed', (data) => {
      this.emit('paymentFailed', data);
      NotificationService.showNotification(
        'Payment Failed',
        `Payment of ${data.amount} sats failed: ${data.reason}`
      );
    });

    this.socket.on('invoice_settled', (data) => {
      this.emit('invoiceSettled', data);
    });

    this.socket.on('balance_updated', (data) => {
      this.emit('balanceUpdated', data);
    });
  }

  public on(event: string, listener: Function): void {
    if (!this.eventListeners.has(event)) {
      this.eventListeners.set(event, new Set());
    }
    this.eventListeners.get(event)!.add(listener);
  }

  public off(event: string, listener: Function): void {
    const listeners = this.eventListeners.get(event);
    if (listeners) {
      listeners.delete(listener);
    }
  }

  private emit(event: string, data: any): void {
    const listeners = this.eventListeners.get(event);
    if (listeners) {
      listeners.forEach(listener => listener(data));
    }
  }

  // Node Management
  public async getNodes(): Promise<LightningNode[]> {
    try {
      const response = await this.apiClient.get('/lightning/nodes');
      return response.data;
    } catch (error) {
      console.error('Failed to get nodes:', error);
      throw error;
    }
  }

  public async getNode(nodeId: string): Promise<LightningNode> {
    try {
      const response = await this.apiClient.get(`/lightning/nodes/${nodeId}`);
      return response.data;
    } catch (error) {
      console.error('Failed to get node:', error);
      throw error;
    }
  }

  public async createNode(config: any): Promise<LightningNode> {
    try {
      const response = await this.apiClient.post('/lightning/nodes', config);
      return response.data;
    } catch (error) {
      console.error('Failed to create node:', error);
      throw error;
    }
  }

  public async startNode(nodeId: string): Promise<void> {
    try {
      await this.apiClient.post(`/lightning/nodes/${nodeId}/start`);
    } catch (error) {
      console.error('Failed to start node:', error);
      throw error;
    }
  }

  public async stopNode(nodeId: string): Promise<void> {
    try {
      await this.apiClient.post(`/lightning/nodes/${nodeId}/stop`);
    } catch (error) {
      console.error('Failed to stop node:', error);
      throw error;
    }
  }

  public async deleteNode(nodeId: string): Promise<void> {
    try {
      await this.apiClient.delete(`/lightning/nodes/${nodeId}`);
    } catch (error) {
      console.error('Failed to delete node:', error);
      throw error;
    }
  }

  // Channel Management
  public async getChannels(nodeId: string): Promise<LightningChannel[]> {
    try {
      const response = await this.apiClient.get(`/lightning/nodes/${nodeId}/channels`);
      return response.data;
    } catch (error) {
      console.error('Failed to get channels:', error);
      throw error;
    }
  }

  public async getChannel(nodeId: string, channelId: string): Promise<LightningChannel> {
    try {
      const response = await this.apiClient.get(`/lightning/nodes/${nodeId}/channels/${channelId}`);
      return response.data;
    } catch (error) {
      console.error('Failed to get channel:', error);
      throw error;
    }
  }

  public async openChannel(nodeId: string, request: OpenChannelRequest): Promise<LightningChannel> {
    try {
      const response = await this.apiClient.post(`/lightning/nodes/${nodeId}/channels`, request);
      return response.data;
    } catch (error) {
      console.error('Failed to open channel:', error);
      throw error;
    }
  }

  public async closeChannel(nodeId: string, channelId: string, force: boolean = false): Promise<void> {
    try {
      await this.apiClient.post(`/lightning/nodes/${nodeId}/channels/${channelId}/close`, { force });
    } catch (error) {
      console.error('Failed to close channel:', error);
      throw error;
    }
  }

  // Payment Operations
  public async sendPayment(nodeId: string, request: SendPaymentRequest): Promise<LightningPayment> {
    try {
      const response = await this.apiClient.post(`/lightning/nodes/${nodeId}/payments`, request);
      return response.data;
    } catch (error) {
      console.error('Failed to send payment:', error);
      throw error;
    }
  }

  public async getPayments(nodeId: string): Promise<LightningPayment[]> {
    try {
      const response = await this.apiClient.get(`/lightning/nodes/${nodeId}/payments`);
      return response.data;
    } catch (error) {
      console.error('Failed to get payments:', error);
      throw error;
    }
  }

  public async getPayment(nodeId: string, paymentHash: string): Promise<LightningPayment> {
    try {
      const response = await this.apiClient.get(`/lightning/nodes/${nodeId}/payments/${paymentHash}`);
      return response.data;
    } catch (error) {
      console.error('Failed to get payment:', error);
      throw error;
    }
  }

  public async cancelPayment(nodeId: string, paymentHash: string): Promise<void> {
    try {
      await this.apiClient.post(`/lightning/nodes/${nodeId}/payments/${paymentHash}/cancel`);
    } catch (error) {
      console.error('Failed to cancel payment:', error);
      throw error;
    }
  }

  // Invoice Management
  public async createInvoice(nodeId: string, request: CreateInvoiceRequest): Promise<LightningInvoice> {
    try {
      const response = await this.apiClient.post(`/lightning/nodes/${nodeId}/invoices`, request);
      return response.data;
    } catch (error) {
      console.error('Failed to create invoice:', error);
      throw error;
    }
  }

  public async getInvoices(nodeId: string): Promise<LightningInvoice[]> {
    try {
      const response = await this.apiClient.get(`/lightning/nodes/${nodeId}/invoices`);
      return response.data;
    } catch (error) {
      console.error('Failed to get invoices:', error);
      throw error;
    }
  }

  public async getInvoice(nodeId: string, paymentHash: string): Promise<LightningInvoice> {
    try {
      const response = await this.apiClient.get(`/lightning/nodes/${nodeId}/invoices/${paymentHash}`);
      return response.data;
    } catch (error) {
      console.error('Failed to get invoice:', error);
      throw error;
    }
  }

  public async cancelInvoice(nodeId: string, paymentHash: string): Promise<void> {
    try {
      await this.apiClient.post(`/lightning/nodes/${nodeId}/invoices/${paymentHash}/cancel`);
    } catch (error) {
      console.error('Failed to cancel invoice:', error);
      throw error;
    }
  }

  // Wallet Operations
  public async getBalance(nodeId: string): Promise<any> {
    try {
      const response = await this.apiClient.get(`/lightning/nodes/${nodeId}/balance`);
      return response.data;
    } catch (error) {
      console.error('Failed to get balance:', error);
      throw error;
    }
  }

  public async getTransactions(nodeId: string): Promise<any[]> {
    try {
      const response = await this.apiClient.get(`/lightning/nodes/${nodeId}/transactions`);
      return response.data;
    } catch (error) {
      console.error('Failed to get transactions:', error);
      throw error;
    }
  }

  public async generateAddress(nodeId: string, type: 'p2wkh' | 'np2wkh' = 'p2wkh'): Promise<string> {
    try {
      const response = await this.apiClient.post(`/lightning/nodes/${nodeId}/address`, { type });
      return response.data.address;
    } catch (error) {
      console.error('Failed to generate address:', error);
      throw error;
    }
  }

  // Utility Methods
  public async decodePaymentRequest(paymentRequest: string): Promise<any> {
    try {
      const response = await this.apiClient.post('/lightning/decode', { paymentRequest });
      return response.data;
    } catch (error) {
      console.error('Failed to decode payment request:', error);
      throw error;
    }
  }

  public async getNetworkInfo(): Promise<any> {
    try {
      const response = await this.apiClient.get('/lightning/network');
      return response.data;
    } catch (error) {
      console.error('Failed to get network info:', error);
      throw error;
    }
  }

  public async searchNodes(query: string): Promise<any[]> {
    try {
      const response = await this.apiClient.get(`/lightning/search/nodes?q=${encodeURIComponent(query)}`);
      return response.data;
    } catch (error) {
      console.error('Failed to search nodes:', error);
      throw error;
    }
  }

  // Cache Management
  public async cacheNodeData(nodeId: string, data: any): Promise<void> {
    try {
      const encryptedData = await CryptoService.encrypt(JSON.stringify(data));
      await AsyncStorage.setItem(`node_cache_${nodeId}`, encryptedData);
    } catch (error) {
      console.error('Failed to cache node data:', error);
    }
  }

  public async getCachedNodeData(nodeId: string): Promise<any | null> {
    try {
      const encryptedData = await AsyncStorage.getItem(`node_cache_${nodeId}`);
      if (encryptedData) {
        const decryptedData = await CryptoService.decrypt(encryptedData);
        return JSON.parse(decryptedData);
      }
      return null;
    } catch (error) {
      console.error('Failed to get cached node data:', error);
      return null;
    }
  }

  public async clearCache(): Promise<void> {
    try {
      const keys = await AsyncStorage.getAllKeys();
      const cacheKeys = keys.filter(key => key.startsWith('node_cache_'));
      await AsyncStorage.multiRemove(cacheKeys);
    } catch (error) {
      console.error('Failed to clear cache:', error);
    }
  }

  // Connection Status
  public isServiceConnected(): boolean {
    return this.isConnected && this.socket?.connected === true;
  }

  public getConnectionStatus(): string {
    if (!this.socket) return 'disconnected';
    if (this.socket.connected) return 'connected';
    if (this.socket.disconnected) return 'disconnected';
    return 'connecting';
  }
}

export default LightningService;