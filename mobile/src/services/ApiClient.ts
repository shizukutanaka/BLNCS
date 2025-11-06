/**
 * API Client Service
 * Handles HTTP requests to BLNCS backend with authentication and error handling
 */

import AsyncStorage from '@react-native-async-storage/async-storage';
import NetInfo from '@react-native-community/netinfo';
import { CryptoService } from './CryptoService';

export interface ApiConfig {
  baseUrl: string;
  timeout: number;
  retryAttempts: number;
  retryDelay: number;
}

export interface ApiResponse<T = any> {
  data: T;
  status: number;
  statusText: string;
  headers: Record<string, string>;
}

export interface ApiError {
  message: string;
  status?: number;
  code?: string;
  details?: any;
}

export class ApiClient {
  private static instance: ApiClient;
  private config: ApiConfig;
  private authToken: string | null = null;
  private refreshToken: string | null = null;
  private isRefreshing = false;
  private refreshPromise: Promise<string> | null = null;

  private constructor() {
    this.config = {
      baseUrl: 'https://api.blncs.local',
      timeout: 30000,
      retryAttempts: 3,
      retryDelay: 1000,
    };
    this.loadStoredTokens();
  }

  public static getInstance(): ApiClient {
    if (!ApiClient.instance) {
      ApiClient.instance = new ApiClient();
    }
    return ApiClient.instance;
  }

  public async configure(config: Partial<ApiConfig>): Promise<void> {
    this.config = { ...this.config, ...config };
    await AsyncStorage.setItem('api_config', JSON.stringify(this.config));
  }

  public async getBaseUrl(): Promise<string> {
    return this.config.baseUrl;
  }

  public async getAuthToken(): Promise<string | null> {
    return this.authToken;
  }

  private async loadStoredTokens(): Promise<void> {
    try {
      const [storedConfig, encryptedAuthToken, encryptedRefreshToken] = await Promise.all([
        AsyncStorage.getItem('api_config'),
        AsyncStorage.getItem('auth_token'),
        AsyncStorage.getItem('refresh_token'),
      ]);

      if (storedConfig) {
        this.config = { ...this.config, ...JSON.parse(storedConfig) };
      }

      if (encryptedAuthToken) {
        this.authToken = await CryptoService.decrypt(encryptedAuthToken);
      }

      if (encryptedRefreshToken) {
        this.refreshToken = await CryptoService.decrypt(encryptedRefreshToken);
      }
    } catch (error) {
      console.error('Failed to load stored tokens:', error);
    }
  }

  public async setAuthTokens(authToken: string, refreshToken?: string): Promise<void> {
    try {
      this.authToken = authToken;
      this.refreshToken = refreshToken || null;

      const encryptedAuthToken = await CryptoService.encrypt(authToken);
      await AsyncStorage.setItem('auth_token', encryptedAuthToken);

      if (refreshToken) {
        const encryptedRefreshToken = await CryptoService.encrypt(refreshToken);
        await AsyncStorage.setItem('refresh_token', encryptedRefreshToken);
      }
    } catch (error) {
      console.error('Failed to store auth tokens:', error);
      throw error;
    }
  }

  public async clearAuthTokens(): Promise<void> {
    try {
      this.authToken = null;
      this.refreshToken = null;
      await Promise.all([
        AsyncStorage.removeItem('auth_token'),
        AsyncStorage.removeItem('refresh_token'),
      ]);
    } catch (error) {
      console.error('Failed to clear auth tokens:', error);
    }
  }

  private async checkNetworkConnection(): Promise<boolean> {
    const netInfo = await NetInfo.fetch();
    return netInfo.isConnected === true && netInfo.isInternetReachable === true;
  }

  private async request<T = any>(
    method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH',
    endpoint: string,
    data?: any,
    headers: Record<string, string> = {},
    attemptNumber = 1
  ): Promise<ApiResponse<T>> {
    try {
      // Check network connectivity
      const isConnected = await this.checkNetworkConnection();
      if (!isConnected) {
        throw new ApiError('No internet connection available');
      }

      // Prepare URL
      const url = `${this.config.baseUrl}${endpoint}`;

      // Prepare headers
      const requestHeaders: Record<string, string> = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        ...headers,
      };

      // Add authentication header
      if (this.authToken) {
        requestHeaders['Authorization'] = `Bearer ${this.authToken}`;
      }

      // Prepare request options
      const requestOptions: RequestInit = {
        method,
        headers: requestHeaders,
        signal: AbortSignal.timeout(this.config.timeout),
      };

      if (data && method !== 'GET') {
        requestOptions.body = JSON.stringify(data);
      }

      // Make request
      const response = await fetch(url, requestOptions);

      // Handle authentication errors
      if (response.status === 401 && this.refreshToken && !this.isRefreshing) {
        const newToken = await this.refreshAuthToken();
        if (newToken) {
          // Retry with new token
          requestHeaders['Authorization'] = `Bearer ${newToken}`;
          return this.request(method, endpoint, data, headers, attemptNumber);
        }
      }

      // Parse response
      let responseData: T;
      const contentType = response.headers.get('content-type');

      if (contentType && contentType.includes('application/json')) {
        responseData = await response.json();
      } else {
        responseData = await response.text() as unknown as T;
      }

      // Handle HTTP errors
      if (!response.ok) {
        const error: ApiError = {
          message: responseData?.message || response.statusText || 'Request failed',
          status: response.status,
          code: responseData?.code,
          details: responseData,
        };
        throw error;
      }

      return {
        data: responseData,
        status: response.status,
        statusText: response.statusText,
        headers: this.parseHeaders(response.headers),
      };

    } catch (error) {
      // Handle network errors and retries
      if (
        attemptNumber < this.config.retryAttempts &&
        this.shouldRetry(error)
      ) {
        await this.delay(this.config.retryDelay * attemptNumber);
        return this.request(method, endpoint, data, headers, attemptNumber + 1);
      }

      // Convert to ApiError if needed
      if (!(error instanceof ApiError)) {
        throw new ApiError(
          error.message || 'Network request failed',
          error.status,
          error.code,
          error
        );
      }

      throw error;
    }
  }

  private shouldRetry(error: any): boolean {
    // Retry on network errors, timeouts, and 5xx status codes
    if (error.name === 'AbortError' || error.name === 'TimeoutError') {
      return true;
    }
    if (error.status >= 500 && error.status < 600) {
      return true;
    }
    if (!error.status && error.message.includes('network')) {
      return true;
    }
    return false;
  }

  private async refreshAuthToken(): Promise<string | null> {
    if (this.isRefreshing) {
      // Wait for ongoing refresh
      return this.refreshPromise;
    }

    this.isRefreshing = true;
    this.refreshPromise = this.performTokenRefresh();

    try {
      const newToken = await this.refreshPromise;
      return newToken;
    } finally {
      this.isRefreshing = false;
      this.refreshPromise = null;
    }
  }

  private async performTokenRefresh(): Promise<string | null> {
    try {
      if (!this.refreshToken) {
        throw new Error('No refresh token available');
      }

      const response = await fetch(`${this.config.baseUrl}/auth/refresh`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          refreshToken: this.refreshToken,
        }),
      });

      if (!response.ok) {
        throw new Error('Token refresh failed');
      }

      const data = await response.json();
      const newAuthToken = data.accessToken;
      const newRefreshToken = data.refreshToken;

      await this.setAuthTokens(newAuthToken, newRefreshToken);
      return newAuthToken;

    } catch (error) {
      console.error('Token refresh failed:', error);
      await this.clearAuthTokens();
      return null;
    }
  }

  private parseHeaders(headers: Headers): Record<string, string> {
    const result: Record<string, string> = {};
    headers.forEach((value, key) => {
      result[key] = value;
    });
    return result;
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // HTTP method helpers
  public async get<T = any>(endpoint: string, headers?: Record<string, string>): Promise<ApiResponse<T>> {
    return this.request<T>('GET', endpoint, undefined, headers);
  }

  public async post<T = any>(endpoint: string, data?: any, headers?: Record<string, string>): Promise<ApiResponse<T>> {
    return this.request<T>('POST', endpoint, data, headers);
  }

  public async put<T = any>(endpoint: string, data?: any, headers?: Record<string, string>): Promise<ApiResponse<T>> {
    return this.request<T>('PUT', endpoint, data, headers);
  }

  public async patch<T = any>(endpoint: string, data?: any, headers?: Record<string, string>): Promise<ApiResponse<T>> {
    return this.request<T>('PATCH', endpoint, data, headers);
  }

  public async delete<T = any>(endpoint: string, headers?: Record<string, string>): Promise<ApiResponse<T>> {
    return this.request<T>('DELETE', endpoint, undefined, headers);
  }

  // File upload helper
  public async uploadFile<T = any>(
    endpoint: string,
    file: File | Blob,
    fieldName = 'file',
    additionalData?: Record<string, any>
  ): Promise<ApiResponse<T>> {
    try {
      const formData = new FormData();
      formData.append(fieldName, file);

      if (additionalData) {
        Object.entries(additionalData).forEach(([key, value]) => {
          formData.append(key, String(value));
        });
      }

      const headers: Record<string, string> = {};
      if (this.authToken) {
        headers['Authorization'] = `Bearer ${this.authToken}`;
      }

      const response = await fetch(`${this.config.baseUrl}${endpoint}`, {
        method: 'POST',
        headers,
        body: formData,
        signal: AbortSignal.timeout(this.config.timeout * 2), // Longer timeout for uploads
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new ApiError(
          errorData.message || 'File upload failed',
          response.status,
          errorData.code,
          errorData
        );
      }

      const responseData = await response.json();

      return {
        data: responseData,
        status: response.status,
        statusText: response.statusText,
        headers: this.parseHeaders(response.headers),
      };

    } catch (error) {
      if (!(error instanceof ApiError)) {
        throw new ApiError(
          error.message || 'File upload failed',
          error.status,
          error.code,
          error
        );
      }
      throw error;
    }
  }

  // Health check
  public async healthCheck(): Promise<boolean> {
    try {
      const response = await this.get('/health');
      return response.status === 200;
    } catch (error) {
      return false;
    }
  }

  // Get client information
  public getClientInfo(): {
    baseUrl: string;
    isAuthenticated: boolean;
    hasRefreshToken: boolean;
  } {
    return {
      baseUrl: this.config.baseUrl,
      isAuthenticated: !!this.authToken,
      hasRefreshToken: !!this.refreshToken,
    };
  }
}

// Custom error class
class ApiError extends Error {
  public status?: number;
  public code?: string;
  public details?: any;

  constructor(message: string, status?: number, code?: string, details?: any) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export { ApiError };
export default ApiClient;