/**
 * Biometric Authentication Service
 * Handles fingerprint, face recognition, and device security features
 */

import ReactNativeBiometrics, { BiometryTypes } from 'react-native-biometrics';
import * as Keychain from 'react-native-keychain';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { Alert, Platform } from 'react-native';

export interface BiometricConfig {
  enabled: boolean;
  type: BiometryTypes | null;
  fallbackToPassword: boolean;
  maxAttempts: number;
  lockoutDuration: number;
}

export interface BiometricResult {
  success: boolean;
  error?: string;
  biometryType?: BiometryTypes;
}

export interface AuthenticationResult {
  success: boolean;
  signature?: string;
  error?: string;
}

export class BiometricService {
  private static instance: BiometricService;
  private rnBiometrics: ReactNativeBiometrics;
  private config: BiometricConfig;
  private failedAttempts: number = 0;
  private isLockedOut: boolean = false;
  private lockoutEndTime: number = 0;

  private constructor() {
    this.rnBiometrics = new ReactNativeBiometrics({
      allowDeviceCredentials: true,
    });

    this.config = {
      enabled: false,
      type: null,
      fallbackToPassword: true,
      maxAttempts: 5,
      lockoutDuration: 300000, // 5 minutes
    };

    this.loadConfig();
  }

  public static getInstance(): BiometricService {
    if (!BiometricService.instance) {
      BiometricService.instance = new BiometricService();
    }
    return BiometricService.instance;
  }

  public static async initialize(): Promise<void> {
    const service = BiometricService.getInstance();
    await service.checkBiometricAvailability();
  }

  private async loadConfig(): Promise<void> {
    try {
      const savedConfig = await AsyncStorage.getItem('biometric_config');
      if (savedConfig) {
        this.config = { ...this.config, ...JSON.parse(savedConfig) };
      }

      const failedAttempts = await AsyncStorage.getItem('biometric_failed_attempts');
      if (failedAttempts) {
        this.failedAttempts = parseInt(failedAttempts, 10);
      }

      const lockoutEndTime = await AsyncStorage.getItem('biometric_lockout_end');
      if (lockoutEndTime) {
        this.lockoutEndTime = parseInt(lockoutEndTime, 10);
        this.isLockedOut = Date.now() < this.lockoutEndTime;
      }

    } catch (error) {
      console.error('Failed to load biometric config:', error);
    }
  }

  private async saveConfig(): Promise<void> {
    try {
      await AsyncStorage.setItem('biometric_config', JSON.stringify(this.config));
    } catch (error) {
      console.error('Failed to save biometric config:', error);
    }
  }

  public async checkBiometricAvailability(): Promise<BiometricResult> {
    try {
      const { available, biometryType } = await this.rnBiometrics.isSensorAvailable();

      if (available && biometryType) {
        this.config.type = biometryType;
        await this.saveConfig();

        return {
          success: true,
          biometryType,
        };
      }

      return {
        success: false,
        error: 'Biometric authentication not available',
      };

    } catch (error) {
      console.error('Error checking biometric availability:', error);
      return {
        success: false,
        error: error.message || 'Failed to check biometric availability',
      };
    }
  }

  public async enableBiometricAuthentication(): Promise<BiometricResult> {
    try {
      const availability = await this.checkBiometricAvailability();
      if (!availability.success) {
        return availability;
      }

      // Check if keys already exist
      const { keysExist } = await this.rnBiometrics.biometricKeysExist();

      if (!keysExist) {
        const { publicKey } = await this.rnBiometrics.createKeys();
        console.log('Created biometric keys:', publicKey);
      }

      // Test biometric authentication
      const testResult = await this.authenticate(
        'Enable Biometric Authentication',
        'Verify your identity to enable biometric authentication'
      );

      if (testResult.success) {
        this.config.enabled = true;
        await this.saveConfig();

        return {
          success: true,
          biometryType: this.config.type,
        };
      }

      return {
        success: false,
        error: testResult.error || 'Biometric authentication test failed',
      };

    } catch (error) {
      console.error('Failed to enable biometric authentication:', error);
      return {
        success: false,
        error: error.message || 'Failed to enable biometric authentication',
      };
    }
  }

  public async disableBiometricAuthentication(): Promise<void> {
    try {
      this.config.enabled = false;
      await this.saveConfig();

      // Optionally delete biometric keys
      const { keysExist } = await this.rnBiometrics.biometricKeysExist();
      if (keysExist) {
        await this.rnBiometrics.deleteKeys();
      }

      // Clear any stored biometric data
      await this.clearBiometricData();

    } catch (error) {
      console.error('Failed to disable biometric authentication:', error);
      throw error;
    }
  }

  public async authenticate(
    title: string = 'Authenticate',
    subtitle: string = 'Use your biometric to authenticate'
  ): Promise<AuthenticationResult> {
    try {
      // Check if locked out
      if (this.isLockedOut) {
        const remainingTime = Math.ceil((this.lockoutEndTime - Date.now()) / 1000);
        return {
          success: false,
          error: `Too many failed attempts. Try again in ${remainingTime} seconds.`,
        };
      }

      // Check if biometrics are enabled and available
      if (!this.config.enabled) {
        return {
          success: false,
          error: 'Biometric authentication not enabled',
        };
      }

      const { available } = await this.rnBiometrics.isSensorAvailable();
      if (!available) {
        return {
          success: false,
          error: 'Biometric sensor not available',
        };
      }

      // Attempt biometric authentication
      const { success, signature, error } = await this.rnBiometrics.createSignature({
        promptMessage: title,
        payload: `${Date.now()}`,
        cancelButtonText: 'Cancel',
        fallbackPromptMessage: subtitle,
      });

      if (success && signature) {
        // Reset failed attempts on success
        this.failedAttempts = 0;
        await AsyncStorage.removeItem('biometric_failed_attempts');
        await AsyncStorage.removeItem('biometric_lockout_end');
        this.isLockedOut = false;

        return {
          success: true,
          signature,
        };
      }

      // Handle failed attempt
      await this.handleFailedAttempt();

      return {
        success: false,
        error: error || 'Biometric authentication failed',
      };

    } catch (error) {
      console.error('Biometric authentication error:', error);
      await this.handleFailedAttempt();

      return {
        success: false,
        error: error.message || 'Biometric authentication failed',
      };
    }
  }

  public async authenticateWithKeychain(
    service: string,
    title: string = 'Authenticate',
    subtitle: string = 'Use your biometric to access secure data'
  ): Promise<{ success: boolean; data?: any; error?: string }> {
    try {
      if (!this.config.enabled) {
        return {
          success: false,
          error: 'Biometric authentication not enabled',
        };
      }

      const credentials = await Keychain.getInternetCredentials(service, {
        authenticationType: Keychain.AUTHENTICATION_TYPE.DEVICE_PASSCODE_OR_BIOMETRICS,
        accessControl: Keychain.ACCESS_CONTROL.BIOMETRY_CURRENT_SET,
        showModal: true,
        kLocalizedFallbackTitle: 'Use Passcode',
      });

      if (credentials.username && credentials.password) {
        return {
          success: true,
          data: {
            username: credentials.username,
            password: credentials.password,
          },
        };
      }

      return {
        success: false,
        error: 'No credentials found',
      };

    } catch (error) {
      console.error('Keychain biometric authentication error:', error);
      return {
        success: false,
        error: error.message || 'Authentication failed',
      };
    }
  }

  private async handleFailedAttempt(): Promise<void> {
    this.failedAttempts++;
    await AsyncStorage.setItem('biometric_failed_attempts', this.failedAttempts.toString());

    if (this.failedAttempts >= this.config.maxAttempts) {
      this.isLockedOut = true;
      this.lockoutEndTime = Date.now() + this.config.lockoutDuration;
      await AsyncStorage.setItem('biometric_lockout_end', this.lockoutEndTime.toString());

      Alert.alert(
        'Too Many Failed Attempts',
        `Biometric authentication locked for ${this.config.lockoutDuration / 60000} minutes.`,
        [{ text: 'OK' }]
      );
    }
  }

  public async verifySignature(signature: string, payload: string): Promise<boolean> {
    try {
      // In a real implementation, you would verify the signature against a public key
      // For now, we'll just check if the signature exists and is valid format
      return signature && signature.length > 0;
    } catch (error) {
      console.error('Signature verification failed:', error);
      return false;
    }
  }

  public async getBiometricType(): Promise<BiometryTypes | null> {
    try {
      const { available, biometryType } = await this.rnBiometrics.isSensorAvailable();
      return available ? biometryType : null;
    } catch (error) {
      console.error('Failed to get biometric type:', error);
      return null;
    }
  }

  public getBiometricTypeName(type: BiometryTypes | null): string {
    if (!type) return 'Not Available';

    switch (type) {
      case BiometryTypes.TouchID:
        return 'Touch ID';
      case BiometryTypes.FaceID:
        return 'Face ID';
      case BiometryTypes.Biometrics:
        return Platform.OS === 'android' ? 'Fingerprint' : 'Biometrics';
      default:
        return 'Unknown';
    }
  }

  public isEnabled(): boolean {
    return this.config.enabled;
  }

  public isAvailable(): boolean {
    return this.config.type !== null;
  }

  public isLockedOutStatus(): boolean {
    return this.isLockedOut;
  }

  public getFailedAttempts(): number {
    return this.failedAttempts;
  }

  public getRemainingLockoutTime(): number {
    if (!this.isLockedOut) return 0;
    return Math.max(0, this.lockoutEndTime - Date.now());
  }

  public async resetFailedAttempts(): Promise<void> {
    this.failedAttempts = 0;
    this.isLockedOut = false;
    this.lockoutEndTime = 0;

    await Promise.all([
      AsyncStorage.removeItem('biometric_failed_attempts'),
      AsyncStorage.removeItem('biometric_lockout_end'),
    ]);
  }

  public async updateConfig(newConfig: Partial<BiometricConfig>): Promise<void> {
    this.config = { ...this.config, ...newConfig };
    await this.saveConfig();
  }

  public getConfig(): BiometricConfig {
    return { ...this.config };
  }

  private async clearBiometricData(): Promise<void> {
    try {
      await Promise.all([
        AsyncStorage.removeItem('biometric_config'),
        AsyncStorage.removeItem('biometric_failed_attempts'),
        AsyncStorage.removeItem('biometric_lockout_end'),
      ]);
    } catch (error) {
      console.error('Failed to clear biometric data:', error);
    }
  }

  public async createBiometricKey(keyAlias: string): Promise<{ publicKey: string }> {
    try {
      const result = await this.rnBiometrics.createKeys(keyAlias);
      return result;
    } catch (error) {
      console.error('Failed to create biometric key:', error);
      throw error;
    }
  }

  public async deleteBiometricKey(keyAlias?: string): Promise<void> {
    try {
      await this.rnBiometrics.deleteKeys(keyAlias);
    } catch (error) {
      console.error('Failed to delete biometric key:', error);
      throw error;
    }
  }

  public async biometricKeysExist(): Promise<boolean> {
    try {
      const { keysExist } = await this.rnBiometrics.biometricKeysExist();
      return keysExist;
    } catch (error) {
      console.error('Failed to check biometric keys:', error);
      return false;
    }
  }

  public async showBiometricPrompt(
    title: string,
    subtitle: string,
    description?: string
  ): Promise<AuthenticationResult> {
    try {
      const result = await this.rnBiometrics.simplePrompt({
        promptMessage: title,
        fallbackPromptMessage: subtitle,
        cancelButtonText: 'Cancel',
      });

      return {
        success: result.success,
        error: result.success ? undefined : 'Authentication cancelled',
      };

    } catch (error) {
      console.error('Biometric prompt error:', error);
      return {
        success: false,
        error: error.message || 'Authentication failed',
      };
    }
  }
}

export default BiometricService;