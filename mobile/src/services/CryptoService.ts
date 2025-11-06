/**
 * Cryptographic Service
 * Handles encryption, decryption, and secure key management for mobile app
 */

import AsyncStorage from '@react-native-async-storage/async-storage';
import * as Keychain from 'react-native-keychain';
import CryptoJS from 'react-native-crypto-js';
import DeviceInfo from 'react-native-device-info';

export interface CryptoConfig {
  algorithm: string;
  keySize: number;
  iterations: number;
  saltSize: number;
}

export interface KeyPair {
  publicKey: string;
  privateKey: string;
}

export interface EncryptedData {
  data: string;
  iv: string;
  salt: string;
  algorithm: string;
}

export class CryptoService {
  private static instance: CryptoService;
  private config: CryptoConfig;
  private masterKey: string | null = null;
  private deviceId: string | null = null;

  private constructor() {
    this.config = {
      algorithm: 'AES',
      keySize: 256,
      iterations: 10000,
      saltSize: 128,
    };
  }

  public static getInstance(): CryptoService {
    if (!CryptoService.instance) {
      CryptoService.instance = new CryptoService();
    }
    return CryptoService.instance;
  }

  public static async initialize(): Promise<void> {
    const service = CryptoService.getInstance();
    await service.initializeService();
  }

  private async initializeService(): Promise<void> {
    try {
      // Get device ID for key derivation
      this.deviceId = await DeviceInfo.getUniqueId();

      // Initialize or retrieve master key
      await this.initializeMasterKey();

    } catch (error) {
      console.error('Failed to initialize crypto service:', error);
      throw error;
    }
  }

  private async initializeMasterKey(): Promise<void> {
    try {
      // Try to get existing master key from keychain
      const credentials = await Keychain.getInternetCredentials('blncs_master_key');

      if (credentials.username && credentials.password) {
        this.masterKey = credentials.password;
      } else {
        // Generate new master key
        this.masterKey = this.generateSecureKey();

        // Store in keychain
        await Keychain.setInternetCredentials(
          'blncs_master_key',
          'master',
          this.masterKey,
          {
            accessControl: Keychain.ACCESS_CONTROL.BIOMETRY_CURRENT_SET,
            authenticationType: Keychain.AUTHENTICATION_TYPE.DEVICE_PASSCODE_OR_BIOMETRICS,
            accessGroup: 'com.blncs.mobile',
            storage: Keychain.STORAGE_TYPE.AES_GCM_NO_AUTH,
          }
        );
      }
    } catch (error) {
      console.error('Failed to initialize master key:', error);
      throw error;
    }
  }

  private generateSecureKey(): string {
    const randomBytes = CryptoJS.lib.WordArray.random(32);
    return randomBytes.toString(CryptoJS.enc.Hex);
  }

  private generateSalt(): string {
    const saltBytes = CryptoJS.lib.WordArray.random(this.config.saltSize / 8);
    return saltBytes.toString(CryptoJS.enc.Hex);
  }

  private generateIV(): string {
    const ivBytes = CryptoJS.lib.WordArray.random(16);
    return ivBytes.toString(CryptoJS.enc.Hex);
  }

  private deriveKey(password: string, salt: string): string {
    const key = CryptoJS.PBKDF2(password, salt, {
      keySize: this.config.keySize / 32,
      iterations: this.config.iterations,
    });
    return key.toString(CryptoJS.enc.Hex);
  }

  public async encrypt(data: string, customKey?: string): Promise<string> {
    try {
      if (!this.masterKey) {
        throw new Error('Crypto service not initialized');
      }

      const salt = this.generateSalt();
      const iv = this.generateIV();
      const key = customKey || this.masterKey;
      const derivedKey = this.deriveKey(key, salt);

      const encrypted = CryptoJS.AES.encrypt(data, derivedKey, {
        iv: CryptoJS.enc.Hex.parse(iv),
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7,
      });

      const encryptedData: EncryptedData = {
        data: encrypted.toString(),
        iv,
        salt,
        algorithm: this.config.algorithm,
      };

      return JSON.stringify(encryptedData);

    } catch (error) {
      console.error('Encryption failed:', error);
      throw error;
    }
  }

  public async decrypt(encryptedString: string, customKey?: string): Promise<string> {
    try {
      if (!this.masterKey) {
        throw new Error('Crypto service not initialized');
      }

      const encryptedData: EncryptedData = JSON.parse(encryptedString);
      const key = customKey || this.masterKey;
      const derivedKey = this.deriveKey(key, encryptedData.salt);

      const decrypted = CryptoJS.AES.decrypt(encryptedData.data, derivedKey, {
        iv: CryptoJS.enc.Hex.parse(encryptedData.iv),
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7,
      });

      const decryptedString = decrypted.toString(CryptoJS.enc.Utf8);

      if (!decryptedString) {
        throw new Error('Failed to decrypt data - invalid key or corrupted data');
      }

      return decryptedString;

    } catch (error) {
      console.error('Decryption failed:', error);
      throw error;
    }
  }

  public async encryptWithPassword(data: string, password: string): Promise<string> {
    return this.encrypt(data, password);
  }

  public async decryptWithPassword(encryptedString: string, password: string): Promise<string> {
    return this.decrypt(encryptedString, password);
  }

  public async hashData(data: string, algorithm: 'SHA256' | 'SHA512' = 'SHA256'): Promise<string> {
    try {
      let hash;
      switch (algorithm) {
        case 'SHA256':
          hash = CryptoJS.SHA256(data);
          break;
        case 'SHA512':
          hash = CryptoJS.SHA512(data);
          break;
        default:
          throw new Error(`Unsupported hash algorithm: ${algorithm}`);
      }
      return hash.toString(CryptoJS.enc.Hex);
    } catch (error) {
      console.error('Hashing failed:', error);
      throw error;
    }
  }

  public async generateHMAC(data: string, key: string, algorithm: 'SHA256' | 'SHA512' = 'SHA256'): Promise<string> {
    try {
      let hmac;
      switch (algorithm) {
        case 'SHA256':
          hmac = CryptoJS.HmacSHA256(data, key);
          break;
        case 'SHA512':
          hmac = CryptoJS.HmacSHA512(data, key);
          break;
        default:
          throw new Error(`Unsupported HMAC algorithm: ${algorithm}`);
      }
      return hmac.toString(CryptoJS.enc.Hex);
    } catch (error) {
      console.error('HMAC generation failed:', error);
      throw error;
    }
  }

  public async generateRandomBytes(size: number): Promise<string> {
    try {
      const randomBytes = CryptoJS.lib.WordArray.random(size);
      return randomBytes.toString(CryptoJS.enc.Hex);
    } catch (error) {
      console.error('Random bytes generation failed:', error);
      throw error;
    }
  }

  public async secureStore(key: string, value: string, requireBiometric: boolean = false): Promise<void> {
    try {
      const encryptedValue = await this.encrypt(value);

      const options: Keychain.Options = {
        accessGroup: 'com.blncs.mobile',
        storage: Keychain.STORAGE_TYPE.AES_GCM_NO_AUTH,
      };

      if (requireBiometric) {
        options.accessControl = Keychain.ACCESS_CONTROL.BIOMETRY_CURRENT_SET;
        options.authenticationType = Keychain.AUTHENTICATION_TYPE.DEVICE_PASSCODE_OR_BIOMETRICS;
      }

      await Keychain.setInternetCredentials(
        `blncs_secure_${key}`,
        key,
        encryptedValue,
        options
      );

    } catch (error) {
      console.error('Secure store failed:', error);
      throw error;
    }
  }

  public async secureRetrieve(key: string): Promise<string | null> {
    try {
      const credentials = await Keychain.getInternetCredentials(`blncs_secure_${key}`);

      if (credentials.username && credentials.password) {
        return await this.decrypt(credentials.password);
      }

      return null;
    } catch (error) {
      console.error('Secure retrieve failed:', error);
      return null;
    }
  }

  public async secureDelete(key: string): Promise<void> {
    try {
      await Keychain.resetInternetCredentials(`blncs_secure_${key}`);
    } catch (error) {
      console.error('Secure delete failed:', error);
      throw error;
    }
  }

  public async generateSeed(length: number = 32): Promise<string> {
    try {
      const seedBytes = CryptoJS.lib.WordArray.random(length);
      return seedBytes.toString(CryptoJS.enc.Hex);
    } catch (error) {
      console.error('Seed generation failed:', error);
      throw error;
    }
  }

  public async deriveBIP32Key(seed: string, path: string): Promise<string> {
    try {
      // Simplified BIP32 key derivation
      // In production, use a proper BIP32 library
      const pathHash = await this.hashData(path);
      const combined = seed + pathHash;
      return await this.hashData(combined);
    } catch (error) {
      console.error('BIP32 key derivation failed:', error);
      throw error;
    }
  }

  public async createWalletSeed(): Promise<{ seed: string; mnemonic: string }> {
    try {
      // Generate 256-bit entropy
      const entropy = await this.generateRandomBytes(32);

      // In production, use proper BIP39 mnemonic generation
      const seed = await this.hashData(entropy, 'SHA512');
      const mnemonic = this.entropyToMnemonic(entropy);

      return { seed, mnemonic };
    } catch (error) {
      console.error('Wallet seed creation failed:', error);
      throw error;
    }
  }

  private entropyToMnemonic(entropy: string): string {
    // Simplified mnemonic generation
    // In production, use proper BIP39 implementation
    const words = [
      'abandon', 'ability', 'able', 'about', 'above', 'absent', 'absorb', 'abstract',
      'absurd', 'abuse', 'access', 'accident', 'account', 'accuse', 'achieve', 'acid',
      // ... complete BIP39 wordlist would go here
    ];

    const chunks = entropy.match(/.{8}/g) || [];
    return chunks.map(chunk => {
      const index = parseInt(chunk.substring(0, 4), 16) % words.length;
      return words[index];
    }).join(' ');
  }

  public async encryptWalletData(walletData: any, password: string): Promise<string> {
    try {
      const jsonData = JSON.stringify(walletData);
      return await this.encryptWithPassword(jsonData, password);
    } catch (error) {
      console.error('Wallet data encryption failed:', error);
      throw error;
    }
  }

  public async decryptWalletData(encryptedData: string, password: string): Promise<any> {
    try {
      const jsonData = await this.decryptWithPassword(encryptedData, password);
      return JSON.parse(jsonData);
    } catch (error) {
      console.error('Wallet data decryption failed:', error);
      throw error;
    }
  }

  public async wipeSecureData(): Promise<void> {
    try {
      // Clear master key
      await Keychain.resetInternetCredentials('blncs_master_key');

      // Clear all secure storage keys
      const allKeys = await Keychain.getAllInternetCredentials();
      for (const credential of allKeys) {
        if (credential.server.startsWith('blncs_secure_')) {
          await Keychain.resetInternetCredentials(credential.server);
        }
      }

      // Clear instance data
      this.masterKey = null;

      console.log('All secure data wiped successfully');
    } catch (error) {
      console.error('Failed to wipe secure data:', error);
      throw error;
    }
  }

  public async verifyIntegrity(data: string, expectedHash: string): Promise<boolean> {
    try {
      const actualHash = await this.hashData(data);
      return actualHash === expectedHash;
    } catch (error) {
      console.error('Integrity verification failed:', error);
      return false;
    }
  }

  public getConfig(): CryptoConfig {
    return { ...this.config };
  }

  public async updateConfig(newConfig: Partial<CryptoConfig>): Promise<void> {
    this.config = { ...this.config, ...newConfig };
    await AsyncStorage.setItem('crypto_config', JSON.stringify(this.config));
  }

  public isInitialized(): boolean {
    return this.masterKey !== null && this.deviceId !== null;
  }

  public getDeviceId(): string | null {
    return this.deviceId;
  }
}

export default CryptoService;