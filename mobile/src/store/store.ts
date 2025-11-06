/**
 * Redux Store Configuration
 * Central state management for BLNCS mobile application
 */

import { configureStore, combineReducers } from '@reduxjs/toolkit';
import { persistStore, persistReducer } from 'redux-persist';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { createTransform } from 'redux-persist';

// Import slices
import appSlice from './slices/appSlice';
import authSlice from './slices/authSlice';
import lightningSlice from './slices/lightningSlice';
import walletSlice from './slices/walletSlice';
import paymentsSlice from './slices/paymentsSlice';
import channelsSlice from './slices/channelsSlice';
import nodesSlice from './slices/nodesSlice';
import notificationsSlice from './slices/notificationsSlice';
import settingsSlice from './slices/settingsSlice';
import securitySlice from './slices/securitySlice';

// Create transform to encrypt sensitive data before persisting
const sensitiveDataTransform = createTransform(
  // Transform state on its way to being serialized and persisted
  (inboundState: any, key: string) => {
    // Remove sensitive data before persisting
    if (key === 'auth') {
      const { token, refreshToken, ...rest } = inboundState;
      return rest;
    }
    if (key === 'wallet') {
      const { privateKeys, seed, ...rest } = inboundState;
      return rest;
    }
    return inboundState;
  },
  // Transform state being rehydrated
  (outboundState: any, key: string) => {
    return outboundState;
  },
  // Configuration
  {
    whitelist: ['auth', 'wallet', 'security'],
  }
);

// Root reducer
const rootReducer = combineReducers({
  app: appSlice,
  auth: authSlice,
  lightning: lightningSlice,
  wallet: walletSlice,
  payments: paymentsSlice,
  channels: channelsSlice,
  nodes: nodesSlice,
  notifications: notificationsSlice,
  settings: settingsSlice,
  security: securitySlice,
});

// Persist configuration
const persistConfig = {
  key: 'root',
  storage: AsyncStorage,
  whitelist: [
    'app',
    'auth',
    'settings',
    'notifications',
    'security'
  ], // Only persist these slices
  blacklist: [
    'lightning',
    'wallet',
    'payments',
    'channels',
    'nodes'
  ], // Don't persist real-time data
  transforms: [sensitiveDataTransform],
  timeout: 10000, // 10 seconds timeout
  writeFailHandler: (error: Error) => {
    console.error('Redux persist write failed:', error);
  },
};

// Create persisted reducer
const persistedReducer = persistReducer(persistConfig, rootReducer);

// Configure store
export const store = configureStore({
  reducer: persistedReducer,
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware({
      serializableCheck: {
        ignoredActions: [
          'persist/PERSIST',
          'persist/REHYDRATE',
          'persist/PAUSE',
          'persist/PURGE',
          'persist/REGISTER',
          'persist/FLUSH',
        ],
        ignoredActionsPaths: ['meta.arg', 'payload.timestamp'],
        ignoredPaths: ['items.dates'],
      },
      immutableCheck: {
        ignoredPaths: ['items.dates'],
      },
    }),
  devTools: __DEV__,
});

// Create persistor
export const persistor = persistStore(store, null, () => {
  console.log('Redux store rehydrated');
});

// Root state and dispatch types
export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;

// Store utilities
export const getStoreState = (): RootState => store.getState();

export const resetStore = async (): Promise<void> => {
  try {
    await persistor.purge();
    await AsyncStorage.multiRemove([
      'persist:root',
      'persist:app',
      'persist:auth',
      'persist:settings',
      'persist:notifications',
      'persist:security',
    ]);
    console.log('Store reset successfully');
  } catch (error) {
    console.error('Failed to reset store:', error);
  }
};

export const clearPersistedData = async (): Promise<void> => {
  try {
    await persistor.flush();
    await persistor.purge();
    console.log('Persisted data cleared');
  } catch (error) {
    console.error('Failed to clear persisted data:', error);
  }
};

// Store debugging utilities
export const logStoreState = (): void => {
  if (__DEV__) {
    console.log('Store State:', store.getState());
  }
};

export const getStoreSize = async (): Promise<number> => {
  try {
    const keys = await AsyncStorage.getAllKeys();
    const stores = keys.filter(key => key.startsWith('persist:'));

    let totalSize = 0;
    for (const key of stores) {
      const value = await AsyncStorage.getItem(key);
      if (value) {
        totalSize += new Blob([value]).size;
      }
    }

    return totalSize;
  } catch (error) {
    console.error('Failed to calculate store size:', error);
    return 0;
  }
};

// Store migration utilities for app updates
export const migrateStore = async (version: number): Promise<void> => {
  try {
    const currentVersion = await AsyncStorage.getItem('store_version');
    const currentVersionNumber = currentVersion ? parseInt(currentVersion, 10) : 0;

    if (currentVersionNumber < version) {
      console.log(`Migrating store from version ${currentVersionNumber} to ${version}`);

      // Perform migrations based on version
      switch (version) {
        case 2:
          await migrateToVersion2();
          break;
        case 3:
          await migrateToVersion3();
          break;
        default:
          break;
      }

      await AsyncStorage.setItem('store_version', version.toString());
      console.log('Store migration completed');
    }
  } catch (error) {
    console.error('Store migration failed:', error);
  }
};

const migrateToVersion2 = async (): Promise<void> => {
  // Example migration: Update settings structure
  try {
    const settingsData = await AsyncStorage.getItem('persist:settings');
    if (settingsData) {
      const settings = JSON.parse(settingsData);
      // Perform settings migration
      await AsyncStorage.setItem('persist:settings', JSON.stringify(settings));
    }
  } catch (error) {
    console.error('Migration to version 2 failed:', error);
  }
};

const migrateToVersion3 = async (): Promise<void> => {
  // Example migration: Update notification structure
  try {
    const notificationData = await AsyncStorage.getItem('persist:notifications');
    if (notificationData) {
      const notifications = JSON.parse(notificationData);
      // Perform notification migration
      await AsyncStorage.setItem('persist:notifications', JSON.stringify(notifications));
    }
  } catch (error) {
    console.error('Migration to version 3 failed:', error);
  }
};

// Store health check
export const checkStoreHealth = async (): Promise<{
  isHealthy: boolean;
  errors: string[];
  size: number;
}> => {
  const errors: string[] = [];
  let isHealthy = true;

  try {
    // Check if store is accessible
    const state = store.getState();
    if (!state) {
      errors.push('Store state is null');
      isHealthy = false;
    }

    // Check persisted data
    const keys = await AsyncStorage.getAllKeys();
    const persistKeys = keys.filter(key => key.startsWith('persist:'));

    if (persistKeys.length === 0) {
      errors.push('No persisted data found');
    }

    // Check for corrupted data
    for (const key of persistKeys) {
      try {
        const value = await AsyncStorage.getItem(key);
        if (value) {
          JSON.parse(value);
        }
      } catch (parseError) {
        errors.push(`Corrupted data in ${key}`);
        isHealthy = false;
      }
    }

    // Get store size
    const size = await getStoreSize();

    return {
      isHealthy,
      errors,
      size,
    };

  } catch (error) {
    errors.push(`Store health check failed: ${error.message}`);
    return {
      isHealthy: false,
      errors,
      size: 0,
    };
  }
};

// Performance monitoring
export const trackStorePerformance = () => {
  if (__DEV__) {
    let actionCount = 0;
    let lastLogTime = Date.now();

    const originalDispatch = store.dispatch;
    store.dispatch = (action: any) => {
      actionCount++;

      // Log performance every 100 actions or every 30 seconds
      const now = Date.now();
      if (actionCount % 100 === 0 || now - lastLogTime > 30000) {
        console.log(`Store Performance: ${actionCount} actions in ${now - lastLogTime}ms`);
        lastLogTime = now;
      }

      return originalDispatch(action);
    };
  }
};

// Initialize performance tracking in development
if (__DEV__) {
  trackStorePerformance();
}

export default store;