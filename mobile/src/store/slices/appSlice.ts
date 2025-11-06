/**
 * App Slice
 * Global application state management
 */

import { createSlice, createAsyncThunk, PayloadAction } from '@reduxjs/toolkit';
import { AppStateStatus } from 'react-native';
import DeviceInfo from 'react-native-device-info';
import AsyncStorage from '@react-native-async-storage/async-storage';

export interface NetworkStatus {
  isConnected: boolean;
  type: string | null;
  isInternetReachable: boolean;
}

export interface AppInfo {
  version: string;
  buildNumber: string;
  bundleId: string;
  deviceId: string;
  deviceName: string;
  systemVersion: string;
  systemName: string;
}

export interface AppState {
  // App lifecycle
  isInitialized: boolean;
  isLoading: boolean;
  isLocked: boolean;
  appState: AppStateStatus;

  // Network status
  networkStatus: NetworkStatus;

  // App information
  appInfo: AppInfo | null;

  // Settings
  theme: 'light' | 'dark' | 'system';
  biometricEnabled: boolean;
  autoLockTimeout: number; // minutes

  // UI state
  activeScreen: string;
  previousScreen: string;

  // Error handling
  lastError: string | null;
  errorCount: number;

  // Performance
  startupTime: number;
  memoryUsage: number;

  // Feature flags
  features: {
    developmentMode: boolean;
    debugMode: boolean;
    betaFeatures: boolean;
    analyticsEnabled: boolean;
  };
}

const initialState: AppState = {
  isInitialized: false,
  isLoading: false,
  isLocked: false,
  appState: 'active',
  networkStatus: {
    isConnected: false,
    type: null,
    isInternetReachable: false,
  },
  appInfo: null,
  theme: 'system',
  biometricEnabled: false,
  autoLockTimeout: 5,
  activeScreen: '',
  previousScreen: '',
  lastError: null,
  errorCount: 0,
  startupTime: 0,
  memoryUsage: 0,
  features: {
    developmentMode: __DEV__,
    debugMode: false,
    betaFeatures: false,
    analyticsEnabled: true,
  },
};

// Async thunks
export const initializeApp = createAsyncThunk(
  'app/initialize',
  async (_, { dispatch }) => {
    const startTime = Date.now();

    try {
      // Get device information
      const [
        version,
        buildNumber,
        bundleId,
        deviceId,
        deviceName,
        systemVersion,
        systemName,
      ] = await Promise.all([
        DeviceInfo.getVersion(),
        DeviceInfo.getBuildNumber(),
        DeviceInfo.getBundleId(),
        DeviceInfo.getUniqueId(),
        DeviceInfo.getDeviceName(),
        DeviceInfo.getSystemVersion(),
        DeviceInfo.getSystemName(),
      ]);

      const appInfo: AppInfo = {
        version,
        buildNumber,
        bundleId,
        deviceId,
        deviceName,
        systemVersion,
        systemName,
      };

      // Load persisted settings
      const savedSettings = await loadAppSettings();

      const endTime = Date.now();
      const startupTime = endTime - startTime;

      return {
        appInfo,
        startupTime,
        ...savedSettings,
      };

    } catch (error) {
      console.error('App initialization failed:', error);
      throw error;
    }
  }
);

export const updateMemoryUsage = createAsyncThunk(
  'app/updateMemoryUsage',
  async () => {
    try {
      const memoryInfo = await DeviceInfo.getUsedMemory();
      return memoryInfo;
    } catch (error) {
      console.error('Failed to get memory usage:', error);
      return 0;
    }
  }
);

export const saveAppSettings = createAsyncThunk(
  'app/saveSettings',
  async (settings: Partial<AppState>) => {
    try {
      const settingsToSave = {
        theme: settings.theme,
        biometricEnabled: settings.biometricEnabled,
        autoLockTimeout: settings.autoLockTimeout,
        features: settings.features,
      };

      await AsyncStorage.setItem('app_settings', JSON.stringify(settingsToSave));
      return settingsToSave;
    } catch (error) {
      console.error('Failed to save app settings:', error);
      throw error;
    }
  }
);

// Helper function to load app settings
const loadAppSettings = async (): Promise<Partial<AppState>> => {
  try {
    const savedSettings = await AsyncStorage.getItem('app_settings');
    if (savedSettings) {
      return JSON.parse(savedSettings);
    }
  } catch (error) {
    console.error('Failed to load app settings:', error);
  }
  return {};
};

// App slice
const appSlice = createSlice({
  name: 'app',
  initialState,
  reducers: {
    setLoading: (state, action: PayloadAction<boolean>) => {
      state.isLoading = action.payload;
    },

    lockApp: (state) => {
      state.isLocked = true;
    },

    unlockApp: (state) => {
      state.isLocked = false;
    },

    setAppState: (state, action: PayloadAction<AppStateStatus>) => {
      state.appState = action.payload;
    },

    setNetworkStatus: (state, action: PayloadAction<NetworkStatus>) => {
      state.networkStatus = action.payload;
    },

    setTheme: (state, action: PayloadAction<'light' | 'dark' | 'system'>) => {
      state.theme = action.payload;
    },

    setBiometricEnabled: (state, action: PayloadAction<boolean>) => {
      state.biometricEnabled = action.payload;
    },

    setAutoLockTimeout: (state, action: PayloadAction<number>) => {
      state.autoLockTimeout = action.payload;
    },

    setActiveScreen: (state, action: PayloadAction<string>) => {
      state.previousScreen = state.activeScreen;
      state.activeScreen = action.payload;
    },

    setError: (state, action: PayloadAction<string>) => {
      state.lastError = action.payload;
      state.errorCount += 1;
    },

    clearError: (state) => {
      state.lastError = null;
    },

    updateFeatures: (state, action: PayloadAction<Partial<AppState['features']>>) => {
      state.features = { ...state.features, ...action.payload };
    },

    resetErrorCount: (state) => {
      state.errorCount = 0;
    },

    // Development helpers
    toggleDebugMode: (state) => {
      state.features.debugMode = !state.features.debugMode;
    },

    toggleBetaFeatures: (state) => {
      state.features.betaFeatures = !state.features.betaFeatures;
    },

    toggleAnalytics: (state) => {
      state.features.analyticsEnabled = !state.features.analyticsEnabled;
    },

    // Performance tracking
    updateStartupTime: (state, action: PayloadAction<number>) => {
      state.startupTime = action.payload;
    },

    // Reset app state
    resetApp: (state) => {
      return {
        ...initialState,
        appInfo: state.appInfo,
        networkStatus: state.networkStatus,
      };
    },
  },

  extraReducers: (builder) => {
    builder
      // Initialize app
      .addCase(initializeApp.pending, (state) => {
        state.isLoading = true;
      })
      .addCase(initializeApp.fulfilled, (state, action) => {
        state.isLoading = false;
        state.isInitialized = true;
        state.appInfo = action.payload.appInfo;
        state.startupTime = action.payload.startupTime;

        // Apply loaded settings
        if (action.payload.theme) state.theme = action.payload.theme;
        if (action.payload.biometricEnabled !== undefined) {
          state.biometricEnabled = action.payload.biometricEnabled;
        }
        if (action.payload.autoLockTimeout) {
          state.autoLockTimeout = action.payload.autoLockTimeout;
        }
        if (action.payload.features) {
          state.features = { ...state.features, ...action.payload.features };
        }
      })
      .addCase(initializeApp.rejected, (state, action) => {
        state.isLoading = false;
        state.lastError = action.error.message || 'App initialization failed';
        state.errorCount += 1;
      })

      // Update memory usage
      .addCase(updateMemoryUsage.fulfilled, (state, action) => {
        state.memoryUsage = action.payload;
      })

      // Save app settings
      .addCase(saveAppSettings.fulfilled, (state, action) => {
        // Settings already updated in the respective reducers
      })
      .addCase(saveAppSettings.rejected, (state, action) => {
        state.lastError = action.error.message || 'Failed to save settings';
      });
  },
});

// Actions
export const {
  setLoading,
  lockApp,
  unlockApp,
  setAppState,
  setNetworkStatus,
  setTheme,
  setBiometricEnabled,
  setAutoLockTimeout,
  setActiveScreen,
  setError,
  clearError,
  updateFeatures,
  resetErrorCount,
  toggleDebugMode,
  toggleBetaFeatures,
  toggleAnalytics,
  updateStartupTime,
  resetApp,
} = appSlice.actions;

// Selectors
export const selectIsInitialized = (state: { app: AppState }) => state.app.isInitialized;
export const selectIsLoading = (state: { app: AppState }) => state.app.isLoading;
export const selectIsLocked = (state: { app: AppState }) => state.app.isLocked;
export const selectNetworkStatus = (state: { app: AppState }) => state.app.networkStatus;
export const selectAppInfo = (state: { app: AppState }) => state.app.appInfo;
export const selectTheme = (state: { app: AppState }) => state.app.theme;
export const selectBiometricEnabled = (state: { app: AppState }) => state.app.biometricEnabled;
export const selectAutoLockTimeout = (state: { app: AppState }) => state.app.autoLockTimeout;
export const selectActiveScreen = (state: { app: AppState }) => state.app.activeScreen;
export const selectLastError = (state: { app: AppState }) => state.app.lastError;
export const selectErrorCount = (state: { app: AppState }) => state.app.errorCount;
export const selectFeatures = (state: { app: AppState }) => state.app.features;
export const selectIsOnline = (state: { app: AppState }) =>
  state.app.networkStatus.isConnected && state.app.networkStatus.isInternetReachable;
export const selectAppState = (state: { app: AppState }) => state.app.appState;
export const selectMemoryUsage = (state: { app: AppState }) => state.app.memoryUsage;
export const selectStartupTime = (state: { app: AppState }) => state.app.startupTime;

// Complex selectors
export const selectIsAppHealthy = (state: { app: AppState }) => {
  const { errorCount, isInitialized, networkStatus } = state.app;
  return isInitialized && errorCount < 5 && networkStatus.isConnected;
};

export const selectShouldShowOfflineWarning = (state: { app: AppState }) => {
  return !state.app.networkStatus.isConnected || !state.app.networkStatus.isInternetReachable;
};

export const selectCanUseBiometrics = (state: { app: AppState }) => {
  return state.app.biometricEnabled && state.app.isInitialized;
};

export default appSlice.reducer;