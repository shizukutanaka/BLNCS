/**
 * Authentication Slice
 * Manages user authentication state and tokens
 */

import { createSlice, createAsyncThunk, PayloadAction } from '@reduxjs/toolkit';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { ApiClient } from '../../services/ApiClient';
import { CryptoService } from '../../services/CryptoService';
import { BiometricService } from '../../services/BiometricService';

export interface User {
  id: string;
  username: string;
  email: string;
  firstName: string;
  lastName: string;
  avatar?: string;
  roles: string[];
  permissions: string[];
  tenantId?: string;
  lastLoginAt: string;
  isActive: boolean;
  settings: {
    language: string;
    timezone: string;
    currency: string;
    notifications: boolean;
  };
}

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
  tokenType: string;
}

export interface LoginCredentials {
  username: string;
  password: string;
  rememberMe?: boolean;
  mfaCode?: string;
}

export interface RegisterData {
  username: string;
  email: string;
  password: string;
  firstName: string;
  lastName: string;
  acceptTerms: boolean;
}

export interface AuthState {
  // Authentication status
  isAuthenticated: boolean;
  isLoading: boolean;
  user: User | null;
  tokens: AuthTokens | null;

  // Login state
  loginAttempts: number;
  lastLoginAttempt: number;
  isLockedOut: boolean;
  lockoutUntil: number;

  // Biometric authentication
  biometricSetup: boolean;
  biometricPromptShown: boolean;

  // Session management
  sessionTimeout: number;
  lastActivity: number;
  autoLogoutWarningShown: boolean;

  // Multi-factor authentication
  mfaRequired: boolean;
  mfaMethod: 'totp' | 'sms' | 'email' | null;
  mfaSetup: boolean;

  // Error handling
  error: string | null;
  registrationError: string | null;

  // Settings
  rememberCredentials: boolean;
  autoLogin: boolean;
}

const initialState: AuthState = {
  isAuthenticated: false,
  isLoading: false,
  user: null,
  tokens: null,
  loginAttempts: 0,
  lastLoginAttempt: 0,
  isLockedOut: false,
  lockoutUntil: 0,
  biometricSetup: false,
  biometricPromptShown: false,
  sessionTimeout: 30 * 60 * 1000, // 30 minutes
  lastActivity: Date.now(),
  autoLogoutWarningShown: false,
  mfaRequired: false,
  mfaMethod: null,
  mfaSetup: false,
  error: null,
  registrationError: null,
  rememberCredentials: false,
  autoLogin: false,
};

// Async thunks
export const login = createAsyncThunk(
  'auth/login',
  async (credentials: LoginCredentials, { rejectWithValue }) => {
    try {
      const apiClient = ApiClient.getInstance();

      const response = await apiClient.post('/auth/login', {
        username: credentials.username,
        password: credentials.password,
        mfaCode: credentials.mfaCode,
      });

      const { user, tokens } = response.data;

      // Store tokens securely
      await apiClient.setAuthTokens(tokens.accessToken, tokens.refreshToken);

      // Store user credentials if remember me is enabled
      if (credentials.rememberMe) {
        const cryptoService = CryptoService.getInstance();
        await cryptoService.secureStore('saved_username', credentials.username);
      }

      return { user, tokens };

    } catch (error: any) {
      return rejectWithValue(error.message || 'Login failed');
    }
  }
);

export const register = createAsyncThunk(
  'auth/register',
  async (data: RegisterData, { rejectWithValue }) => {
    try {
      const apiClient = ApiClient.getInstance();

      const response = await apiClient.post('/auth/register', data);
      const { user, tokens } = response.data;

      // Store tokens securely
      await apiClient.setAuthTokens(tokens.accessToken, tokens.refreshToken);

      return { user, tokens };

    } catch (error: any) {
      return rejectWithValue(error.message || 'Registration failed');
    }
  }
);

export const logout = createAsyncThunk(
  'auth/logout',
  async (_, { getState }) => {
    try {
      const apiClient = ApiClient.getInstance();

      // Notify server of logout
      try {
        await apiClient.post('/auth/logout');
      } catch (error) {
        // Continue with logout even if server call fails
        console.warn('Server logout failed:', error);
      }

      // Clear tokens
      await apiClient.clearAuthTokens();

      // Clear biometric data if not setup for reuse
      const state = getState() as { auth: AuthState };
      if (!state.auth.biometricSetup) {
        const biometricService = BiometricService.getInstance();
        await biometricService.disableBiometricAuthentication();
      }

      return null;

    } catch (error) {
      console.error('Logout error:', error);
      // Always succeed logout to clear local state
      return null;
    }
  }
);

export const refreshToken = createAsyncThunk(
  'auth/refreshToken',
  async (_, { getState, rejectWithValue }) => {
    try {
      const state = getState() as { auth: AuthState };
      if (!state.auth.tokens?.refreshToken) {
        throw new Error('No refresh token available');
      }

      const apiClient = ApiClient.getInstance();
      const response = await apiClient.post('/auth/refresh', {
        refreshToken: state.auth.tokens.refreshToken,
      });

      const { tokens } = response.data;
      await apiClient.setAuthTokens(tokens.accessToken, tokens.refreshToken);

      return tokens;

    } catch (error: any) {
      return rejectWithValue(error.message || 'Token refresh failed');
    }
  }
);

export const validateSession = createAsyncThunk(
  'auth/validateSession',
  async (_, { rejectWithValue }) => {
    try {
      const apiClient = ApiClient.getInstance();
      const response = await apiClient.get('/auth/me');

      return response.data;

    } catch (error: any) {
      return rejectWithValue(error.message || 'Session validation failed');
    }
  }
);

export const setupBiometric = createAsyncThunk(
  'auth/setupBiometric',
  async (_, { rejectWithValue }) => {
    try {
      const biometricService = BiometricService.getInstance();
      const result = await biometricService.enableBiometricAuthentication();

      if (!result.success) {
        throw new Error(result.error || 'Biometric setup failed');
      }

      return true;

    } catch (error: any) {
      return rejectWithValue(error.message || 'Biometric setup failed');
    }
  }
);

export const loginWithBiometric = createAsyncThunk(
  'auth/loginWithBiometric',
  async (_, { rejectWithValue }) => {
    try {
      const biometricService = BiometricService.getInstance();
      const cryptoService = CryptoService.getInstance();

      // Authenticate with biometrics
      const authResult = await biometricService.authenticate(
        'Login to BLNCS',
        'Use your biometric to access your account'
      );

      if (!authResult.success) {
        throw new Error(authResult.error || 'Biometric authentication failed');
      }

      // Retrieve stored credentials
      const username = await cryptoService.secureRetrieve('saved_username');
      if (!username) {
        throw new Error('No saved credentials found');
      }

      // Get stored session token if available
      const apiClient = ApiClient.getInstance();
      const storedToken = await apiClient.getAuthToken();

      if (storedToken) {
        // Validate existing session
        const response = await apiClient.get('/auth/me');
        return response.data;
      } else {
        throw new Error('No valid session found');
      }

    } catch (error: any) {
      return rejectWithValue(error.message || 'Biometric login failed');
    }
  }
);

export const setupMFA = createAsyncThunk(
  'auth/setupMFA',
  async (method: 'totp' | 'sms' | 'email', { rejectWithValue }) => {
    try {
      const apiClient = ApiClient.getInstance();
      const response = await apiClient.post('/auth/mfa/setup', { method });

      return response.data;

    } catch (error: any) {
      return rejectWithValue(error.message || 'MFA setup failed');
    }
  }
);

export const verifyMFA = createAsyncThunk(
  'auth/verifyMFA',
  async (code: string, { rejectWithValue }) => {
    try {
      const apiClient = ApiClient.getInstance();
      const response = await apiClient.post('/auth/mfa/verify', { code });

      return response.data;

    } catch (error: any) {
      return rejectWithValue(error.message || 'MFA verification failed');
    }
  }
);

// Auth slice
const authSlice = createSlice({
  name: 'auth',
  initialState,
  reducers: {
    clearError: (state) => {
      state.error = null;
      state.registrationError = null;
    },

    clearRegistrationError: (state) => {
      state.registrationError = null;
    },

    updateLastActivity: (state) => {
      state.lastActivity = Date.now();
      state.autoLogoutWarningShown = false;
    },

    showAutoLogoutWarning: (state) => {
      state.autoLogoutWarningShown = true;
    },

    setRememberCredentials: (state, action: PayloadAction<boolean>) => {
      state.rememberCredentials = action.payload;
    },

    setAutoLogin: (state, action: PayloadAction<boolean>) => {
      state.autoLogin = action.payload;
    },

    setBiometricPromptShown: (state, action: PayloadAction<boolean>) => {
      state.biometricPromptShown = action.payload;
    },

    updateUserSettings: (state, action: PayloadAction<Partial<User['settings']>>) => {
      if (state.user) {
        state.user.settings = { ...state.user.settings, ...action.payload };
      }
    },

    updateUserProfile: (state, action: PayloadAction<Partial<User>>) => {
      if (state.user) {
        state.user = { ...state.user, ...action.payload };
      }
    },

    resetLoginAttempts: (state) => {
      state.loginAttempts = 0;
      state.isLockedOut = false;
      state.lockoutUntil = 0;
    },

    incrementLoginAttempts: (state) => {
      state.loginAttempts += 1;
      state.lastLoginAttempt = Date.now();

      // Lock out after 5 failed attempts for 15 minutes
      if (state.loginAttempts >= 5) {
        state.isLockedOut = true;
        state.lockoutUntil = Date.now() + 15 * 60 * 1000;
      }
    },

    checkLockoutStatus: (state) => {
      if (state.isLockedOut && Date.now() > state.lockoutUntil) {
        state.isLockedOut = false;
        state.loginAttempts = 0;
        state.lockoutUntil = 0;
      }
    },

    setSessionTimeout: (state, action: PayloadAction<number>) => {
      state.sessionTimeout = action.payload;
    },

    // Reset auth state
    resetAuth: () => initialState,
  },

  extraReducers: (builder) => {
    builder
      // Login
      .addCase(login.pending, (state) => {
        state.isLoading = true;
        state.error = null;
      })
      .addCase(login.fulfilled, (state, action) => {
        state.isLoading = false;
        state.isAuthenticated = true;
        state.user = action.payload.user;
        state.tokens = action.payload.tokens;
        state.loginAttempts = 0;
        state.isLockedOut = false;
        state.lastActivity = Date.now();
        state.error = null;
      })
      .addCase(login.rejected, (state, action) => {
        state.isLoading = false;
        state.error = action.payload as string;
        state.loginAttempts += 1;
        state.lastLoginAttempt = Date.now();

        if (state.loginAttempts >= 5) {
          state.isLockedOut = true;
          state.lockoutUntil = Date.now() + 15 * 60 * 1000;
        }
      })

      // Register
      .addCase(register.pending, (state) => {
        state.isLoading = true;
        state.registrationError = null;
      })
      .addCase(register.fulfilled, (state, action) => {
        state.isLoading = false;
        state.isAuthenticated = true;
        state.user = action.payload.user;
        state.tokens = action.payload.tokens;
        state.lastActivity = Date.now();
        state.registrationError = null;
      })
      .addCase(register.rejected, (state, action) => {
        state.isLoading = false;
        state.registrationError = action.payload as string;
      })

      // Logout
      .addCase(logout.fulfilled, (state) => {
        return { ...initialState };
      })

      // Refresh token
      .addCase(refreshToken.fulfilled, (state, action) => {
        state.tokens = action.payload;
        state.lastActivity = Date.now();
      })
      .addCase(refreshToken.rejected, (state) => {
        // Token refresh failed, logout user
        return { ...initialState };
      })

      // Validate session
      .addCase(validateSession.fulfilled, (state, action) => {
        state.user = action.payload;
        state.lastActivity = Date.now();
      })
      .addCase(validateSession.rejected, (state) => {
        // Session invalid, logout user
        return { ...initialState };
      })

      // Biometric setup
      .addCase(setupBiometric.fulfilled, (state) => {
        state.biometricSetup = true;
      })
      .addCase(setupBiometric.rejected, (state, action) => {
        state.error = action.payload as string;
      })

      // Biometric login
      .addCase(loginWithBiometric.pending, (state) => {
        state.isLoading = true;
        state.error = null;
      })
      .addCase(loginWithBiometric.fulfilled, (state, action) => {
        state.isLoading = false;
        state.isAuthenticated = true;
        state.user = action.payload;
        state.lastActivity = Date.now();
      })
      .addCase(loginWithBiometric.rejected, (state, action) => {
        state.isLoading = false;
        state.error = action.payload as string;
      })

      // MFA setup
      .addCase(setupMFA.fulfilled, (state, action) => {
        state.mfaSetup = true;
        state.mfaMethod = action.meta.arg;
      })
      .addCase(setupMFA.rejected, (state, action) => {
        state.error = action.payload as string;
      })

      // MFA verification
      .addCase(verifyMFA.fulfilled, (state) => {
        state.mfaRequired = false;
      })
      .addCase(verifyMFA.rejected, (state, action) => {
        state.error = action.payload as string;
      });
  },
});

// Actions
export const {
  clearError,
  clearRegistrationError,
  updateLastActivity,
  showAutoLogoutWarning,
  setRememberCredentials,
  setAutoLogin,
  setBiometricPromptShown,
  updateUserSettings,
  updateUserProfile,
  resetLoginAttempts,
  incrementLoginAttempts,
  checkLockoutStatus,
  setSessionTimeout,
  resetAuth,
} = authSlice.actions;

// Selectors
export const selectIsAuthenticated = (state: { auth: AuthState }) => state.auth.isAuthenticated;
export const selectUser = (state: { auth: AuthState }) => state.auth.user;
export const selectIsLoading = (state: { auth: AuthState }) => state.auth.isLoading;
export const selectError = (state: { auth: AuthState }) => state.auth.error;
export const selectRegistrationError = (state: { auth: AuthState }) => state.auth.registrationError;
export const selectTokens = (state: { auth: AuthState }) => state.auth.tokens;
export const selectBiometricSetup = (state: { auth: AuthState }) => state.auth.biometricSetup;
export const selectMfaRequired = (state: { auth: AuthState }) => state.auth.mfaRequired;
export const selectMfaMethod = (state: { auth: AuthState }) => state.auth.mfaMethod;
export const selectIsLockedOut = (state: { auth: AuthState }) => state.auth.isLockedOut;
export const selectLockoutUntil = (state: { auth: AuthState }) => state.auth.lockoutUntil;
export const selectLoginAttempts = (state: { auth: AuthState }) => state.auth.loginAttempts;
export const selectLastActivity = (state: { auth: AuthState }) => state.auth.lastActivity;
export const selectSessionTimeout = (state: { auth: AuthState }) => state.auth.sessionTimeout;
export const selectAutoLogoutWarningShown = (state: { auth: AuthState }) => state.auth.autoLogoutWarningShown;

// Complex selectors
export const selectIsSessionExpired = (state: { auth: AuthState }) => {
  const { lastActivity, sessionTimeout } = state.auth;
  return Date.now() - lastActivity > sessionTimeout;
};

export const selectTimeUntilAutoLogout = (state: { auth: AuthState }) => {
  const { lastActivity, sessionTimeout } = state.auth;
  const elapsed = Date.now() - lastActivity;
  return Math.max(0, sessionTimeout - elapsed);
};

export const selectShouldShowAutoLogoutWarning = (state: { auth: AuthState }) => {
  const timeUntilLogout = selectTimeUntilAutoLogout(state);
  const warningThreshold = 5 * 60 * 1000; // 5 minutes
  return timeUntilLogout <= warningThreshold && timeUntilLogout > 0 && !state.auth.autoLogoutWarningShown;
};

export const selectCanUseBiometric = (state: { auth: AuthState }) => {
  return state.auth.biometricSetup && state.auth.rememberCredentials;
};

export const selectUserPermissions = (state: { auth: AuthState }) => {
  return state.auth.user?.permissions || [];
};

export const selectUserRoles = (state: { auth: AuthState }) => {
  return state.auth.user?.roles || [];
};

export const selectHasPermission = (permission: string) => (state: { auth: AuthState }) => {
  return state.auth.user?.permissions.includes(permission) || false;
};

export const selectHasRole = (role: string) => (state: { auth: AuthState }) => {
  return state.auth.user?.roles.includes(role) || false;
};

export default authSlice.reducer;