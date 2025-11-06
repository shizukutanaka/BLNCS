/**
 * BLNCS Mobile Application
 * React Native app for Lightning Network Control System
 */

import React, { useEffect, useState } from 'react';
import {
  StatusBar,
  Platform,
  Alert,
  AppState,
  AppStateStatus,
} from 'react-native';
import { NavigationContainer } from '@react-navigation/native';
import { Provider } from 'react-redux';
import { PersistGate } from 'redux-persist/integration/react';
import SplashScreen from 'react-native-splash-screen';
import NetInfo from '@react-native-community/netinfo';
import { SafeAreaProvider } from 'react-native-safe-area-context';
import * as Keychain from 'react-native-keychain';

import { store, persistor } from './src/store/store';
import { AppNavigator } from './src/navigation/AppNavigator';
import { LoadingScreen } from './src/components/LoadingScreen';
import { ErrorBoundary } from './src/components/ErrorBoundary';
import { BiometricService } from './src/services/BiometricService';
import { CryptoService } from './src/services/CryptoService';
import { LightningService } from './src/services/LightningService';
import { ThemeProvider } from './src/contexts/ThemeContext';
import { AuthProvider } from './src/contexts/AuthContext';
import { NotificationProvider } from './src/contexts/NotificationContext';
import { useAppDispatch, useAppSelector } from './src/hooks/redux';
import {
  setNetworkStatus,
  setAppState,
  initializeApp,
  lockApp,
  unlockApp
} from './src/store/slices/appSlice';
import { Colors } from './src/styles/Colors';

const AppContent: React.FC = () => {
  const dispatch = useAppDispatch();
  const { isInitialized, isLocked, biometricEnabled } = useAppSelector(state => state.app);
  const [isReady, setIsReady] = useState(false);

  useEffect(() => {
    initializeApplication();
  }, []);

  useEffect(() => {
    // Network monitoring
    const unsubscribeNetInfo = NetInfo.addEventListener(state => {
      dispatch(setNetworkStatus({
        isConnected: state.isConnected || false,
        type: state.type,
        isInternetReachable: state.isInternetReachable || false,
      }));
    });

    // App state monitoring
    const handleAppStateChange = (nextAppState: AppStateStatus) => {
      dispatch(setAppState(nextAppState));

      if (nextAppState === 'background' || nextAppState === 'inactive') {
        handleAppBackground();
      } else if (nextAppState === 'active') {
        handleAppForeground();
      }
    };

    const appStateSubscription = AppState.addEventListener('change', handleAppStateChange);

    return () => {
      unsubscribeNetInfo();
      appStateSubscription?.remove();
    };
  }, [dispatch]);

  const initializeApplication = async () => {
    try {
      // Initialize crypto service
      await CryptoService.initialize();

      // Initialize biometric service
      await BiometricService.initialize();

      // Initialize Lightning service
      await LightningService.initialize();

      // Check if app should be locked
      const shouldLock = await checkAppLockRequired();
      if (shouldLock) {
        dispatch(lockApp());
      }

      dispatch(initializeApp());
      setIsReady(true);

      // Hide splash screen
      if (Platform.OS === 'android') {
        SplashScreen.hide();
      }

    } catch (error) {
      console.error('App initialization failed:', error);
      Alert.alert(
        'Initialization Error',
        'Failed to initialize the application. Please restart.',
        [{ text: 'OK', onPress: () => setIsReady(true) }]
      );
    }
  };

  const checkAppLockRequired = async (): Promise<boolean> => {
    try {
      const lastActiveTime = await Keychain.getInternetCredentials('lastActiveTime');
      if (lastActiveTime.username) {
        const lastActive = parseInt(lastActiveTime.username, 10);
        const now = Date.now();
        const timeDiff = now - lastActive;

        // Lock app if inactive for more than 5 minutes
        return timeDiff > 5 * 60 * 1000;
      }
    } catch (error) {
      console.error('Error checking app lock requirement:', error);
    }
    return false;
  };

  const handleAppBackground = async () => {
    try {
      // Store last active time
      await Keychain.setInternetCredentials(
        'lastActiveTime',
        Date.now().toString(),
        ''
      );

      // Lock app immediately if biometric is enabled
      if (biometricEnabled) {
        dispatch(lockApp());
      }
    } catch (error) {
      console.error('Error handling app background:', error);
    }
  };

  const handleAppForeground = async () => {
    try {
      if (isLocked && biometricEnabled) {
        const biometricResult = await BiometricService.authenticate(
          'Unlock BLNCS',
          'Use your biometric to access the app'
        );

        if (biometricResult.success) {
          dispatch(unlockApp());
        }
      }
    } catch (error) {
      console.error('Error handling app foreground:', error);
    }
  };

  if (!isReady || !isInitialized) {
    return <LoadingScreen />;
  }

  return (
    <NavigationContainer>
      <StatusBar
        barStyle="light-content"
        backgroundColor={Colors.primary}
        translucent={false}
      />
      <AppNavigator />
    </NavigationContainer>
  );
};

const App: React.FC = () => {
  return (
    <ErrorBoundary>
      <Provider store={store}>
        <PersistGate loading={<LoadingScreen />} persistor={persistor}>
          <SafeAreaProvider>
            <ThemeProvider>
              <AuthProvider>
                <NotificationProvider>
                  <AppContent />
                </NotificationProvider>
              </AuthProvider>
            </ThemeProvider>
          </SafeAreaProvider>
        </PersistGate>
      </Provider>
    </ErrorBoundary>
  );
};

export default App;