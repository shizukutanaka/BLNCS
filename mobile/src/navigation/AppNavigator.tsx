/**
 * Main Application Navigator
 * Handles navigation between authenticated and unauthenticated flows
 */

import React from 'react';
import { createStackNavigator } from '@react-navigation/stack';
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';
import Icon from 'react-native-vector-icons/MaterialIcons';

import { useAuth } from '../contexts/AuthContext';
import { useAppSelector } from '../hooks/redux';

// Auth Screens
import { LoginScreen } from '../screens/auth/LoginScreen';
import { RegisterScreen } from '../screens/auth/RegisterScreen';
import { BiometricSetupScreen } from '../screens/auth/BiometricSetupScreen';
import { PinSetupScreen } from '../screens/auth/PinSetupScreen';

// Main App Screens
import { DashboardScreen } from '../screens/dashboard/DashboardScreen';
import { WalletScreen } from '../screens/wallet/WalletScreen';
import { PaymentsScreen } from '../screens/payments/PaymentsScreen';
import { NodesScreen } from '../screens/nodes/NodesScreen';
import { ChannelsScreen } from '../screens/channels/ChannelsScreen';
import { SettingsScreen } from '../screens/settings/SettingsScreen';

// Transaction Screens
import { SendPaymentScreen } from '../screens/payments/SendPaymentScreen';
import { ReceivePaymentScreen } from '../screens/payments/ReceivePaymentScreen';
import { PaymentDetailsScreen } from '../screens/payments/PaymentDetailsScreen';

// Node Management Screens
import { NodeDetailsScreen } from '../screens/nodes/NodeDetailsScreen';
import { CreateNodeScreen } from '../screens/nodes/CreateNodeScreen';
import { NodeLogsScreen } from '../screens/nodes/NodeLogsScreen';

// Channel Management Screens
import { ChannelDetailsScreen } from '../screens/channels/ChannelDetailsScreen';
import { OpenChannelScreen } from '../screens/channels/OpenChannelScreen';
import { CloseChannelScreen } from '../screens/channels/CloseChannelScreen';

// Settings Screens
import { SecuritySettingsScreen } from '../screens/settings/SecuritySettingsScreen';
import { NetworkSettingsScreen } from '../screens/settings/NetworkSettingsScreen';
import { NotificationSettingsScreen } from '../screens/settings/NotificationSettingsScreen';
import { BackupScreen } from '../screens/settings/BackupScreen';

// Utility Screens
import { QRScannerScreen } from '../screens/utility/QRScannerScreen';
import { AppLockScreen } from '../screens/auth/AppLockScreen';

import { Colors } from '../styles/Colors';
import { Typography } from '../styles/Typography';

const Stack = createStackNavigator();
const Tab = createBottomTabNavigator();

// Navigation Types
export type RootStackParamList = {
  Auth: undefined;
  Main: undefined;
  AppLock: undefined;
};

export type AuthStackParamList = {
  Login: undefined;
  Register: undefined;
  BiometricSetup: undefined;
  PinSetup: undefined;
};

export type MainTabParamList = {
  Dashboard: undefined;
  Wallet: undefined;
  Payments: undefined;
  Nodes: undefined;
  Settings: undefined;
};

export type PaymentStackParamList = {
  PaymentsList: undefined;
  SendPayment: undefined;
  ReceivePayment: undefined;
  PaymentDetails: { paymentId: string };
  QRScanner: { onScan: (data: string) => void };
};

export type NodeStackParamList = {
  NodesList: undefined;
  NodeDetails: { nodeId: string };
  CreateNode: undefined;
  NodeLogs: { nodeId: string };
};

export type ChannelStackParamList = {
  ChannelsList: undefined;
  ChannelDetails: { channelId: string };
  OpenChannel: { nodeId?: string };
  CloseChannel: { channelId: string };
};

export type SettingsStackParamList = {
  SettingsMain: undefined;
  SecuritySettings: undefined;
  NetworkSettings: undefined;
  NotificationSettings: undefined;
  Backup: undefined;
};

// Tab Navigator Configuration
const MainTabs: React.FC = () => {
  return (
    <Tab.Navigator
      screenOptions={({ route }) => ({
        tabBarIcon: ({ focused, color, size }) => {
          let iconName: string;

          switch (route.name) {
            case 'Dashboard':
              iconName = 'dashboard';
              break;
            case 'Wallet':
              iconName = 'account-balance-wallet';
              break;
            case 'Payments':
              iconName = 'payment';
              break;
            case 'Nodes':
              iconName = 'cloud';
              break;
            case 'Settings':
              iconName = 'settings';
              break;
            default:
              iconName = 'help';
          }

          return <Icon name={iconName} size={size} color={color} />;
        },
        tabBarActiveTintColor: Colors.primary,
        tabBarInactiveTintColor: Colors.textSecondary,
        tabBarStyle: {
          backgroundColor: Colors.surface,
          borderTopColor: Colors.border,
          paddingTop: 5,
          paddingBottom: 5,
          height: 60,
        },
        tabBarLabelStyle: {
          fontSize: Typography.fontSize.small,
          fontFamily: Typography.fontFamily.medium,
        },
        headerShown: false,
      })}
    >
      <Tab.Screen name="Dashboard" component={DashboardStackNavigator} />
      <Tab.Screen name="Wallet" component={WalletStackNavigator} />
      <Tab.Screen name="Payments" component={PaymentStackNavigator} />
      <Tab.Screen name="Nodes" component={NodeStackNavigator} />
      <Tab.Screen name="Settings" component={SettingsStackNavigator} />
    </Tab.Navigator>
  );
};

// Stack Navigators for each tab
const DashboardStackNavigator: React.FC = () => (
  <Stack.Navigator
    screenOptions={{
      headerStyle: { backgroundColor: Colors.primary },
      headerTintColor: Colors.textPrimary,
      headerTitleStyle: { fontFamily: Typography.fontFamily.bold },
    }}
  >
    <Stack.Screen
      name="DashboardMain"
      component={DashboardScreen}
      options={{ title: 'Dashboard' }}
    />
  </Stack.Navigator>
);

const WalletStackNavigator: React.FC = () => (
  <Stack.Navigator
    screenOptions={{
      headerStyle: { backgroundColor: Colors.primary },
      headerTintColor: Colors.textPrimary,
      headerTitleStyle: { fontFamily: Typography.fontFamily.bold },
    }}
  >
    <Stack.Screen
      name="WalletMain"
      component={WalletScreen}
      options={{ title: 'Wallet' }}
    />
  </Stack.Navigator>
);

const PaymentStackNavigator: React.FC = () => (
  <Stack.Navigator
    screenOptions={{
      headerStyle: { backgroundColor: Colors.primary },
      headerTintColor: Colors.textPrimary,
      headerTitleStyle: { fontFamily: Typography.fontFamily.bold },
    }}
  >
    <Stack.Screen
      name="PaymentsList"
      component={PaymentsScreen}
      options={{ title: 'Payments' }}
    />
    <Stack.Screen
      name="SendPayment"
      component={SendPaymentScreen}
      options={{ title: 'Send Payment' }}
    />
    <Stack.Screen
      name="ReceivePayment"
      component={ReceivePaymentScreen}
      options={{ title: 'Receive Payment' }}
    />
    <Stack.Screen
      name="PaymentDetails"
      component={PaymentDetailsScreen}
      options={{ title: 'Payment Details' }}
    />
    <Stack.Screen
      name="QRScanner"
      component={QRScannerScreen}
      options={{ title: 'Scan QR Code' }}
    />
  </Stack.Navigator>
);

const NodeStackNavigator: React.FC = () => (
  <Stack.Navigator
    screenOptions={{
      headerStyle: { backgroundColor: Colors.primary },
      headerTintColor: Colors.textPrimary,
      headerTitleStyle: { fontFamily: Typography.fontFamily.bold },
    }}
  >
    <Stack.Screen
      name="NodesList"
      component={NodesScreen}
      options={{ title: 'Lightning Nodes' }}
    />
    <Stack.Screen
      name="NodeDetails"
      component={NodeDetailsScreen}
      options={{ title: 'Node Details' }}
    />
    <Stack.Screen
      name="CreateNode"
      component={CreateNodeScreen}
      options={{ title: 'Create Node' }}
    />
    <Stack.Screen
      name="NodeLogs"
      component={NodeLogsScreen}
      options={{ title: 'Node Logs' }}
    />
    <Stack.Screen
      name="ChannelsList"
      component={ChannelsScreen}
      options={{ title: 'Channels' }}
    />
    <Stack.Screen
      name="ChannelDetails"
      component={ChannelDetailsScreen}
      options={{ title: 'Channel Details' }}
    />
    <Stack.Screen
      name="OpenChannel"
      component={OpenChannelScreen}
      options={{ title: 'Open Channel' }}
    />
    <Stack.Screen
      name="CloseChannel"
      component={CloseChannelScreen}
      options={{ title: 'Close Channel' }}
    />
  </Stack.Navigator>
);

const SettingsStackNavigator: React.FC = () => (
  <Stack.Navigator
    screenOptions={{
      headerStyle: { backgroundColor: Colors.primary },
      headerTintColor: Colors.textPrimary,
      headerTitleStyle: { fontFamily: Typography.fontFamily.bold },
    }}
  >
    <Stack.Screen
      name="SettingsMain"
      component={SettingsScreen}
      options={{ title: 'Settings' }}
    />
    <Stack.Screen
      name="SecuritySettings"
      component={SecuritySettingsScreen}
      options={{ title: 'Security' }}
    />
    <Stack.Screen
      name="NetworkSettings"
      component={NetworkSettingsScreen}
      options={{ title: 'Network' }}
    />
    <Stack.Screen
      name="NotificationSettings"
      component={NotificationSettingsScreen}
      options={{ title: 'Notifications' }}
    />
    <Stack.Screen
      name="Backup"
      component={BackupScreen}
      options={{ title: 'Backup & Recovery' }}
    />
  </Stack.Navigator>
);

// Auth Stack Navigator
const AuthNavigator: React.FC = () => (
  <Stack.Navigator
    screenOptions={{
      headerShown: false,
      cardStyle: { backgroundColor: Colors.background },
    }}
  >
    <Stack.Screen name="Login" component={LoginScreen} />
    <Stack.Screen name="Register" component={RegisterScreen} />
    <Stack.Screen name="BiometricSetup" component={BiometricSetupScreen} />
    <Stack.Screen name="PinSetup" component={PinSetupScreen} />
  </Stack.Navigator>
);

// Main App Navigator
export const AppNavigator: React.FC = () => {
  const { isAuthenticated } = useAuth();
  const { isLocked } = useAppSelector(state => state.app);

  if (isLocked) {
    return (
      <Stack.Navigator screenOptions={{ headerShown: false }}>
        <Stack.Screen name="AppLock" component={AppLockScreen} />
      </Stack.Navigator>
    );
  }

  return (
    <Stack.Navigator
      screenOptions={{ headerShown: false }}
      initialRouteName={isAuthenticated ? 'Main' : 'Auth'}
    >
      {isAuthenticated ? (
        <Stack.Screen name="Main" component={MainTabs} />
      ) : (
        <Stack.Screen name="Auth" component={AuthNavigator} />
      )}
    </Stack.Navigator>
  );
};