/**
 * Notification Service
 * Handles push notifications, local notifications, and in-app messaging
 */

import { Platform, Alert, Linking, AppState } from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { check, request, PERMISSIONS, RESULTS } from 'react-native-permissions';
import PushNotification, { Importance } from 'react-native-push-notification';

export interface NotificationConfig {
  enabled: boolean;
  soundEnabled: boolean;
  vibrationEnabled: boolean;
  badgeEnabled: boolean;
  categories: {
    payments: boolean;
    channels: boolean;
    nodes: boolean;
    security: boolean;
    system: boolean;
  };
}

export interface NotificationData {
  id: string;
  title: string;
  message: string;
  data?: any;
  category: string;
  priority: 'high' | 'normal' | 'low';
  timestamp: number;
  read: boolean;
}

export interface PushNotificationPayload {
  title: string;
  body: string;
  data?: any;
  badge?: number;
  sound?: string;
  category?: string;
  scheduledTime?: Date;
}

export class NotificationService {
  private static instance: NotificationService;
  private config: NotificationConfig;
  private notifications: NotificationData[] = [];
  private listeners: Set<(notification: NotificationData) => void> = new Set();
  private isInitialized = false;

  private constructor() {
    this.config = {
      enabled: true,
      soundEnabled: true,
      vibrationEnabled: true,
      badgeEnabled: true,
      categories: {
        payments: true,
        channels: true,
        nodes: true,
        security: true,
        system: true,
      },
    };

    this.loadConfig();
  }

  public static getInstance(): NotificationService {
    if (!NotificationService.instance) {
      NotificationService.instance = new NotificationService();
    }
    return NotificationService.instance;
  }

  public static async initialize(): Promise<void> {
    const service = NotificationService.getInstance();
    await service.initializeService();
  }

  public static showNotification(title: string, message: string, data?: any): void {
    const service = NotificationService.getInstance();
    service.showLocalNotification({
      title,
      body: message,
      data,
      category: 'general',
    });
  }

  private async initializeService(): Promise<void> {
    try {
      await this.requestPermissions();
      await this.configureNotifications();
      await this.loadNotificationHistory();
      this.isInitialized = true;
    } catch (error) {
      console.error('Failed to initialize notification service:', error);
    }
  }

  private async loadConfig(): Promise<void> {
    try {
      const savedConfig = await AsyncStorage.getItem('notification_config');
      if (savedConfig) {
        this.config = { ...this.config, ...JSON.parse(savedConfig) };
      }
    } catch (error) {
      console.error('Failed to load notification config:', error);
    }
  }

  private async saveConfig(): Promise<void> {
    try {
      await AsyncStorage.setItem('notification_config', JSON.stringify(this.config));
    } catch (error) {
      console.error('Failed to save notification config:', error);
    }
  }

  private async requestPermissions(): Promise<boolean> {
    try {
      if (Platform.OS === 'ios') {
        const result = await request(PERMISSIONS.IOS.NOTIFICATION);
        return result === RESULTS.GRANTED;
      } else {
        const result = await request(PERMISSIONS.ANDROID.POST_NOTIFICATIONS);
        return result === RESULTS.GRANTED;
      }
    } catch (error) {
      console.error('Failed to request notification permissions:', error);
      return false;
    }
  }

  private async configureNotifications(): Promise<void> {
    try {
      // Configure push notifications
      PushNotification.configure({
        onRegister: (token) => {
          console.log('FCM Token:', token);
          this.handleTokenRegistration(token.token);
        },

        onNotification: (notification) => {
          console.log('Notification received:', notification);
          this.handleNotificationReceived(notification);
        },

        onAction: (notification) => {
          console.log('Notification action:', notification);
          this.handleNotificationAction(notification);
        },

        onRegistrationError: (error) => {
          console.error('FCM registration error:', error);
        },

        permissions: {
          alert: true,
          badge: true,
          sound: true,
        },

        popInitialNotification: true,
        requestPermissions: true,
      });

      // Create notification channels for Android
      if (Platform.OS === 'android') {
        this.createNotificationChannels();
      }

    } catch (error) {
      console.error('Failed to configure notifications:', error);
    }
  }

  private createNotificationChannels(): void {
    const channels = [
      {
        channelId: 'payments',
        channelName: 'Payment Notifications',
        channelDescription: 'Notifications about Lightning payments',
        playSound: this.config.soundEnabled,
        soundName: 'default',
        importance: Importance.HIGH,
        vibrate: this.config.vibrationEnabled,
      },
      {
        channelId: 'channels',
        channelName: 'Channel Notifications',
        channelDescription: 'Notifications about Lightning channels',
        playSound: this.config.soundEnabled,
        soundName: 'default',
        importance: Importance.HIGH,
        vibrate: this.config.vibrationEnabled,
      },
      {
        channelId: 'nodes',
        channelName: 'Node Notifications',
        channelDescription: 'Notifications about Lightning nodes',
        playSound: this.config.soundEnabled,
        soundName: 'default',
        importance: Importance.HIGH,
        vibrate: this.config.vibrationEnabled,
      },
      {
        channelId: 'security',
        channelName: 'Security Alerts',
        channelDescription: 'Important security notifications',
        playSound: true,
        soundName: 'default',
        importance: Importance.HIGH,
        vibrate: true,
      },
      {
        channelId: 'system',
        channelName: 'System Notifications',
        channelDescription: 'General system notifications',
        playSound: this.config.soundEnabled,
        soundName: 'default',
        importance: Importance.DEFAULT,
        vibrate: this.config.vibrationEnabled,
      },
    ];

    channels.forEach(channel => {
      PushNotification.createChannel(channel, () => {
        console.log(`Created notification channel: ${channel.channelId}`);
      });
    });
  }

  private async handleTokenRegistration(token: string): Promise<void> {
    try {
      // Store token locally
      await AsyncStorage.setItem('fcm_token', token);

      // Send token to server
      // This would typically involve an API call to your backend
      console.log('FCM Token stored:', token);

    } catch (error) {
      console.error('Failed to handle token registration:', error);
    }
  }

  private handleNotificationReceived(notification: any): void {
    if (!this.config.enabled) return;

    const notificationData: NotificationData = {
      id: notification.id || Date.now().toString(),
      title: notification.title || '',
      message: notification.message || notification.body || '',
      data: notification.data,
      category: notification.category || 'general',
      priority: notification.priority || 'normal',
      timestamp: Date.now(),
      read: false,
    };

    // Add to notification history
    this.addNotificationToHistory(notificationData);

    // Notify listeners
    this.notifyListeners(notificationData);

    // Handle app state-specific behavior
    if (AppState.currentState === 'active') {
      // App is in foreground, show in-app notification
      this.showInAppNotification(notificationData);
    } else {
      // App is in background, notification already shown by system
      this.updateBadgeCount();
    }
  }

  private handleNotificationAction(notification: any): void {
    console.log('Notification action triggered:', notification);

    // Handle different notification actions
    switch (notification.action) {
      case 'view_payment':
        this.handleViewPayment(notification.data);
        break;
      case 'open_channel':
        this.handleOpenChannel(notification.data);
        break;
      case 'view_node':
        this.handleViewNode(notification.data);
        break;
      default:
        // Open app to main screen
        break;
    }
  }

  private handleViewPayment(data: any): void {
    // Navigate to payment details
    // This would typically use navigation service
    console.log('Navigate to payment:', data);
  }

  private handleOpenChannel(data: any): void {
    // Navigate to channel details
    console.log('Navigate to channel:', data);
  }

  private handleViewNode(data: any): void {
    // Navigate to node details
    console.log('Navigate to node:', data);
  }

  public async showLocalNotification(payload: PushNotificationPayload): Promise<void> {
    if (!this.config.enabled) return;

    const category = payload.category || 'system';
    if (!this.config.categories[category]) return;

    try {
      const notificationId = Date.now().toString();

      const notificationOptions = {
        id: notificationId,
        channelId: category,
        title: payload.title,
        message: payload.body,
        data: payload.data,
        playSound: this.config.soundEnabled,
        soundName: payload.sound || 'default',
        number: payload.badge,
        vibrate: this.config.vibrationEnabled,
        priority: payload.category === 'security' ? 'high' : 'default',
        importance: payload.category === 'security' ? Importance.HIGH : Importance.DEFAULT,
        invokeApp: true,
        when: null,
        usesChronometer: false,
        timeoutAfter: null,
        date: payload.scheduledTime,
      };

      if (payload.scheduledTime) {
        PushNotification.localNotificationSchedule(notificationOptions);
      } else {
        PushNotification.localNotification(notificationOptions);
      }

      // Add to history
      const notificationData: NotificationData = {
        id: notificationId,
        title: payload.title,
        message: payload.body,
        data: payload.data,
        category,
        priority: 'normal',
        timestamp: Date.now(),
        read: false,
      };

      this.addNotificationToHistory(notificationData);
      this.updateBadgeCount();

    } catch (error) {
      console.error('Failed to show local notification:', error);
    }
  }

  public cancelNotification(notificationId: string): void {
    PushNotification.cancelLocalNotifications({ id: notificationId });
  }

  public cancelAllNotifications(): void {
    PushNotification.cancelAllLocalNotifications();
  }

  private showInAppNotification(notification: NotificationData): void {
    // Show banner-style notification when app is active
    Alert.alert(
      notification.title,
      notification.message,
      [
        { text: 'Dismiss', style: 'cancel' },
        { text: 'View', onPress: () => this.handleNotificationTap(notification) },
      ]
    );
  }

  private handleNotificationTap(notification: NotificationData): void {
    // Mark as read
    this.markNotificationAsRead(notification.id);

    // Handle notification-specific actions
    switch (notification.category) {
      case 'payments':
        this.handleViewPayment(notification.data);
        break;
      case 'channels':
        this.handleOpenChannel(notification.data);
        break;
      case 'nodes':
        this.handleViewNode(notification.data);
        break;
      default:
        break;
    }
  }

  private async addNotificationToHistory(notification: NotificationData): Promise<void> {
    try {
      this.notifications.unshift(notification);

      // Keep only last 100 notifications
      if (this.notifications.length > 100) {
        this.notifications = this.notifications.slice(0, 100);
      }

      await this.saveNotificationHistory();
    } catch (error) {
      console.error('Failed to add notification to history:', error);
    }
  }

  private async loadNotificationHistory(): Promise<void> {
    try {
      const history = await AsyncStorage.getItem('notification_history');
      if (history) {
        this.notifications = JSON.parse(history);
      }
    } catch (error) {
      console.error('Failed to load notification history:', error);
    }
  }

  private async saveNotificationHistory(): Promise<void> {
    try {
      await AsyncStorage.setItem('notification_history', JSON.stringify(this.notifications));
    } catch (error) {
      console.error('Failed to save notification history:', error);
    }
  }

  public getNotifications(): NotificationData[] {
    return [...this.notifications];
  }

  public getUnreadNotifications(): NotificationData[] {
    return this.notifications.filter(n => !n.read);
  }

  public getUnreadCount(): number {
    return this.getUnreadNotifications().length;
  }

  public markNotificationAsRead(notificationId: string): void {
    const notification = this.notifications.find(n => n.id === notificationId);
    if (notification) {
      notification.read = true;
      this.saveNotificationHistory();
      this.updateBadgeCount();
    }
  }

  public markAllAsRead(): void {
    this.notifications.forEach(n => n.read = true);
    this.saveNotificationHistory();
    this.updateBadgeCount();
  }

  public clearNotificationHistory(): void {
    this.notifications = [];
    this.saveNotificationHistory();
    this.updateBadgeCount();
  }

  private updateBadgeCount(): void {
    if (!this.config.badgeEnabled) return;

    const unreadCount = this.getUnreadCount();
    PushNotification.setApplicationIconBadgeNumber(unreadCount);
  }

  public addListener(listener: (notification: NotificationData) => void): void {
    this.listeners.add(listener);
  }

  public removeListener(listener: (notification: NotificationData) => void): void {
    this.listeners.delete(listener);
  }

  private notifyListeners(notification: NotificationData): void {
    this.listeners.forEach(listener => {
      try {
        listener(notification);
      } catch (error) {
        console.error('Notification listener error:', error);
      }
    });
  }

  public async updateConfig(newConfig: Partial<NotificationConfig>): Promise<void> {
    this.config = { ...this.config, ...newConfig };
    await this.saveConfig();

    // Update channels if Android
    if (Platform.OS === 'android') {
      this.createNotificationChannels();
    }
  }

  public getConfig(): NotificationConfig {
    return { ...this.config };
  }

  public async getFCMToken(): Promise<string | null> {
    try {
      return await AsyncStorage.getItem('fcm_token');
    } catch (error) {
      console.error('Failed to get FCM token:', error);
      return null;
    }
  }

  public async schedulePaymentReminder(
    paymentHash: string,
    amount: number,
    delay: number
  ): Promise<void> {
    const scheduledTime = new Date(Date.now() + delay);

    await this.showLocalNotification({
      title: 'Payment Reminder',
      body: `Don't forget about your pending payment of ${amount} sats`,
      data: { type: 'payment_reminder', paymentHash },
      category: 'payments',
      scheduledTime,
    });
  }

  public async scheduleChannelBalanceAlert(
    channelId: string,
    threshold: number
  ): Promise<void> {
    await this.showLocalNotification({
      title: 'Channel Balance Alert',
      body: `Channel balance is below ${threshold}% threshold`,
      data: { type: 'balance_alert', channelId },
      category: 'channels',
    });
  }

  public async scheduleNodeMaintenanceNotification(
    nodeId: string,
    maintenanceTime: Date
  ): Promise<void> {
    const notificationTime = new Date(maintenanceTime.getTime() - 30 * 60 * 1000); // 30 minutes before

    await this.showLocalNotification({
      title: 'Scheduled Maintenance',
      body: 'Node maintenance is scheduled to begin in 30 minutes',
      data: { type: 'maintenance', nodeId },
      category: 'nodes',
      scheduledTime: notificationTime,
    });
  }

  public isInitialized(): boolean {
    return this.isInitialized;
  }

  public async openNotificationSettings(): Promise<void> {
    try {
      await Linking.openSettings();
    } catch (error) {
      console.error('Failed to open notification settings:', error);
    }
  }
}

export default NotificationService;