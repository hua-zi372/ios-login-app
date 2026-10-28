import React, { useState } from 'react';
import { StatusBar } from 'expo-status-bar';
import { SafeAreaProvider } from 'react-native-safe-area-context';
import LoginScreen from './src/screens/LoginScreen';
import WebScreen from './src/screens/WebScreen';

/**
 * 应用入口:
 * - 未登录 -> 显示原生登录界面
 * - 已登录 -> 显示加载网页的 WebView 界面
 */
export default function App() {
  const [user, setUser] = useState(null);

  return (
    <SafeAreaProvider>
      <StatusBar style="light" />
      {user ? (
        <WebScreen user={user} onLogout={() => setUser(null)} />
      ) : (
        <LoginScreen onLogin={(u) => setUser(u)} />
      )}
    </SafeAreaProvider>
  );
}
