import React, { useRef, useState } from 'react';
import {
  ActivityIndicator,
  StyleSheet,
  Text,
  TouchableOpacity,
  View,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { WebView } from 'react-native-webview';
import { APP_CONFIG } from '../config';

/**
 * 登录成功后的网页页面
 * 顶部是原生导航栏(显示已登录用户、刷新、退出),
 * 下方用 react-native-webview 加载配置的网页。
 */
export default function WebScreen({ user, onLogout }) {
  const webRef = useRef(null);
  const [loading, setLoading] = useState(true);
  const [currentUrl, setCurrentUrl] = useState(APP_CONFIG.HOME_URL);

  return (
    <SafeAreaView style={styles.safe} edges={['top']}>
      {/* 原生导航栏 */}
      <View style={styles.header}>
        <View style={styles.headerLeft}>
          <Text style={styles.headerTitle} numberOfLines={1}>
            已登录:{user.username}
          </Text>
        </View>
        <View style={styles.headerActions}>
          <TouchableOpacity
            style={styles.headerBtn}
            onPress={() => webRef.current && webRef.current.reload()}
            hitSlop={{ top: 8, bottom: 8, left: 8, right: 8 }}
          >
            <Text style={styles.headerBtnText}>刷新</Text>
          </TouchableOpacity>
          <TouchableOpacity
            style={[styles.headerBtn, styles.logoutBtn]}
            onPress={onLogout}
            hitSlop={{ top: 8, bottom: 8, left: 8, right: 8 }}
          >
            <Text style={[styles.headerBtnText, styles.logoutText]}>退出</Text>
          </TouchableOpacity>
        </View>
      </View>

      {/* 网页区域 */}
      <View style={styles.webWrap}>
        <WebView
          ref={webRef}
          source={{ uri: APP_CONFIG.HOME_URL }}
          style={styles.flex}
          onLoadStart={() => setLoading(true)}
          onLoadEnd={() => setLoading(false)}
          onNavigationStateChange={(navState) => {
            if (navState && navState.url) setCurrentUrl(navState.url);
          }}
          startInLoadingState
          javaScriptEnabled
          domStorageEnabled
          allowsInlineMediaPlayback
        />
        {loading && (
          <View style={styles.loadingOverlay}>
            <ActivityIndicator size="large" color="#2F6FED" />
          </View>
        )}
      </View>

      {/* 底部地址栏 */}
      <View style={styles.urlBar}>
        <Text style={styles.urlText} numberOfLines={1}>
          {currentUrl}
        </Text>
      </View>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  safe: { flex: 1, backgroundColor: '#FFFFFF' },
  flex: { flex: 1 },
  header: {
    height: 52,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingHorizontal: 16,
    backgroundColor: '#2F6FED',
  },
  headerLeft: {
    flex: 1,
    paddingRight: 8,
  },
  headerTitle: {
    color: '#FFFFFF',
    fontSize: 16,
    fontWeight: '600',
  },
  headerActions: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  headerBtn: {
    paddingHorizontal: 12,
    paddingVertical: 6,
    borderRadius: 8,
    marginLeft: 8,
    backgroundColor: 'rgba(255,255,255,0.18)',
  },
  headerBtnText: {
    color: '#FFFFFF',
    fontSize: 14,
    fontWeight: '600',
  },
  logoutBtn: {
    backgroundColor: 'rgba(255,255,255,0.28)',
  },
  logoutText: {
    color: '#FFFFFF',
  },
  webWrap: {
    flex: 1,
    backgroundColor: '#FFFFFF',
  },
  loadingOverlay: {
    ...StyleSheet.absoluteFillObject,
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: 'rgba(255,255,255,0.6)',
  },
  urlBar: {
    height: 30,
    justifyContent: 'center',
    paddingHorizontal: 12,
    backgroundColor: '#F5F7FB',
    borderTopWidth: StyleSheet.hairlineWidth,
    borderTopColor: '#E5E7EB',
  },
  urlText: {
    color: '#6B7280',
    fontSize: 12,
  },
});
