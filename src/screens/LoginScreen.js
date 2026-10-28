import React, { useRef, useState } from 'react';
import {
  ActivityIndicator,
  KeyboardAvoidingView,
  Platform,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  TouchableOpacity,
  View,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { APP_CONFIG } from '../config';

/**
 * 原生登录界面
 * 使用 React Native 原生组件渲染(TextInput 在 iOS 上即原生 UITextField),
 * 校验通过后通过 onLogin 回调把用户信息传给上层。
 */
export default function LoginScreen({ onLogin }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const passwordRef = useRef(null);

  function handleLogin() {
    const u = username.trim();
    const p = password;

    if (!u || !p) {
      setError('请输入用户名和密码');
      return;
    }

    setError('');
    setLoading(true);

    // 模拟网络请求延迟;实际项目可替换为真实登录接口(fetch/axios)
    setTimeout(() => {
      const matched = APP_CONFIG.VALID_USERS.find(
        (item) => item.username === u && item.password === p
      );
      setLoading(false);

      if (matched) {
        onLogin({ username: matched.username });
      } else {
        setError('用户名或密码错误');
      }
    }, 600);
  }

  return (
    <SafeAreaView style={styles.safe}>
      <KeyboardAvoidingView
        style={styles.flex}
        behavior={Platform.OS === 'ios' ? 'padding' : undefined}
      >
        <ScrollView
          contentContainerStyle={styles.container}
          keyboardShouldPersistTaps="handled"
        >
          {/* 顶部品牌区 */}
          <View style={styles.brand}>
            <View style={styles.logo}>
              <Text style={styles.logoText}>IPA</Text>
            </View>
            <Text style={styles.title}>{APP_CONFIG.APP_TITLE}</Text>
            <Text style={styles.subtitle}>请使用账号登录后继续</Text>
          </View>

          {/* 表单卡片 */}
          <View style={styles.card}>
            <Text style={styles.label}>用户名</Text>
            <TextInput
              style={styles.input}
              placeholder="请输入用户名"
              placeholderTextColor="#9AA0A6"
              value={username}
              onChangeText={setTextSafe(setUsername, setError)}
              autoCapitalize="none"
              autoCorrect={false}
              returnKeyType="next"
              onSubmitEditing={() => passwordRef.current && passwordRef.current.focus()}
            />

            <Text style={styles.label}>密码</Text>
            <View style={styles.passwordRow}>
              <TextInput
                ref={passwordRef}
                style={styles.passwordInput}
                placeholder="请输入密码"
                placeholderTextColor="#9AA0A6"
                value={password}
                onChangeText={setTextSafe(setPassword, setError)}
                secureTextEntry={!showPassword}
                autoCapitalize="none"
                autoCorrect={false}
                returnKeyType="go"
                onSubmitEditing={handleLogin}
              />
              <TouchableOpacity
                style={styles.toggleBtn}
                onPress={() => setShowPassword((v) => !v)}
                hitSlop={{ top: 8, bottom: 8, left: 8, right: 8 }}
              >
                <Text style={styles.toggleText}>{showPassword ? '隐藏' : '显示'}</Text>
              </TouchableOpacity>
            </View>

            {error ? <Text style={styles.error}>{error}</Text> : null}

            <TouchableOpacity
              style={[styles.button, loading && styles.buttonDisabled]}
              onPress={handleLogin}
              activeOpacity={0.85}
              disabled={loading}
            >
              {loading ? (
                <ActivityIndicator color="#FFFFFF" />
              ) : (
                <Text style={styles.buttonText}>登 录</Text>
              )}
            </TouchableOpacity>

            <Text style={styles.hint}>
              演示账号:admin / 123456
            </Text>
          </View>
        </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

// 输入时清除错误提示的小工具
function setTextSafe(setter, setError) {
  return (value) => {
    setter(value);
    setError('');
  };
}

const styles = StyleSheet.create({
  safe: { flex: 1, backgroundColor: '#F5F7FB' },
  flex: { flex: 1 },
  container: {
    flexGrow: 1,
    justifyContent: 'center',
    padding: 24,
  },
  brand: {
    alignItems: 'center',
    marginBottom: 28,
  },
  logo: {
    width: 72,
    height: 72,
    borderRadius: 20,
    backgroundColor: '#2F6FED',
    alignItems: 'center',
    justifyContent: 'center',
    marginBottom: 16,
    shadowColor: '#2F6FED',
    shadowOpacity: 0.3,
    shadowRadius: 12,
    shadowOffset: { width: 0, height: 6 },
    elevation: 6,
  },
  logoText: {
    color: '#FFFFFF',
    fontSize: 22,
    fontWeight: '700',
    letterSpacing: 1,
  },
  title: {
    fontSize: 22,
    fontWeight: '700',
    color: '#1A1A1A',
  },
  subtitle: {
    fontSize: 14,
    color: '#6B7280',
    marginTop: 6,
  },
  card: {
    backgroundColor: '#FFFFFF',
    borderRadius: 18,
    padding: 20,
    shadowColor: '#000',
    shadowOpacity: 0.06,
    shadowRadius: 16,
    shadowOffset: { width: 0, height: 4 },
    elevation: 3,
  },
  label: {
    fontSize: 13,
    color: '#374151',
    marginBottom: 8,
    marginTop: 4,
    fontWeight: '600',
  },
  input: {
    height: 48,
    borderWidth: 1,
    borderColor: '#E5E7EB',
    borderRadius: 12,
    paddingHorizontal: 14,
    fontSize: 16,
    color: '#1A1A1A',
    backgroundColor: '#FBFBFD',
    marginBottom: 16,
  },
  passwordRow: {
    flexDirection: 'row',
    alignItems: 'center',
    borderWidth: 1,
    borderColor: '#E5E7EB',
    borderRadius: 12,
    backgroundColor: '#FBFBFD',
    marginBottom: 8,
    paddingRight: 6,
  },
  passwordInput: {
    flex: 1,
    height: 48,
    paddingHorizontal: 14,
    fontSize: 16,
    color: '#1A1A1A',
  },
  toggleBtn: {
    paddingHorizontal: 10,
    paddingVertical: 8,
  },
  toggleText: {
    color: '#2F6FED',
    fontSize: 13,
    fontWeight: '600',
  },
  error: {
    color: '#E5484D',
    fontSize: 13,
    marginTop: 4,
    marginBottom: 4,
  },
  button: {
    height: 50,
    borderRadius: 12,
    backgroundColor: '#2F6FED',
    alignItems: 'center',
    justifyContent: 'center',
    marginTop: 16,
  },
  buttonDisabled: {
    opacity: 0.7,
  },
  buttonText: {
    color: '#FFFFFF',
    fontSize: 17,
    fontWeight: '700',
    letterSpacing: 2,
  },
  hint: {
    textAlign: 'center',
    color: '#9AA0A6',
    fontSize: 12,
    marginTop: 16,
  },
});
