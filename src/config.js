// 应用配置:登录凭据、登录后加载的网页地址、应用标题
// 你可以直接修改这里的内容

export const APP_CONFIG = {
  // 应用名称(显示在登录页顶部)
  APP_TITLE: 'IPA 登录演示',

  // 演示用账号密码(可增删;实际项目请替换为真实后端校验)
  VALID_USERS: [
    { username: 'admin', password: '123456' },
    { username: 'test', password: 'test' },
  ],

  // 登录成功后 WebView 加载的首页地址
  HOME_URL: 'https://www.bing.com',
};
