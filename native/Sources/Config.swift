import Foundation
import UIKit

/// 改这里就能改账号和登录后打开的网页。
enum AppConfig {
  static let appTitle = "登录演示"
  static let appSubtitle = "登录后打开网页"

  /// 登录成功后加载的网址
  static let homeURL = URL(string: "https://www.bing.com")!

  /// 可用账号:用户名 -> 密码
  static let validUsers: [String: String] = [
    "admin": "123456",
    "test": "test"
  ]

  static let primaryColor = UIColor(red: 0.184, green: 0.435, blue: 0.929, alpha: 1)
  static let backgroundColor = UIColor(red: 0.953, green: 0.961, blue: 0.976, alpha: 1)
}
