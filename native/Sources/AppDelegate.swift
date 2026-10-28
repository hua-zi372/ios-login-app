import UIKit

@main
final class AppDelegate: UIResponder, UIApplicationDelegate {
  var window: UIWindow?

  func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
  ) -> Bool {
    let window = UIWindow(frame: UIScreen.main.bounds)
    window.rootViewController = LoginViewController()
    window.makeKeyAndVisible()
    self.window = window
    return true
  }

  /// 登录成功后把根控制器换成网页页面,退出登录时换回登录页。
  static func switchRoot(to viewController: UIViewController) {
    guard let delegate = UIApplication.shared.delegate as? AppDelegate,
          let window = delegate.window else {
      return
    }
    UIView.transition(with: window, duration: 0.25, options: .transitionCrossDissolve) {
      window.rootViewController = viewController
    }
  }
}
