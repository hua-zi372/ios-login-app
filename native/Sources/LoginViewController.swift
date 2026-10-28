import UIKit

/// 原生登录界面,纯代码布局,无第三方依赖。
final class LoginViewController: UIViewController {
  private let scrollView = UIScrollView()
  private let card = UIView()
  private let titleLabel = UILabel()
  private let subtitleLabel = UILabel()
  private let usernameField = UITextField()
  private let passwordField = UITextField()
  private let revealButton = UIButton(type: .system)
  private let errorLabel = UILabel()
  private let loginButton = UIButton(type: .system)
  private let spinner = UIActivityIndicatorView(style: .medium)
  private let hintLabel = UILabel()

  override func viewDidLoad() {
    super.viewDidLoad()
    view.backgroundColor = AppConfig.backgroundColor
    buildUI()
    registerKeyboardNotifications()

    let tap = UITapGestureRecognizer(target: self, action: #selector(dismissKeyboard))
    tap.cancelsTouchesInView = false
    view.addGestureRecognizer(tap)
  }

  // MARK: - 布局

  private func buildUI() {
    scrollView.translatesAutoresizingMaskIntoConstraints = false
    scrollView.keyboardDismissMode = .interactive
    view.addSubview(scrollView)

    card.translatesAutoresizingMaskIntoConstraints = false
    card.backgroundColor = .white
    card.layer.cornerRadius = 16
    card.layer.shadowColor = UIColor.black.cgColor
    card.layer.shadowOpacity = 0.08
    card.layer.shadowRadius = 12
    card.layer.shadowOffset = CGSize(width: 0, height: 4)
    scrollView.addSubview(card)

    titleLabel.text = AppConfig.appTitle
    titleLabel.font = .systemFont(ofSize: 26, weight: .bold)
    titleLabel.textColor = .label

    subtitleLabel.text = AppConfig.appSubtitle
    subtitleLabel.font = .systemFont(ofSize: 15)
    subtitleLabel.textColor = .secondaryLabel

    configure(usernameField, placeholder: "用户名")
    usernameField.autocapitalizationType = .none
    usernameField.autocorrectionType = .no
    usernameField.textContentType = .username
    usernameField.returnKeyType = .next
    usernameField.delegate = self

    configure(passwordField, placeholder: "密码")
    passwordField.isSecureTextEntry = true
    passwordField.textContentType = .password
    passwordField.returnKeyType = .go
    passwordField.delegate = self

    revealButton.setTitle("显示", for: .normal)
    revealButton.titleLabel?.font = .systemFont(ofSize: 14, weight: .medium)
    revealButton.setTitleColor(AppConfig.primaryColor, for: .normal)
    revealButton.addTarget(self, action: #selector(toggleSecureEntry), for: .touchUpInside)
    let revealContainer = UIView(frame: CGRect(x: 0, y: 0, width: 56, height: 48))
    revealButton.frame = revealContainer.bounds
    revealContainer.addSubview(revealButton)
    passwordField.rightView = revealContainer
    passwordField.rightViewMode = .always

    errorLabel.font = .systemFont(ofSize: 13)
    errorLabel.textColor = .systemRed
    errorLabel.numberOfLines = 0
    errorLabel.isHidden = true

    loginButton.setTitle("登 录", for: .normal)
    loginButton.titleLabel?.font = .systemFont(ofSize: 17, weight: .semibold)
    loginButton.setTitleColor(.white, for: .normal)
    loginButton.backgroundColor = AppConfig.primaryColor
    loginButton.layer.cornerRadius = 12
    loginButton.addTarget(self, action: #selector(handleLogin), for: .touchUpInside)
    loginButton.translatesAutoresizingMaskIntoConstraints = false
    loginButton.heightAnchor.constraint(equalToConstant: 50).isActive = true

    spinner.translatesAutoresizingMaskIntoConstraints = false
    spinner.color = .white
    spinner.hidesWhenStopped = true
    loginButton.addSubview(spinner)
    NSLayoutConstraint.activate([
      spinner.centerYAnchor.constraint(equalTo: loginButton.centerYAnchor),
      spinner.trailingAnchor.constraint(equalTo: loginButton.trailingAnchor, constant: -18)
    ])

    hintLabel.text = "演示账号:admin / 123456,或 test / test"
    hintLabel.font = .systemFont(ofSize: 12)
    hintLabel.textColor = .tertiaryLabel
    hintLabel.textAlignment = .center
    hintLabel.numberOfLines = 0

    let stack = UIStackView(arrangedSubviews: [
      titleLabel, subtitleLabel, usernameField, passwordField, errorLabel, loginButton, hintLabel
    ])
    stack.axis = .vertical
    stack.spacing = 14
    stack.translatesAutoresizingMaskIntoConstraints = false
    stack.setCustomSpacing(6, after: titleLabel)
    stack.setCustomSpacing(24, after: subtitleLabel)
    stack.setCustomSpacing(18, after: errorLabel)
    stack.setCustomSpacing(18, after: loginButton)
    card.addSubview(stack)

    let frame = scrollView.frameLayoutGuide
    let content = scrollView.contentLayoutGuide

    NSLayoutConstraint.activate([
      scrollView.topAnchor.constraint(equalTo: view.topAnchor),
      scrollView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
      scrollView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
      scrollView.bottomAnchor.constraint(equalTo: view.bottomAnchor),

      card.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 24),
      card.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -24),
      card.topAnchor.constraint(equalTo: content.topAnchor, constant: 60),
      card.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -40),
      // 内容宽度跟随可视区宽度,避免横向滚动
      content.widthAnchor.constraint(equalTo: frame.widthAnchor),

      stack.topAnchor.constraint(equalTo: card.topAnchor, constant: 28),
      stack.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 22),
      stack.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -22),
      stack.bottomAnchor.constraint(equalTo: card.bottomAnchor, constant: -28)
    ])
  }

  private func configure(_ field: UITextField, placeholder: String) {
    field.placeholder = placeholder
    field.font = .systemFont(ofSize: 16)
    field.backgroundColor = UIColor.secondarySystemBackground
    field.layer.cornerRadius = 10
    field.clearButtonMode = .whileEditing
    field.translatesAutoresizingMaskIntoConstraints = false
    field.heightAnchor.constraint(equalToConstant: 48).isActive = true
    field.leftView = UIView(frame: CGRect(x: 0, y: 0, width: 14, height: 48))
    field.leftViewMode = .always
  }

  // MARK: - 登录

  @objc private func toggleSecureEntry() {
    passwordField.isSecureTextEntry.toggle()
    revealButton.setTitle(passwordField.isSecureTextEntry ? "显示" : "隐藏", for: .normal)
  }

  @objc private func handleLogin() {
    dismissKeyboard()

    let username = usernameField.text?.trimmingCharacters(in: .whitespaces) ?? ""
    let password = passwordField.text ?? ""

    guard !username.isEmpty, !password.isEmpty else {
      showError("请输入用户名和密码")
      return
    }

    setLoading(true)
    // 模拟一次网络请求的耗时,让 loading 状态可见
    DispatchQueue.main.asyncAfter(deadline: .now() + 0.6) { [weak self] in
      guard let self else { return }
      self.setLoading(false)

      if AppConfig.validUsers[username] == password {
        let web = WebViewController(username: username)
        AppDelegate.switchRoot(to: UINavigationController(rootViewController: web))
      } else {
        self.showError("用户名或密码不正确")
      }
    }
  }

  private func setLoading(_ loading: Bool) {
    loginButton.isEnabled = !loading
    loginButton.alpha = loading ? 0.7 : 1
    loginButton.setTitle(loading ? "登录中…" : "登 录", for: .normal)
    if loading {
      spinner.startAnimating()
    } else {
      spinner.stopAnimating()
    }
  }

  private func showError(_ message: String) {
    errorLabel.text = message
    errorLabel.isHidden = false
  }

  private func clearError() {
    errorLabel.isHidden = true
  }

  // MARK: - 键盘

  @objc private func dismissKeyboard() {
    view.endEditing(true)
  }

  private func registerKeyboardNotifications() {
    let center = NotificationCenter.default
    center.addObserver(self, selector: #selector(keyboardWillChange(_:)),
                       name: UIResponder.keyboardWillChangeFrameNotification, object: nil)
    center.addObserver(self, selector: #selector(keyboardWillHide),
                       name: UIResponder.keyboardWillHideNotification, object: nil)
  }

  @objc private func keyboardWillChange(_ note: Notification) {
    guard let frame = note.userInfo?[UIResponder.keyboardFrameEndUserInfoKey] as? CGRect else {
      return
    }
    let overlap = max(0, view.bounds.height - frame.origin.y)
    scrollView.contentInset.bottom = overlap
    scrollView.verticalScrollIndicatorInsets.bottom = overlap
  }

  @objc private func keyboardWillHide() {
    scrollView.contentInset.bottom = 0
    scrollView.verticalScrollIndicatorInsets.bottom = 0
  }
}

// MARK: - UITextFieldDelegate

extension LoginViewController: UITextFieldDelegate {
  func textFieldShouldReturn(_ textField: UITextField) -> Bool {
    if textField === usernameField {
      passwordField.becomeFirstResponder()
    } else {
      handleLogin()
    }
    return true
  }

  func textField(_ textField: UITextField,
                 shouldChangeCharactersIn range: NSRange,
                 replacementString string: String) -> Bool {
    clearError()
    return true
  }
}
