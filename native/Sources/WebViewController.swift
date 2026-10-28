import UIKit
import WebKit

/// 登录后的网页页面:原生导航栏 + WKWebView。
final class WebViewController: UIViewController {
  private let username: String
  private let webView: WKWebView
  private let progressBar = UIProgressView(progressViewStyle: .bar)
  private let urlLabel = UILabel()
  private var progressObservation: NSKeyValueObservation?
  private var urlObservation: NSKeyValueObservation?

  init(username: String) {
    self.username = username
    let configuration = WKWebViewConfiguration()
    configuration.allowsInlineMediaPlayback = true
    self.webView = WKWebView(frame: .zero, configuration: configuration)
    super.init(nibName: nil, bundle: nil)
  }

  @available(*, unavailable)
  required init?(coder: NSCoder) {
    fatalError("init(coder:) has not been implemented")
  }

  override func viewDidLoad() {
    super.viewDidLoad()
    view.backgroundColor = .systemBackground
    setupNavigationBar()
    setupSubviews()
    observeWebView()
    webView.load(URLRequest(url: AppConfig.homeURL))
  }

  private func setupNavigationBar() {
    title = "已登录:\(username)"
    navigationItem.rightBarButtonItem = UIBarButtonItem(
      title: "退出", style: .plain, target: self, action: #selector(handleLogout)
    )
    navigationItem.leftBarButtonItem = UIBarButtonItem(
      barButtonSystemItem: .refresh, target: self, action: #selector(handleReload)
    )
  }

  private func setupSubviews() {
    webView.translatesAutoresizingMaskIntoConstraints = false
    webView.allowsBackForwardNavigationGestures = true
    webView.navigationDelegate = self
    view.addSubview(webView)

    progressBar.translatesAutoresizingMaskIntoConstraints = false
    progressBar.progressTintColor = AppConfig.primaryColor
    progressBar.trackTintColor = .clear
    view.addSubview(progressBar)

    urlLabel.translatesAutoresizingMaskIntoConstraints = false
    urlLabel.font = .systemFont(ofSize: 11)
    urlLabel.textColor = .secondaryLabel
    urlLabel.textAlignment = .center
    urlLabel.lineBreakMode = .byTruncatingMiddle
    urlLabel.backgroundColor = AppConfig.backgroundColor
    urlLabel.text = AppConfig.homeURL.absoluteString
    view.addSubview(urlLabel)

    NSLayoutConstraint.activate([
      progressBar.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
      progressBar.leadingAnchor.constraint(equalTo: view.leadingAnchor),
      progressBar.trailingAnchor.constraint(equalTo: view.trailingAnchor),
      progressBar.heightAnchor.constraint(equalToConstant: 2),

      webView.topAnchor.constraint(equalTo: progressBar.bottomAnchor),
      webView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
      webView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
      webView.bottomAnchor.constraint(equalTo: urlLabel.topAnchor),

      urlLabel.leadingAnchor.constraint(equalTo: view.leadingAnchor),
      urlLabel.trailingAnchor.constraint(equalTo: view.trailingAnchor),
      urlLabel.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor),
      urlLabel.heightAnchor.constraint(equalToConstant: 22)
    ])
  }

  private func observeWebView() {
    progressObservation = webView.observe(\.estimatedProgress, options: [.new]) { [weak self] webView, _ in
      guard let self else { return }
      let progress = Float(webView.estimatedProgress)
      self.progressBar.setProgress(progress, animated: true)
      self.progressBar.isHidden = progress >= 1.0
    }
    urlObservation = webView.observe(\.url, options: [.new]) { [weak self] webView, _ in
      self?.urlLabel.text = webView.url?.absoluteString
    }
  }

  @objc private func handleReload() {
    if webView.url == nil {
      webView.load(URLRequest(url: AppConfig.homeURL))
    } else {
      webView.reload()
    }
  }

  @objc private func handleLogout() {
    let alert = UIAlertController(title: "退出登录", message: "确定要退出吗?", preferredStyle: .alert)
    alert.addAction(UIAlertAction(title: "取消", style: .cancel))
    alert.addAction(UIAlertAction(title: "退出", style: .destructive) { _ in
      AppDelegate.switchRoot(to: LoginViewController())
    })
    present(alert, animated: true)
  }
}

// MARK: - WKNavigationDelegate

extension WebViewController: WKNavigationDelegate {
  func webView(_ webView: WKWebView, didStartProvisionalNavigation navigation: WKNavigation!) {
    progressBar.isHidden = false
  }

  func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
    progressBar.isHidden = true
  }

  func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
    showLoadFailure(error)
  }

  func webView(_ webView: WKWebView,
               didFailProvisionalNavigation navigation: WKNavigation!,
               withError error: Error) {
    showLoadFailure(error)
  }

  private func showLoadFailure(_ error: Error) {
    progressBar.isHidden = true
    // 用户主动中断导航不算加载失败,不必打扰
    let nsError = error as NSError
    guard nsError.code != NSURLErrorCancelled else { return }

    let alert = UIAlertController(
      title: "网页加载失败",
      message: error.localizedDescription,
      preferredStyle: .alert
    )
    alert.addAction(UIAlertAction(title: "重试", style: .default) { [weak self] _ in
      self?.handleReload()
    })
    alert.addAction(UIAlertAction(title: "好", style: .cancel))
    present(alert, animated: true)
  }
}
