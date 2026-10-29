import UIKit

final class DiagnosticsButton: UIButton {
  override init(frame: CGRect) {
    super.init(frame: frame)
    commonInit()
  }

  required init?(coder: NSCoder) {
    super.init(coder: coder)
    commonInit()
  }

  private func commonInit() {
    setTitle("🧪", for: .normal)
    titleLabel?.font = .systemFont(ofSize: 20)
    backgroundColor = UIColor.systemBackground.withAlphaComponent(0.86)
    tintColor = AppConfig.primaryColor
    layer.cornerRadius = 22
    layer.shadowColor = UIColor.black.cgColor
    layer.shadowOpacity = 0.18
    layer.shadowRadius = 8
    layer.shadowOffset = CGSize(width: 0, height: 2)
    accessibilityLabel = "打开诊断日志"
    addTarget(self, action: #selector(openLogs), for: .touchUpInside)
  }

  @objc private func openLogs() {
    guard let window = window else { return }
    let vc = DiagnosticsViewController()
    vc.modalPresentationStyle = .pageSheet
    window.rootViewController?.present(vc, animated: true)
  }
}

enum Diagnostics {
  static var documentsURL: URL {
    let urls = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)
    return urls.first ?? URL(fileURLWithPath: NSTemporaryDirectory())
  }

  static var diagURL: URL { documentsURL.appendingPathComponent("diag.log") }
  static var loaderURL: URL { documentsURL.appendingPathComponent("loader89.log") }

  static func install(in window: UIWindow) {
    logLaunchInfo()
    let button = DiagnosticsButton(frame: CGRect(x: 0, y: 0, width: 44, height: 44))
    button.translatesAutoresizingMaskIntoConstraints = false
    window.addSubview(button)
    NSLayoutConstraint.activate([
      button.trailingAnchor.constraint(equalTo: window.safeAreaLayoutGuide.trailingAnchor, constant: -14),
      button.bottomAnchor.constraint(equalTo: window.safeAreaLayoutGuide.bottomAnchor, constant: -18),
      button.widthAnchor.constraint(equalToConstant: 44),
      button.heightAnchor.constraint(equalToConstant: 44)
    ])
    window.bringSubviewToFront(button)
  }

  static func log(_ message: String) {
    let line = "[\(Date())] \(message)\n"
    guard let data = line.data(using: .utf8) else { return }
    if let handle = try? FileHandle(forWritingTo: diagURL) {
      _ = try? handle.seekToEnd()
      try? handle.write(contentsOf: data)
      try? handle.close()
    } else {
      try? data.write(to: diagURL)
    }
    NSLog("%@", line)
  }

  private static func logLaunchInfo() {
    let info = Bundle.main.infoDictionary ?? [:]
    log("app launch")
    log("bundleId=\(Bundle.main.bundleIdentifier ?? "-")")
    log("version=\(info["CFBundleShortVersionString"] ?? "-") build=\(info["CFBundleVersion"] ?? "-")")
    log("executablePath=\(Bundle.main.executablePath?.path ?? "-")")
    log("bundlePath=\(Bundle.main.bundlePath)")
    log("home=\(ProcessInfo.processInfo.environment["HOME"] ?? "-")")
    log("fileSharing=\(info["UIFileSharingEnabled"] ?? "-") openInPlace=\(info["LSSupportsOpeningDocumentsInPlace"] ?? "-")")
    log("diagPath=\(diagURL.path)")
    log("loaderLogPath=\(loaderURL.path)")
  }

  static func readTail(_ url: URL, maxBytes: Int = 65536) -> String {
    guard let data = try? Data(contentsOf: url) else { return "" }
    let clipped = data.count > maxBytes ? data.suffix(maxBytes) : data
    return String(data: clipped, encoding: .utf8) ?? ""
  }

  static func combinedText() -> String {
    let diag = readTail(diagURL)
    let loader = readTail(loaderURL)
    return """
    === diag.log ===
    \(diag.isEmpty ? "(empty)" : diag)

    === loader89.log ===
    \(loader.isEmpty ? "(empty)" : loader)
    """
  }
}

final class DiagnosticsViewController: UIViewController {
  private let textView = UITextView()
  private let statusLabel = UILabel()

  override func viewDidLoad() {
    super.viewDidLoad()
    view.backgroundColor = .systemBackground
    navigationItem.title = "诊断日志"
    navigationItem.rightBarButtonItem = UIBarButtonItem(title: "关闭", style: .plain, target: self, action: #selector(close))

    textView.font = UIFont.monospacedSystemFont(ofSize: 12, weight: .regular)
    textView.isEditable = false
    textView.alwaysBounceVertical = true
    textView.translatesAutoresizingMaskIntoConstraints = false
    view.addSubview(textView)

    statusLabel.font = .systemFont(ofSize: 12)
    statusLabel.textColor = .secondaryLabel
    statusLabel.numberOfLines = 0
    statusLabel.translatesAutoresizingMaskIntoConstraints = false
    view.addSubview(statusLabel)

    let stack = UIStackView(arrangedSubviews: [
      makeButton("刷新", #selector(refresh)),
      makeButton("复制", #selector(copyAll)),
      makeButton("分享", #selector(shareLogs)),
      makeButton("上传", #selector(uploadLogs))
    ])
    stack.axis = .horizontal
    stack.distribution = .fillEqually
    stack.spacing = 8
    stack.translatesAutoresizingMaskIntoConstraints = false
    view.addSubview(stack)

    NSLayoutConstraint.activate([
      statusLabel.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 8),
      statusLabel.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
      statusLabel.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),

      stack.topAnchor.constraint(equalTo: statusLabel.bottomAnchor, constant: 8),
      stack.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
      stack.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),

      textView.topAnchor.constraint(equalTo: stack.bottomAnchor, constant: 8),
      textView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
      textView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
      textView.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor)
    ])

    refresh()
  }

  private func makeButton(_ title: String, _ action: Selector) -> UIButton {
    let b = UIButton(type: .system)
    b.setTitle(title, for: .normal)
    b.backgroundColor = .secondarySystemBackground
    b.layer.cornerRadius = 8
    b.addTarget(self, action: action, for: .touchUpInside)
    return b
  }

  @objc private func close() { dismiss(animated: true) }

  @objc private func refresh() {
    textView.text = Diagnostics.combinedText()
    statusLabel.text = "documents: \(Diagnostics.documentsURL.path)"
  }

  @objc private func copyAll() {
    UIPasteboard.general.string = textView.text ?? ""
    statusLabel.text = "已复制到剪贴板"
  }

  @objc private func shareLogs() {
    let items: [Any] = [Diagnostics.diagURL, Diagnostics.loaderURL]
    let vc = UIActivityViewController(activityItems: items, applicationActivities: nil)
    vc.popoverPresentationController?.sourceView = view
    present(vc, animated: true)
  }

  @objc private func uploadLogs() {
    guard let url = AppConfig.diagnosticsUploadURL else {
      statusLabel.text = "未配置上传地址"
      return
    }
    var req = URLRequest(url: url)
    req.httpMethod = "POST"
    req.httpBody = (textView.text ?? "").data(using: .utf8)
    statusLabel.text = "上传中..."
    URLSession.shared.dataTask(with: req) { [weak self] _, response, error in
      DispatchQueue.main.async {
        if let error = error {
          self?.statusLabel.text = "上传失败: \(error.localizedDescription)"
        } else {
          self?.statusLabel.text = "上传完成: \((response as? HTTPURLResponse)?.statusCode ?? 0)"
        }
      }
    }.resume()
  }
}
