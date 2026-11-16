import SwiftUI
import Foundation
import Security
import PhotosUI
import UIKit
import UniformTypeIdentifiers
import Compression

// MARK: - 数据模型
struct PickedFile: Identifiable {
    let id = UUID()
    var data: Data
    var filename: String
    var isImage: Bool
    var purpose: String      // user_data / text_recognition / rich_layout_recognition
    var mimeType: String
    var isZip: Bool
}

struct MessageAttachment: Identifiable, Codable {
    var id = UUID()
    var filename: String
    var isImage: Bool
    var fileId: String?
    var thumbBase64: String?
}

struct ChatMessage: Identifiable, Codable {
    enum Role: String, Codable { case user, assistant }
    var id = UUID()
    var role: Role
    var content: String
    var attachments: [MessageAttachment] = []
}

struct Conversation: Identifiable, Codable {
    var id = UUID()
    var title: String = "新对话"
    var messages: [ChatMessage] = []
    var updatedAt: Date = Date()
}

struct ChatRequestError: Error { let message: String }

enum StreamEvent {
    case text(String)
    case status(String)
}

struct ModelInfo: Identifiable, Decodable {
    let id: String
    let name: String?
    let owned_by: String?
    let input_modalities: [String]?
    var display: String {
        if let n = name, !n.isEmpty { return n }
        return id
    }
}

struct ModelsResponse: Decodable { let data: [ModelInfo] }

// MARK: - 文件类型识别
enum FileClassifier {
    static func make(from url: URL) -> PickedFile? {
        let access = url.startAccessingSecurityScopedResource()
        defer { if access { url.stopAccessingSecurityScopedResource() } }
        guard let data = try? Data(contentsOf: url) else { return nil }
        let name = url.lastPathComponent
        let ext = url.pathExtension.lowercased()
        var purpose = "user_data"
        var isImage = false
        var isZip = false
        var mime = "application/octet-stream"
        switch ext {
        case "jpg", "jpeg": isImage = true; mime = "image/jpeg"
        case "png": isImage = true; mime = "image/png"
        case "gif": isImage = true; mime = "image/gif"
        case "webp": isImage = true; mime = "image/webp"
        case "pdf": purpose = "text_recognition"; mime = "application/pdf"
        case "doc": purpose = "text_recognition"; mime = "application/msword"
        case "docx": purpose = "text_recognition"; mime = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        case "ppt": purpose = "text_recognition"; mime = "application/vnd.ms-powerpoint"
        case "pptx": purpose = "text_recognition"; mime = "application/vnd.openxmlformats-officedocument.presentationml.presentation"
        case "xlsx": mime = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        case "xls": mime = "application/vnd.ms-excel"
        case "epub": mime = "application/epub+zip"
        case "zip": isZip = true; mime = "application/zip"
        case "txt", "md", "csv", "json", "xml", "html", "swift", "py", "js", "ts", "c", "cpp", "java":
            mime = "text/plain"
        default:
            mime = "application/octet-stream"
        }
        return PickedFile(data: data, filename: name, isImage: isImage,
                          purpose: purpose, mimeType: mime, isZip: isZip)
    }

    static func image(from data: Data) -> PickedFile? {
        let jpeg: Data
        if let ui = UIImage(data: data), let j = ui.jpegData(compressionQuality: 0.85) {
            jpeg = j
        } else {
            jpeg = data
        }
        return PickedFile(data: jpeg, filename: "photo.jpg", isImage: true,
                          purpose: "user_data", mimeType: "image/jpeg", isZip: false)
    }

    static func thumbnail(from data: Data) -> String? {
        guard let ui = UIImage(data: data) else { return nil }
        let maxSide: CGFloat = 320
        let ratio = min(1, maxSide / max(ui.size.width, ui.size.height))
        let size = CGSize(width: max(1, ui.size.width * ratio), height: max(1, ui.size.height * ratio))
        UIGraphicsBeginImageContextWithOptions(size, false, 1)
        ui.draw(in: CGRect(origin: .zero, size: size))
        let img = UIGraphicsGetImageFromCurrentImageContext()
        UIGraphicsEndImageContext()
        return img?.jpegData(compressionQuality: 0.7)?.base64EncodedString()
    }
}

// MARK: - 钥匙串
enum Keychain {
    static let service = "com.colin.deepseekchat"
    static func save(_ value: String, for key: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key
        ]
        SecItemDelete(query as CFDictionary)
        guard !value.isEmpty else { return }
        var add = query
        add[kSecValueData as String] = Data(value.utf8)
        add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        SecItemAdd(add as CFDictionary, nil)
    }
    static func read(_ key: String) -> String {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        if SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
           let data = item as? Data, let s = String(data: data, encoding: .utf8) {
            return s
        }
        return ""
    }
}

// MARK: - ZIP 解析（本地解压并抽取文本）
enum ZipReader {
    static func extractText(from data: Data, maxTotal: Int = 150_000) -> String {
        guard data.count > 22 else { return "" }
        var eocd = -1
        let minPos = max(0, data.count - 22 - 65535)
        var i = data.count - 22
        while i >= minPos {
            if u32(data, i) == 0x06054b50 { eocd = i; break }
            i -= 1
        }
        guard eocd >= 0 else { return "" }
        let total = u16(data, eocd + 10)
        let cdOffset = u32(data, eocd + 16)
        guard cdOffset > 0, cdOffset < data.count else { return "" }
        var pos = cdOffset
        var result = ""
        var idx = 0
        while idx < total, pos + 46 <= data.count {
            guard u32(data, pos) == 0x02014b50 else { break }
            let method = u16(data, pos + 10)
            let compSize = u32(data, pos + 20)
            let uncompSize = u32(data, pos + 24)
            let nameLen = u16(data, pos + 28)
            let extraLen = u16(data, pos + 30)
            let commentLen = u16(data, pos + 32)
            let localOff = u32(data, pos + 42)
            guard pos + 46 + nameLen <= data.count else { break }
            let name = String(data: data.subdata(in: pos + 46 ..< pos + 46 + nameLen), encoding: .utf8) ?? "file\(idx)"
            if shouldInclude(name), localOff + 30 <= data.count {
                let lnameLen = u16(data, localOff + 26)
                let lextraLen = u16(data, localOff + 28)
                let dataStart = localOff + 30 + lnameLen + lextraLen
                if dataStart + compSize <= data.count, compSize > 0 {
                    let comp = data.subdata(in: dataStart ..< dataStart + compSize)
                    var fileData: Data? = nil
                    if method == 0 {
                        fileData = comp
                    } else if method == 8 {
                        fileData = inflate(comp, expected: min(uncompSize, 5_000_000))
                    }
                    if let fd = fileData, let text = decodeText(fd) {
                        let clipped = String(text.prefix(60_000))
                        let piece = "\n--- \(name) ---\n" + clipped + "\n"
                        if result.count + piece.count <= maxTotal {
                            result += piece
                        } else {
                            let remain = maxTotal - result.count
                            if remain > 0 { result += String(piece.prefix(remain)) }
                            break
                        }
                    }
                }
            }
            pos += 46 + nameLen + extraLen + commentLen
            idx += 1
            if result.count >= maxTotal { break }
        }
        return result
    }

    private static func shouldInclude(_ name: String) -> Bool {
        let lower = name.lowercased()
        if lower.hasSuffix("/") { return false }
        let ext = (lower as NSString).pathExtension
        let textExts: Set<String> = ["txt","md","markdown","csv","tsv","json","xml","html","htm","yml","yaml",
            "swift","py","js","ts","jsx","tsx","c","h","cpp","hpp","java","go","rs","rb","php",
            "sh","bash","log","ini","toml","sql","r","m","tex","cfg","conf","gradle","properties","plist"]
        if textExts.contains(ext) { return true }
        if ext.isEmpty { return true }
        return false
    }

    private static func decodeText(_ d: Data) -> String? {
        if let s = String(data: d, encoding: .utf8) { return s }
        if let s = String(data: d, encoding: .isoLatin1) { return s }
        return nil
    }

    private static func inflate(_ input: Data, expected: Int) -> Data? {
        let capacity = max(expected, input.count * 4, 4096)
        var dst = Data(count: capacity)
        let n = dst.withUnsafeMutableBytes { (dptr: UnsafeMutableRawBufferPointer) -> Int in
            input.withUnsafeBytes { (sptr: UnsafeRawBufferPointer) -> Int in
                guard let dbase = dptr.bindMemory(to: UInt8.self).baseAddress,
                      let sbase = sptr.bindMemory(to: UInt8.self).baseAddress else { return 0 }
                return compression_decode_buffer(dbase, capacity, sbase, input.count, nil, COMPRESSION_ZLIB)
            }
        }
        if n <= 0 { return nil }
        return Data(dst.prefix(n))
    }

    private static func u16(_ d: Data, _ off: Int) -> Int {
        let i = d.startIndex + off
        guard i + 1 < d.endIndex else { return 0 }
        return Int(d[i]) | (Int(d[i + 1]) << 8)
    }
    private static func u32(_ d: Data, _ off: Int) -> Int {
        let i = d.startIndex + off
        guard i + 3 < d.endIndex else { return 0 }
        return Int(d[i]) | (Int(d[i + 1]) << 8) | (Int(d[i + 2]) << 16) | (Int(d[i + 3]) << 24)
    }
}

// MARK: - DeepSeek 网络客户端
final class DeepSeekClient {
    let apiBase: String
    let apiKey: String
    let model: String
    let webSearch: Bool
    init(apiBase: String, apiKey: String, model: String, webSearch: Bool) {
        self.apiBase = apiBase
        self.apiKey = apiKey
        self.model = model
        self.webSearch = webSearch
    }

    func cleanedBase() -> String {
        apiBase.trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
    }

    func uploadFile(_ f: PickedFile) async throws -> String {
        guard let url = URL(string: cleanedBase() + "/files") else {
            throw ChatRequestError(message: "API 地址无效")
        }
        let boundary = "Boundary-\(UUID().uuidString)"
        var body = Data()
        func app(_ s: String) { if let d = s.data(using: .utf8) { body.append(d) } }
        app("--\(boundary)\r\n")
        app("Content-Disposition: form-data; name=\"purpose\"\r\n\r\n")
        app("\(f.purpose)\r\n")
        app("--\(boundary)\r\n")
        app("Content-Disposition: form-data; name=\"file\"; filename=\"\(f.filename)\"\r\n")
        app("Content-Type: \(f.mimeType)\r\n\r\n")
        body.append(f.data)
        app("\r\n--\(boundary)--\r\n")

        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("Bearer \(apiKey)", forHTTPHeaderField: "Authorization")
        req.setValue("multipart/form-data; boundary=\(boundary)", forHTTPHeaderField: "Content-Type")
        let (data, resp) = try await URLSession.shared.upload(for: req, from: body)
        guard let http = resp as? HTTPURLResponse else {
            throw ChatRequestError(message: "上传无响应")
        }
        if http.statusCode != 200 {
            let t = String(data: data, encoding: .utf8) ?? ""
            throw ChatRequestError(message: "上传失败 HTTP \(http.statusCode)\n\(t)")
        }
        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let id = obj["id"] as? String else {
            throw ChatRequestError(message: "上传返回异常")
        }
        return id
    }

    private func encodeMessages(_ msgs: [ChatMessage]) -> [[String: Any]] {
        msgs.map { m in
            let files = (m.attachments).filter { $0.fileId != nil }
            if !files.isEmpty {
                var blocks: [[String: Any]] = []
                if !m.content.isEmpty { blocks.append(["type": "text", "text": m.content]) }
                for f in files { blocks.append(["type": "file", "file_id": f.fileId!]) }
                return ["role": m.role.rawValue, "content": blocks]
            } else {
                return ["role": m.role.rawValue, "content": m.content]
            }
        }
    }

    func stream(messages: [ChatMessage]) -> AsyncThrowingStream<StreamEvent, Error> {
        AsyncThrowingStream { continuation in
            let task = Task {
                do {
                    guard let url = URL(string: cleanedBase() + "/chat/completions") else {
                        throw ChatRequestError(message: "API 地址无效")
                    }
                    var req = URLRequest(url: url)
                    req.httpMethod = "POST"
                    req.setValue("application/json", forHTTPHeaderField: "Content-Type")
                    req.setValue("Bearer \(apiKey)", forHTTPHeaderField: "Authorization")
                    var body: [String: Any] = [
                        "model": model,
                        "stream": true,
                        "messages": encodeMessages(messages)
                    ]
                    if webSearch {
                        body["tools"] = [
                            ["type": "deepseek_web_search"],
                            ["type": "deepseek_read_url"]
                        ]
                    }
                    req.httpBody = try JSONSerialization.data(withJSONObject: body)

                    let (bytes, response) = try await URLSession.shared.bytes(for: req)
                    guard let http = response as? HTTPURLResponse else {
                        throw ChatRequestError(message: "无响应")
                    }
                    if http.statusCode != 200 {
                        var errText = ""
                        for try await line in bytes.lines { errText += line }
                        throw ChatRequestError(message: "HTTP \(http.statusCode)\n\(errText)")
                    }
                    var full = ""
                    for try await line in bytes.lines {
                        guard line.hasPrefix("data:") else { continue }
                        let payload = line.dropFirst(5).trimmingCharacters(in: .whitespaces)
                        if payload == "[DONE]" { break }
                        guard let d = payload.data(using: .utf8),
                              let obj = try? JSONSerialization.jsonObject(with: d) as? [String: Any] else { continue }
                        if let err = obj["error"] as? [String: Any] {
                            let msg = err["message"] as? String ?? "未知错误"
                            throw ChatRequestError(message: msg)
                        }
                        guard let choices = obj["choices"] as? [[String: Any]],
                              let choice = choices.first else { continue }
                        if let ev = choice["server_tool_event"] as? [String: Any],
                           let et = ev["type"] as? String {
                            if et == "call_started" {
                                var label = "🔧 正在处理…"
                                if let call = ev["call"] as? [String: Any],
                                   let kind = call["kind"] as? String {
                                    if kind.contains("search") { label = "🔍 正在联网搜索…" }
                                    else if kind.contains("read") { label = "📄 正在读取网页…" }
                                }
                                continuation.yield(.status(label))
                            } else if et == "call_completed" {
                                continuation.yield(.status(""))
                            }
                        }
                        if let delta = choice["delta"] as? [String: Any],
                           let c = delta["content"] as? String, !c.isEmpty {
                            full += c
                            continuation.yield(.text(full))
                        }
                    }
                    continuation.finish()
                } catch {
                    continuation.finish(throwing: error)
                }
            }
            continuation.onTermination = { _ in task.cancel() }
        }
    }
}

// MARK: - 状态管理
@MainActor
final class ChatStore: ObservableObject {
    @Published var conversations: [Conversation] = []
    @Published var currentID: UUID = UUID()
    @Published var isSending = false
    @Published var errorText: String?
    @Published var statusText: String?

    @Published var apiBase: String
    @Published var models: [ModelInfo] = [
        ModelInfo(id: "deepseek-chat", name: "deepseek-chat", owned_by: nil, input_modalities: ["text"]),
        ModelInfo(id: "deepseek-reasoner", name: "deepseek-reasoner", owned_by: nil, input_modalities: ["text"])
    ]
    @Published var selectedModel: String
    @Published var webSearch: Bool
    var apiKey: String

    private var fileURL: URL {
        let dir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        return dir.appendingPathComponent("conversations.json")
    }

    init() {
        apiBase = UserDefaults.standard.string(forKey: "apiBase") ?? "https://api.deepseek.com"
        selectedModel = UserDefaults.standard.string(forKey: "model") ?? "deepseek-chat"
        webSearch = UserDefaults.standard.bool(forKey: "webSearch")
        apiKey = Keychain.read("apiKey")
        load()
    }

    // 当前会话
    var currentIndex: Int? { conversations.firstIndex { $0.id == currentID } }
    var messages: [ChatMessage] {
        if let i = currentIndex { return conversations[i].messages }
        return []
    }
    var currentTitle: String {
        if let i = currentIndex { return conversations[i].title }
        return "我的 DeepSeek"
    }
    var currentModelDisplay: String {
        models.first(where: { $0.id == selectedModel })?.display ?? selectedModel
    }

    // 持久化
    func load() {
        if let data = try? Data(contentsOf: fileURL),
           let decoded = try? JSONDecoder().decode([Conversation].self, from: data),
           !decoded.isEmpty {
            conversations = decoded
            if let saved = UserDefaults.standard.string(forKey: "currentID"), let u = UUID(uuidString: saved),
               conversations.contains(where: { $0.id == u }) {
                currentID = u
            } else {
                currentID = conversations[0].id
            }
        } else {
            let c = Conversation()
            conversations = [c]
            currentID = c.id
        }
    }

    func persist() {
        if let data = try? JSONEncoder().encode(conversations) {
            try? data.write(to: fileURL)
        }
        UserDefaults.standard.set(currentID.uuidString, forKey: "currentID")
    }

    // 会话操作
    func newConversation() {
        let c = Conversation()
        conversations.insert(c, at: 0)
        currentID = c.id
        errorText = nil
        statusText = nil
        persist()
    }

    func select(_ id: UUID) {
        currentID = id
        errorText = nil
        statusText = nil
        persist()
    }

    func delete(_ id: UUID) {
        conversations.removeAll { $0.id == id }
        if conversations.isEmpty {
            let c = Conversation()
            conversations = [c]
            currentID = c.id
        } else if currentID == id {
            currentID = conversations[0].id
        }
        persist()
    }

    func clearCurrent() {
        guard let i = currentIndex else { return }
        var conv = conversations[i]
        conv.messages.removeAll()
        conversations[i] = conv
        errorText = nil
        statusText = nil
        persist()
    }

    private func appendToCurrent(_ msg: ChatMessage) {
        guard let i = currentIndex else { return }
        var conv = conversations[i]
        conv.messages.append(msg)
        if conv.title == "新对话", msg.role == .user, !msg.content.isEmpty {
            conv.title = String(msg.content.prefix(20))
        }
        conv.updatedAt = Date()
        conversations[i] = conv
    }

    private func setContent(_ msgIndex: Int, _ text: String) {
        guard let i = currentIndex, msgIndex < conversations[i].messages.count else { return }
        var conv = conversations[i]
        conv.messages[msgIndex].content = text
        conversations[i] = conv
    }

    func exportText() -> String {
        var s = "# \(currentTitle)\n\n"
        for m in messages {
            s += (m.role == .user ? "我：" : "AI：") + m.content + "\n\n"
            for a in m.attachments {
                s += "［附件：\(a.filename)］\n"
            }
        }
        return s
    }

    // 设置
    func saveSettings(apiKey: String, apiBase: String, model: String, webSearch: Bool) {
        self.apiKey = apiKey
        self.apiBase = apiBase
        self.selectedModel = model
        self.webSearch = webSearch
        Keychain.save(apiKey, for: "apiKey")
        UserDefaults.standard.set(apiBase, forKey: "apiBase")
        UserDefaults.standard.set(model, forKey: "model")
        UserDefaults.standard.set(webSearch, forKey: "webSearch")
    }

    func toggleWebSearch() {
        webSearch.toggle()
        UserDefaults.standard.set(webSearch, forKey: "webSearch")
    }

    func loadModels() async {
        guard !apiKey.isEmpty else { return }
        let base = apiBase.trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        guard let url = URL(string: base + "/models") else { return }
        var req = URLRequest(url: url)
        req.setValue("Bearer \(apiKey)", forHTTPHeaderField: "Authorization")
        do {
            let (data, _) = try await URLSession.shared.data(for: req)
            let decoded = try JSONDecoder().decode(ModelsResponse.self, from: data)
            if !decoded.data.isEmpty {
                models = decoded.data
                if !models.contains(where: { $0.id == selectedModel }) {
                    selectedModel = models.first!.id
                    UserDefaults.standard.set(selectedModel, forKey: "model")
                }
                if errorText?.hasPrefix("模型列表获取失败") == true { errorText = nil }
            }
        } catch {
            if errorText == nil {
                errorText = "模型列表获取失败：\(error.localizedDescription)"
            }
        }
    }

    // 发送
    func send(_ text: String, files: [PickedFile]) async {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty || !files.isEmpty else { return }
        guard !isSending else { return }
        guard !apiKey.isEmpty else {
            errorText = "请先在设置里填写 API Key"
            return
        }
        errorText = nil
        statusText = nil
        isSending = true

        var meta: [MessageAttachment] = []
        var zipText = ""
        do {
            for f in files where f.isZip {
                statusText = "正在解析压缩包 \(f.filename)…"
                let t = ZipReader.extractText(from: f.data)
                zipText += t.isEmpty ? "\n--- \(f.filename)：未找到可读文本 ---\n" : t
            }
            for f in files where !f.isZip {
                statusText = "正在上传 \(f.filename)…"
                let uploader = DeepSeekClient(apiBase: apiBase, apiKey: apiKey, model: selectedModel, webSearch: false)
                let fid = try await uploader.uploadFile(f)
                let thumb = f.isImage ? FileClassifier.thumbnail(from: f.data) : nil
                meta.append(MessageAttachment(filename: f.filename, isImage: f.isImage, fileId: fid, thumbBase64: thumb))
            }
        } catch {
            let msg = (error as? ChatRequestError)?.message ?? error.localizedDescription
            errorText = "处理文件失败：\(msg)"
            statusText = nil
            isSending = false
            return
        }
        statusText = nil

        var finalText = trimmed
        if !zipText.isEmpty {
            finalText += (finalText.isEmpty ? "" : "\n\n") + "[压缩包内容]\n" + zipText
        }

        appendToCurrent(ChatMessage(role: .user, content: finalText, attachments: meta))
        let assistantIndex = messages.count
        appendToCurrent(ChatMessage(role: .assistant, content: "", attachments: []))
        let convo = Array(messages.prefix(assistantIndex))

        let needsFile = !meta.isEmpty
        let effectiveModel = (needsFile || webSearch) ? "deepseek-flash" : selectedModel
        let client = DeepSeekClient(apiBase: apiBase, apiKey: apiKey, model: effectiveModel, webSearch: webSearch)
        do {
            for try await ev in client.stream(messages: convo) {
                switch ev {
                case .text(let t):
                    setContent(assistantIndex, t)
                case .status(let s):
                    statusText = s.isEmpty ? nil : s
                }
            }
        } catch {
            let msg = (error as? ChatRequestError)?.message ?? error.localizedDescription
            if assistantIndex < messages.count {
                if messages[assistantIndex].content.isEmpty {
                    setContent(assistantIndex, "⚠️ " + msg)
                } else {
                    errorText = msg
                }
            }
        }
        statusText = nil
        isSending = false
        persist()
    }
}

// MARK: - 附件预览
struct AttachmentChip: View {
    let att: MessageAttachment
    var body: some View {
        if att.isImage, let b64 = att.thumbBase64, let d = Data(base64Encoded: b64), let ui = UIImage(data: d) {
            Image(uiImage: ui)
                .resizable()
                .scaledToFit()
                .frame(maxWidth: 180)
                .clipShape(RoundedRectangle(cornerRadius: 10))
        } else {
            Label(att.filename, systemImage: "doc.fill")
                .font(.caption)
                .padding(8)
                .background(Color(UIColor.tertiarySystemBackground))
                .clipShape(RoundedRectangle(cornerRadius: 10))
        }
    }
}

// MARK: - 单条消息
struct MessageRow: View {
    let message: ChatMessage
    var body: some View {
        let isUser = message.role == .user
        HStack(alignment: .top, spacing: 8) {
            if isUser { Spacer(minLength: 50) }
            VStack(alignment: isUser ? .trailing : .leading, spacing: 6) {
                ForEach(message.attachments) { att in
                    AttachmentChip(att: att)
                }
                if !message.content.isEmpty {
                    Text(message.content)
                        .padding(.horizontal, 12)
                        .padding(.vertical, 9)
                        .background(isUser ? Color.accentColor.opacity(0.22) : Color(UIColor.secondarySystemBackground))
                        .foregroundColor(.primary)
                        .clipShape(RoundedRectangle(cornerRadius: 16))
                        .textSelection(.enabled)
                } else if message.attachments.isEmpty {
                    HStack(spacing: 6) {
                        ProgressView()
                        Text("思考中…").font(.footnote).foregroundColor(.secondary)
                    }
                    .padding(10)
                    .background(Color(UIColor.secondarySystemBackground))
                    .clipShape(RoundedRectangle(cornerRadius: 16))
                }
            }
            if !isUser { Spacer(minLength: 50) }
        }
    }
}

// MARK: - 主界面
struct ContentView: View {
    @StateObject private var store = ChatStore()
    @State private var input = ""
    @State private var showSettings = false
    @State private var showConvList = false
    @State private var picked: [PickedFile] = []
    @State private var photoItems: [PhotosPickerItem] = []
    @State private var showPhotos = false
    @State private var showFiles = false
    @FocusState private var inputFocused: Bool

    var body: some View {
        NavigationView {
            VStack(spacing: 0) {
                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 14) {
                            ForEach(store.messages) { m in
                                MessageRow(message: m).id(m.id)
                            }
                            if let s = store.statusText {
                                Text(s).font(.footnote).foregroundColor(.secondary)
                            }
                        }
                        .padding(.horizontal, 12)
                        .padding(.vertical, 14)
                    }
                    .scrollDismissesKeyboard(.interactively)
                    .onTapGesture { inputFocused = false }
                    .onChange(of: store.messages.count) { _ in
                        if let last = store.messages.last {
                            withAnimation { proxy.scrollTo(last.id, anchor: .bottom) }
                        }
                    }
                }

                if let err = store.errorText {
                    Text(err)
                        .font(.footnote)
                        .foregroundColor(.red)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, 12)
                        .padding(.vertical, 4)
                        .background(Color.red.opacity(0.08))
                }

                Divider()

                if !picked.isEmpty {
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 8) {
                            ForEach(picked) { pf in
                                HStack(spacing: 6) {
                                    if pf.isImage, let ui = UIImage(data: pf.data) {
                                        Image(uiImage: ui).resizable().scaledToFill()
                                            .frame(width: 40, height: 40).clipShape(RoundedRectangle(cornerRadius: 6))
                                    } else {
                                        Image(systemName: pf.isZip ? "doc.zipper" : "doc.fill")
                                    }
                                    Text(pf.filename).font(.caption).lineLimit(1)
                                    Button {
                                        picked.removeAll { $0.id == pf.id }
                                    } label: {
                                        Image(systemName: "xmark.circle.fill").foregroundColor(.secondary)
                                    }
                                }
                                .padding(6)
                                .background(Color(UIColor.secondarySystemBackground))
                                .clipShape(RoundedRectangle(cornerRadius: 8))
                            }
                        }
                        .padding(.horizontal, 12)
                        .padding(.top, 8)
                    }
                }

                HStack(alignment: .bottom, spacing: 8) {
                    Menu {
                        Button { showPhotos = true } label: { Label("照片（可多选）", systemImage: "photo") }
                        Button { showFiles = true } label: { Label("文件（可多选，含 ZIP）", systemImage: "folder") }
                    } label: {
                        Image(systemName: "paperclip").font(.system(size: 20)).padding(.bottom, 8)
                    }

                    Button { store.toggleWebSearch() } label: {
                        Image(systemName: "globe")
                            .font(.system(size: 20))
                            .foregroundColor(store.webSearch ? .accentColor : .secondary)
                            .padding(.bottom, 8)
                    }

                    TextField("输入消息…", text: $input, axis: .vertical)
                        .focused($inputFocused)
                        .lineLimit(1...5)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 9)
                        .background(Color(UIColor.secondarySystemBackground))
                        .clipShape(RoundedRectangle(cornerRadius: 18))

                    Button {
                        let t = input
                        let files = picked
                        input = ""
                        picked = []
                        inputFocused = false
                        Task { await store.send(t, files: files) }
                    } label: {
                        Image(systemName: "arrow.up.circle.fill")
                            .font(.system(size: 30))
                            .foregroundColor(canSend ? .accentColor : .gray)
                    }
                    .disabled(!canSend)
                }
                .padding(.horizontal, 10)
                .padding(.vertical, 8)
                .background(Color(UIColor.systemBackground))
            }
            .navigationTitle(store.currentTitle)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button { showConvList = true } label: { Image(systemName: "list.bullet") }
                }
                ToolbarItemGroup(placement: .navigationBarTrailing) {
                    ShareLink(item: store.exportText()) {
                        Image(systemName: "square.and.arrow.up")
                    }
                    Button { showSettings = true } label: { Image(systemName: "gearshape") }
                }
                ToolbarItemGroup(placement: .keyboard) {
                    Spacer()
                    Button("收起键盘") { inputFocused = false }
                }
            }
            .sheet(isPresented: $showSettings) { SettingsView(store: store) }
            .sheet(isPresented: $showConvList) { ConversationListView(store: store) }
            .photosPicker(isPresented: $showPhotos, selection: $photoItems, maxSelectionCount: 0, matching: .images)
            .onChange(of: photoItems) { items in
                guard !items.isEmpty else { return }
                Task {
                    var arr: [PickedFile] = []
                    for it in items {
                        if let data = try? await it.loadTransferable(type: Data.self),
                           let pf = FileClassifier.image(from: data) {
                            arr.append(pf)
                        }
                    }
                    await MainActor.run {
                        picked.append(contentsOf: arr)
                        photoItems = []
                    }
                }
            }
            .fileImporter(isPresented: $showFiles, allowedContentTypes: [.item], allowsMultipleSelection: true) { result in
                switch result {
                case .success(let urls):
                    var arr: [PickedFile] = []
                    for url in urls {
                        if let pf = FileClassifier.make(from: url) { arr.append(pf) }
                    }
                    picked.append(contentsOf: arr)
                case .failure(let e):
                    store.errorText = "选取文件失败：\(e.localizedDescription)"
                }
            }
            .task { await store.loadModels() }
        }
    }

    private var canSend: Bool {
        !store.isSending && (!input.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || !picked.isEmpty)
    }
}

// MARK: - 会话列表
struct ConversationListView: View {
    @ObservedObject var store: ChatStore
    @Environment(\.dismiss) var dismiss

    var body: some View {
        NavigationView {
            List {
                Section {
                    Button {
                        store.newConversation()
                        dismiss()
                    } label: {
                        Label("新建对话", systemImage: "plus.circle.fill")
                    }
                }
                Section(header: Text("历史对话")) {
                    ForEach(store.conversations) { conv in
                        Button {
                            store.select(conv.id)
                            dismiss()
                        } label: {
                            HStack {
                                VStack(alignment: .leading, spacing: 3) {
                                    Text(conv.title).font(.body).lineLimit(1)
                                    Text("\(conv.messages.count) 条消息")
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                }
                                Spacer()
                                if conv.id == store.currentID {
                                    Image(systemName: "checkmark").foregroundColor(.accentColor)
                                }
                            }
                        }
                        .foregroundColor(.primary)
                    }
                    .onDelete { idx in
                        let ids = idx.map { store.conversations[$0].id }
                        for id in ids { store.delete(id) }
                    }
                }
            }
            .navigationTitle("对话")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("完成") { dismiss() }
                }
            }
        }
    }
}

// MARK: - 设置页
struct SettingsView: View {
    @ObservedObject var store: ChatStore
    @Environment(\.dismiss) var dismiss
    @State private var key = ""
    @State private var base = ""
    @State private var model = ""
    @State private var webSearch = false
    @State private var loading = false

    var body: some View {
        NavigationView {
            Form {
                Section(header: Text("API Key（只存本机钥匙串）")) {
                    SecureField("sk-...", text: $key)
                }
                Section(header: Text("API 地址")) {
                    TextField("https://api.deepseek.com", text: $base)
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                }
                Section(header: Text("模型（来自官方 /models 实时拉取）")) {
                    if store.models.isEmpty {
                        Text("暂无，请点下方刷新").foregroundColor(.secondary)
                    }
                    Picker("模型", selection: $model) {
                        ForEach(store.models) { m in
                            Text(m.display).tag(m.id)
                        }
                    }
                    Button(loading ? "刷新中…" : "刷新模型列表") {
                        Task {
                            loading = true
                            store.saveSettings(apiKey: key,
                                               apiBase: base.isEmpty ? "https://api.deepseek.com" : base,
                                               model: model.isEmpty ? store.selectedModel : model,
                                               webSearch: webSearch)
                            await store.loadModels()
                            if !store.models.contains(where: { $0.id == model }) {
                                model = store.selectedModel
                            }
                            loading = false
                        }
                    }
                    .disabled(key.isEmpty || loading)
                }
                Section(header: Text("联网搜索")) {
                    Toggle("开启联网搜索", isOn: $webSearch)
                    Text("开启后使用 deepseek-flash 模型联网检索并给出引用。")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                Section(header: Text("文件 / 压缩包说明")) {
                    Text("可一次选多个文件或照片。发送文件/图片/ZIP 时会自动改用 deepseek-flash 模型。ZIP 会在本机解压、抽取其中文本文件内容再交给模型（图片/二进制文件会被忽略）。")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                Section {
                    Button("清空当前对话", role: .destructive) { store.clearCurrent() }
                }
            }
            .navigationTitle("设置")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("保存") {
                        store.saveSettings(apiKey: key,
                                           apiBase: base.isEmpty ? "https://api.deepseek.com" : base,
                                           model: model.isEmpty ? store.selectedModel : model,
                                           webSearch: webSearch)
                        dismiss()
                    }
                }
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("取消") { dismiss() }
                }
            }
            .onAppear {
                key = store.apiKey
                base = store.apiBase
                model = store.selectedModel
                webSearch = store.webSearch
                Task {
                    await store.loadModels()
                    if !store.models.contains(where: { $0.id == model }) {
                        model = store.selectedModel
                    }
                }
            }
        }
    }
}

// MARK: - 入口
@main
struct DeepSeekChatApp: App {
    var body: some Scene {
        WindowGroup { ContentView() }
    }
}
