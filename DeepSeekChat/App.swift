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
    var purpose: String
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
    var providerID: UUID?
    var apiID: UUID?
    var model: String?
}

// 一个 API 配置（昵称 + key）。key 不写入 json，只存钥匙串。
struct APIConfig: Identifiable, Codable, Equatable {
    var id = UUID()
    var nickname: String = ""
    var key: String = ""
    enum CodingKeys: String, CodingKey { case id, nickname }
}

// 一个 AI 提供商（可含多个 API）
struct AIProvider: Identifiable, Codable, Equatable {
    var id = UUID()
    var name: String = ""
    var baseURL: String = ""
    var apis: [APIConfig] = []
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
    static func readData(_ url: URL) -> Data? {
        let access = url.startAccessingSecurityScopedResource()
        defer { if access { url.stopAccessingSecurityScopedResource() } }
        var result: Data? = nil
        var coordError: NSError? = nil
        let coordinator = NSFileCoordinator()
        coordinator.coordinate(readingItemAt: url, options: [], error: &coordError) { newURL in
            result = try? Data(contentsOf: newURL, options: .mappedIfSafe)
            if result == nil { result = try? Data(contentsOf: newURL) }
        }
        if result == nil { result = try? Data(contentsOf: url, options: .mappedIfSafe) }
        if result == nil { result = try? Data(contentsOf: url) }
        return result
    }

    static func make(from url: URL) -> PickedFile? {
        guard let data = readData(url) else { return nil }
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
    static func save(_ value: String, for account: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.colin.deepseekchat",
            kSecAttrAccount as String: account
        ]
        SecItemDelete(query as CFDictionary)
        guard !value.isEmpty else { return }
        var add = query
        add[kSecValueData as String] = Data(value.utf8)
        add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        SecItemAdd(add as CFDictionary, nil)
    }
    static func read(_ account: String) -> String {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.colin.deepseekchat",
            kSecAttrAccount as String: account,
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

// MARK: - ZIP 解析
enum ZipReader {
    static func extractText(from data: Data, maxTotal: Int = 150_000) -> String {
        let entries = extractFiles(from: data, onlyExtensions: nil, maxEach: 5_000_000, maxTotal: maxTotal)
        var result = ""
        for (name, d) in entries {
            guard shouldInclude(name), let text = decodeText(d) else { continue }
            let piece = "\n--- \(name) ---\n" + String(text.prefix(60_000)) + "\n"
            if result.count + piece.count <= maxTotal { result += piece }
            else { let remain = maxTotal - result.count; if remain > 0 { result += String(piece.prefix(remain)) }; break }
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

    static func extractFiles(from data: Data, onlyExtensions: Set<String>?, maxEach: Int = 30_000_000, maxTotal: Int = 80_000_000) -> [(String, Data)] {
        var out: [(String, Data)] = []
        guard data.count > 22 else { return out }
        var eocd = -1
        let minPos = max(0, data.count - 22 - 65535)
        var i = data.count - 22
        while i >= minPos {
            if u32(data, i) == 0x06054b50 { eocd = i; break }
            i -= 1
        }
        guard eocd >= 0 else { return out }
        let total = u16(data, eocd + 10)
        let cdOffset = u32(data, eocd + 16)
        guard cdOffset > 0, cdOffset < data.count else { return out }
        var pos = cdOffset
        var idx = 0
        var totalBytes = 0
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
            let ext = (name.lowercased() as NSString).pathExtension
            let wanted = (onlyExtensions == nil) || onlyExtensions!.contains(ext)
            if wanted, !name.hasSuffix("/"), localOff + 30 <= data.count {
                let lnameLen = u16(data, localOff + 26)
                let lextraLen = u16(data, localOff + 28)
                let dataStart = localOff + 30 + lnameLen + lextraLen
                if dataStart + compSize <= data.count, compSize > 0, compSize <= maxEach {
                    let comp = data.subdata(in: dataStart ..< dataStart + compSize)
                    var fd: Data? = nil
                    if method == 0 { fd = comp }
                    else if method == 8 { fd = inflate(comp, expected: min(uncompSize, maxEach)) }
                    if let fd = fd {
                        out.append((name, fd))
                        totalBytes += fd.count
                        if totalBytes > maxTotal { break }
                    }
                }
            }
            pos += 46 + nameLen + extraLen + commentLen
            idx += 1
        }
        return out
    }

    private static func inflate(_ input: Data, expected: Int) -> Data? {
        let inputCount = input.count
        let capacity = max(expected, inputCount * 4, 4096)
        var dst = Data(count: capacity)
        let n = dst.withUnsafeMutableBytes { (dptr: UnsafeMutableRawBufferPointer) -> Int in
            input.withUnsafeBytes { (sptr: UnsafeRawBufferPointer) -> Int in
                guard let dbase = dptr.bindMemory(to: UInt8.self).baseAddress,
                      let sbase = sptr.bindMemory(to: UInt8.self).baseAddress else { return 0 }
                return compression_decode_buffer(dbase, capacity, sbase, inputCount, nil, COMPRESSION_ZLIB)
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

// MARK: - 导入解析（兼容 Chatbox / 通用 JSON / ZIP）
enum ConversationImporter {
    private static func isZipData(_ d: Data) -> Bool {
        guard d.count >= 4 else { return false }
        let base = d.startIndex
        return d[base] == 0x50 && d[base + 1] == 0x4B && (d[base + 2] == 0x03 || d[base + 2] == 0x05)
    }

    static func parse(_ data: Data, filename: String = "") -> [Conversation] {
        let isZip = filename.lowercased().hasSuffix(".zip") || isZipData(data)
        if isZip {
            var all: [Conversation] = []
            let entries = ZipReader.extractFiles(from: data, onlyExtensions: ["json"])
            for (_, d) in entries {
                if let root = try? JSONSerialization.jsonObject(with: d) {
                    all.append(contentsOf: parseRoot(root))
                }
            }
            if all.isEmpty {
                let entries2 = ZipReader.extractFiles(from: data, onlyExtensions: nil)
                for (name, d) in entries2 where name.lowercased().hasSuffix(".json") {
                    if let root = try? JSONSerialization.jsonObject(with: d) {
                        all.append(contentsOf: parseRoot(root))
                    }
                }
            }
            return all
        } else {
            guard let root = try? JSONSerialization.jsonObject(with: data) else { return [] }
            return parseRoot(root)
        }
    }

    private static func parseRoot(_ root: Any) -> [Conversation] {
        if let dict = root as? [String: Any] {
            for key in ["sessions", "conversations", "chats", "history", "data", "items"] {
                if let arr = dict[key] as? [Any] {
                    let convs = parseSessionArray(arr)
                    if !convs.isEmpty { return convs }
                }
            }
            if let c = parseSession(dict) { return [c] }
            return []
        }
        if let arr = root as? [Any] {
            let convs = parseSessionArray(arr)
            if !convs.isEmpty { return convs }
            if let msgs = parseMessages(arr) {
                var c = Conversation()
                c.messages = msgs
                c.title = String((msgs.first?.content ?? "导入对话").prefix(20))
                return [c]
            }
        }
        return []
    }

    private static func parseSessionArray(_ arr: [Any]) -> [Conversation] {
        var out: [Conversation] = []
        for item in arr {
            if let dict = item as? [String: Any], let c = parseSession(dict) { out.append(c) }
        }
        return out
    }

    private static func parseSession(_ dict: [String: Any]) -> Conversation? {
        var msgArr: [Any]? = nil
        for key in ["messages", "msgs", "chat", "items"] {
            if let a = dict[key] as? [Any] { msgArr = a; break }
        }
        guard let arr = msgArr, let msgs = parseMessages(arr) else { return nil }
        var c = Conversation()
        var title = "导入对话"
        for key in ["name", "title", "topic", "summary"] {
            if let s = dict[key] as? String, !s.isEmpty { title = s; break }
        }
        c.title = String(title.prefix(30))
        c.messages = msgs
        return c
    }

    private static func parseMessages(_ arr: [Any]) -> [ChatMessage]? {
        var msgs: [ChatMessage] = []
        for item in arr {
            guard let dict = item as? [String: Any] else { continue }
            var roleStr = "user"
            for key in ["role", "from", "sender", "type", "author"] {
                if let s = dict[key] as? String { roleStr = s; break }
            }
            let low = roleStr.lowercased()
            let isAssistant = low.contains("assist") || low.contains("ai") || low.contains("bot") || low == "model" || low == "gpt" || low == "assistant"
            let role: ChatMessage.Role = isAssistant ? .assistant : .user
            var content = ""
            if let s = dict["content"] as? String { content = s }
            else if let s = dict["text"] as? String { content = s }
            else if let s = dict["message"] as? String { content = s }
            else if let parts = dict["content"] as? [Any] {
                for p in parts {
                    if let ps = p as? String { content += ps }
                    else if let pd = p as? [String: Any], let t = pd["text"] as? String { content += t }
                }
            }
            if low.contains("system") { continue }
            if content.isEmpty { continue }
            msgs.append(ChatMessage(role: role, content: content, attachments: []))
        }
        return msgs.isEmpty ? nil : msgs
    }
}

// MARK: - 网络客户端（OpenAI 兼容，可指向任意提供商）
final class ChatClient {
    let baseURL: String
    let apiKey: String
    let model: String
    let webSearch: Bool
    let isDeepSeek: Bool
    init(baseURL: String, apiKey: String, model: String, webSearch: Bool, isDeepSeek: Bool) {
        self.baseURL = baseURL
        self.apiKey = apiKey
        self.model = model
        self.webSearch = webSearch
        self.isDeepSeek = isDeepSeek
    }

    func cleanedBase() -> String {
        baseURL.trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
    }

    func fetchModels() async throws -> [ModelInfo] {
        guard let url = URL(string: cleanedBase() + "/models") else { return [] }
        var req = URLRequest(url: url)
        req.setValue("Bearer \(apiKey)", forHTTPHeaderField: "Authorization")
        let (data, _) = try await URLSession.shared.data(for: req)
        let decoded = try JSONDecoder().decode(ModelsResponse.self, from: data)
        return decoded.data
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
        msgs.map { m -> [String: Any] in
            let files = m.attachments.filter { $0.fileId != nil }
            if !files.isEmpty {
                var blocks: [[String: Any]] = []
                if !m.content.isEmpty { blocks.append(["type": "text", "text": m.content]) }
                for f in files { if let fid = f.fileId { blocks.append(["type": "file", "file_id": fid]) } }
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
                    if webSearch && isDeepSeek {
                        let tools: [[String: Any]] = [
                            ["type": "deepseek_web_search"],
                            ["type": "deepseek_read_url"]
                        ]
                        body["tools"] = tools
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

    @Published var providers: [AIProvider] = []
    @Published var providerModels: [UUID: [ModelInfo]] = [:]

    private var convURL: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0].appendingPathComponent("conversations.json")
    }
    private var provURL: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0].appendingPathComponent("providers.json")
    }

    init() {
        loadProviders()
        loadConversations()
    }

    var currentIndex: Int? { conversations.firstIndex { $0.id == currentID } }
    var messages: [ChatMessage] {
        if let i = currentIndex { return conversations[i].messages }
        return []
    }
    var currentTitle: String {
        if let i = currentIndex { return conversations[i].title }
        return "我的 AI"
    }

    func selection() -> (AIProvider?, APIConfig?, String?) {
        let conv = currentIndex.map { conversations[$0] }
        let provider = providers.first { $0.id == conv?.providerID } ?? providers.first
        guard let p = provider else { return (nil, nil, nil) }
        let api = p.apis.first { $0.id == conv?.apiID } ?? p.apis.first
        var model = conv?.model
        if model == nil || model!.isEmpty {
            model = providerModels[p.id]?.first?.id
            if model == nil, p.baseURL.lowercased().contains("deepseek") { model = "deepseek-chat" }
        }
        return (p, api, model)
    }

    var selectionSummary: String {
        let (p, a, m) = selection()
        let pn = p?.name ?? "未配置"
        let an = (a?.nickname.isEmpty == false ? a!.nickname : "默认")
        let mn = (m?.isEmpty == false ? m! : "选择模型")
        return "\(pn) · \(an) · \(mn)"
    }

    // MARK: 持久化 - 提供商
    func loadProviders() {
        if let data = try? Data(contentsOf: provURL),
           let decoded = try? JSONDecoder().decode([AIProvider].self, from: data),
           !decoded.isEmpty {
            providers = decoded
        } else {
            providers = [AIProvider(name: "DeepSeek", baseURL: "https://api.deepseek.com", apis: [])]
        }
        for i in providers.indices {
            for j in providers[i].apis.indices {
                providers[i].apis[j].key = Keychain.read("api_\(providers[i].apis[j].id.uuidString)")
            }
        }
        if providers[0].apis.isEmpty {
            let old = Keychain.read("apiKey")
            if !old.isEmpty {
                let cfg = APIConfig(nickname: "默认", key: old)
                providers[0].apis.append(cfg)
                Keychain.save(old, for: "api_\(cfg.id.uuidString)")
                persistProviders()
            }
        }
    }

    func persistProviders() {
        for p in providers {
            for a in p.apis {
                Keychain.save(a.key, for: "api_\(a.id.uuidString)")
            }
        }
        if let data = try? JSONEncoder().encode(providers) {
            try? data.write(to: provURL)
        }
    }

    func addProvider(name: String, baseURL: String) {
        providers.append(AIProvider(name: name, baseURL: baseURL, apis: []))
        persistProviders()
    }

    func updateProvider(_ id: UUID, name: String, baseURL: String, apis: [APIConfig]) {
        if let i = providers.firstIndex(where: { $0.id == id }) {
            providers[i].name = name
            providers[i].baseURL = baseURL
            providers[i].apis = apis
            persistProviders()
        }
    }

    func deleteProvider(_ id: UUID) {
        providers.removeAll { $0.id == id }
        if providers.isEmpty {
            providers = [AIProvider(name: "DeepSeek", baseURL: "https://api.deepseek.com", apis: [])]
        }
        persistProviders()
    }

    func models(for provider: AIProvider) -> [ModelInfo] {
        providerModels[provider.id] ?? []
    }

    func fetchModels(provider: AIProvider, apiKey: String) async {
        let client = ChatClient(baseURL: provider.baseURL, apiKey: apiKey, model: "", webSearch: false, isDeepSeek: false)
        do {
            let list = try await client.fetchModels()
            if !list.isEmpty { providerModels[provider.id] = list }
        } catch {}
    }

    // MARK: 持久化 - 会话
    func loadConversations() {
        if let data = try? Data(contentsOf: convURL),
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
            try? data.write(to: convURL)
        }
        UserDefaults.standard.set(currentID.uuidString, forKey: "currentID")
    }

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

    func setSelection(providerID: UUID?, apiID: UUID?, model: String?) {
        guard let i = currentIndex else { return }
        conversations[i].providerID = providerID
        conversations[i].apiID = apiID
        conversations[i].model = model
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

    // MARK: 导入 / 导出
    func exportJSON(_ convs: [Conversation]) -> String {
        var sessions: [[String: Any]] = []
        for c in convs {
            var msgs: [[String: Any]] = []
            for m in c.messages where !m.content.isEmpty {
                msgs.append(["role": m.role == .user ? "user" : "assistant", "content": m.content])
            }
            sessions.append(["name": c.title, "messages": msgs])
        }
        let root: [String: Any] = ["source": "deepseek-chat-ios", "sessions": sessions]
        guard let data = try? JSONSerialization.data(withJSONObject: root, options: [.prettyPrinted, .withoutEscapingSlashes]),
              let str = String(data: data, encoding: .utf8) else { return "{}" }
        return str
    }

    func writeTempExport(_ convs: [Conversation]) -> URL? {
        let json = exportJSON(convs)
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("对话导出.json")
        do {
            try json.data(using: .utf8)?.write(to: url)
            return url
        } catch { return nil }
    }

    @discardableResult
    func importConversations(from url: URL) -> Int {
        guard let data = FileClassifier.readData(url) else { return -1 }
        let convs = ConversationImporter.parse(data, filename: url.lastPathComponent)
        guard !convs.isEmpty else { return 0 }
        conversations.insert(contentsOf: convs, at: 0)
        if let f = convs.first { currentID = f.id }
        persist()
        return convs.count
    }

    // MARK: 发送
    func send(_ text: String, files: [PickedFile]) async {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty || !files.isEmpty else { return }
        guard !isSending else { return }
        let (providerOpt, apiOpt, modelOpt) = selection()
        guard let provider = providerOpt else { errorText = "请先在设置里添加 AI 提供商"; return }
        guard let api = apiOpt else { errorText = "请先在「\(provider.name)」下添加 API"; return }
        guard let model = modelOpt, !model.isEmpty else { errorText = "请先为当前对话选择一个模型"; return }
        guard !api.key.isEmpty else { errorText = "该 API 未填写 Key"; return }
        let isDeepSeek = provider.baseURL.lowercased().contains("deepseek")
        let nonZip = files.filter { !$0.isZip }
        if !nonZip.isEmpty && !isDeepSeek {
            errorText = "当前 AI（\(provider.name)）暂不支持上传文件，请改用 DeepSeek 或改发文字"
            return
        }
        errorText = nil
        statusText = nil
        isSending = true

        let client = ChatClient(baseURL: provider.baseURL, apiKey: api.key, model: model, webSearch: isDeepSeek, isDeepSeek: isDeepSeek)

        var meta: [MessageAttachment] = []
        var zipText = ""
        do {
            for f in files where f.isZip {
                statusText = "正在解析压缩包 \(f.filename)…"
                let t = ZipReader.extractText(from: f.data)
                zipText += t.isEmpty ? "\n--- \(f.filename)：未找到可读文本 ---\n" : t
            }
            for f in nonZip {
                statusText = "正在上传 \(f.filename)…"
                let fid = try await client.uploadFile(f)
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

        do {
            for try await ev in client.stream(messages: convo) {
                switch ev {
                case .text(let t): setContent(assistantIndex, t)
                case .status(let s): statusText = s.isEmpty ? nil : s
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

// MARK: - 系统分享面板
struct ActivityView: UIViewControllerRepresentable {
    let items: [Any]
    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }
    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}

// MARK: - 附件预览
struct AttachmentChip: View {
    let att: MessageAttachment
    var body: some View {
        if att.isImage, let b64 = att.thumbBase64, let d = Data(base64Encoded: b64), let ui = UIImage(data: d) {
            Image(uiImage: ui).resizable().scaledToFit().frame(maxWidth: 180)
                .clipShape(RoundedRectangle(cornerRadius: 10))
        } else {
            Label(att.filename, systemImage: "doc.fill").font(.caption).padding(8)
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
            if isUser { Spacer(minLength: 40) }
            VStack(alignment: isUser ? .trailing : .leading, spacing: 6) {
                ForEach(message.attachments) { att in AttachmentChip(att: att) }
                if !message.content.isEmpty {
                    Text(message.content)
                        .padding(.horizontal, 12).padding(.vertical, 9)
                        .background(isUser ? Color.accentColor.opacity(0.22) : Color(UIColor.secondarySystemBackground))
                        .foregroundColor(.primary)
                        .clipShape(RoundedRectangle(cornerRadius: 16))
                        .textSelection(.enabled)
                } else if message.attachments.isEmpty {
                    HStack(spacing: 6) { ProgressView(); Text("思考中…").font(.footnote).foregroundColor(.secondary) }
                        .padding(10).background(Color(UIColor.secondarySystemBackground))
                        .clipShape(RoundedRectangle(cornerRadius: 16))
                }
            }
            if !isUser { Spacer(minLength: 40) }
        }
    }
}

// MARK: - 主界面
struct ContentView: View {
    @StateObject private var store = ChatStore()
    @State private var input = ""
    @State private var showSettings = false
    @State private var showConvList = false
    @State private var showAI = false
    @State private var picked: [PickedFile] = []
    @State private var photoItems: [PhotosPickerItem] = []
    @State private var showPhotos = false
    @State private var showFiles = false
    @State private var exportItems: [Any] = []
    @State private var showExport = false
    @FocusState private var inputFocused: Bool

    var body: some View {
        NavigationView {
            VStack(spacing: 0) {
                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 14) {
                            ForEach(store.messages) { m in MessageRow(message: m).id(m.id) }
                            if let s = store.statusText { Text(s).font(.footnote).foregroundColor(.secondary) }
                        }
                        .padding(.horizontal, 12).padding(.vertical, 14)
                    }
                    .scrollDismissesKeyboard(.interactively)
                    .onTapGesture { inputFocused = false }
                    .onChange(of: store.messages.count) { _ in
                        if let last = store.messages.last { withAnimation { proxy.scrollTo(last.id, anchor: .bottom) } }
                    }
                }

                if let err = store.errorText {
                    Text(err).font(.footnote).foregroundColor(.red)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, 12).padding(.vertical, 4)
                        .background(Color.red.opacity(0.08))
                }

                Divider()

                Button { showAI = true } label: {
                    HStack(spacing: 6) {
                        Image(systemName: "cpu")
                        Text(store.selectionSummary).font(.footnote).lineLimit(1)
                        Image(systemName: "chevron.down").font(.caption2)
                        Spacer()
                    }
                    .padding(.horizontal, 12).padding(.vertical, 6)
                    .background(Color(UIColor.secondarySystemBackground))
                }
                .foregroundColor(.primary)

                HStack(spacing: 10) {
                    Button { showPhotos = true } label: { Label("照片", systemImage: "photo").font(.subheadline) }
                    Button { showFiles = true } label: { Label("文件", systemImage: "folder").font(.subheadline) }
                    Spacer()
                }
                .padding(.horizontal, 12).padding(.top, 8)

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
                                    Button { picked.removeAll { $0.id == pf.id } } label: {
                                        Image(systemName: "xmark.circle.fill").foregroundColor(.secondary)
                                    }
                                }
                                .padding(6).background(Color(UIColor.secondarySystemBackground))
                                .clipShape(RoundedRectangle(cornerRadius: 8))
                            }
                        }
                        .padding(.horizontal, 12).padding(.top, 6)
                    }
                }

                HStack(alignment: .bottom, spacing: 8) {
                    TextField("输入消息…", text: $input, axis: .vertical)
                        .focused($inputFocused).lineLimit(1...5)
                        .padding(.horizontal, 10).padding(.vertical, 9)
                        .background(Color(UIColor.secondarySystemBackground))
                        .clipShape(RoundedRectangle(cornerRadius: 18))

                    Button {
                        let t = input; let files = picked
                        input = ""; picked = []; inputFocused = false
                        Task { await store.send(t, files: files) }
                    } label: {
                        Image(systemName: "arrow.up.circle.fill").font(.system(size: 30))
                            .foregroundColor(canSend ? .accentColor : .gray)
                    }
                    .disabled(!canSend)
                }
                .padding(.horizontal, 10).padding(.vertical, 8)
                .background(Color(UIColor.systemBackground))
            }
            .navigationTitle(store.currentTitle)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button { showConvList = true } label: { Image(systemName: "list.bullet") }
                }
                ToolbarItemGroup(placement: .navigationBarTrailing) {
                    Button {
                        let current = store.currentIndex.map { [store.conversations[$0]] } ?? store.conversations
                        if let url = store.writeTempExport(current) { exportItems = [url]; showExport = true }
                    } label: { Image(systemName: "square.and.arrow.up") }
                    Button { showSettings = true } label: { Image(systemName: "gearshape") }
                }
                ToolbarItemGroup(placement: .keyboard) {
                    Spacer()
                    Button("收起键盘") { inputFocused = false }
                }
            }
            .sheet(isPresented: $showSettings) { SettingsView(store: store) }
            .sheet(isPresented: $showConvList) { ConversationListView(store: store) }
            .sheet(isPresented: $showAI) { AISelectorView(store: store) }
            .sheet(isPresented: $showExport) { ActivityView(items: exportItems) }
            .photosPicker(isPresented: $showPhotos, selection: $photoItems, maxSelectionCount: 0, matching: .images)
            .onChange(of: photoItems) { items in
                guard !items.isEmpty else { return }
                Task {
                    var arr: [PickedFile] = []
                    for it in items {
                        if let data = try? await it.loadTransferable(type: Data.self), let pf = FileClassifier.image(from: data) {
                            arr.append(pf)
                        }
                    }
                    await MainActor.run { picked.append(contentsOf: arr); photoItems = [] }
                }
            }
            .fileImporter(isPresented: $showFiles, allowedContentTypes: [.data], allowsMultipleSelection: true) { result in
                switch result {
                case .success(let urls):
                    var arr: [PickedFile] = []
                    var failed: [String] = []
                    for url in urls {
                        if let pf = FileClassifier.make(from: url) { arr.append(pf) } else { failed.append(url.lastPathComponent) }
                    }
                    if !arr.isEmpty { picked.append(contentsOf: arr) }
                    if !failed.isEmpty { store.errorText = "无法读取文件：" + failed.joined(separator: "、") }
                case .failure(let e):
                    store.errorText = "选取文件失败：\(e.localizedDescription)"
                }
            }
        }
    }

    private var canSend: Bool {
        !store.isSending && (!input.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || !picked.isEmpty)
    }
}

// MARK: - AI 选择器（每个对话）
struct AISelectorView: View {
    @ObservedObject var store: ChatStore
    @Environment(\.dismiss) var dismiss
    @State private var providerID: UUID?
    @State private var apiID: UUID?
    @State private var model: String = ""
    @State private var loading = false

    private var provider: AIProvider? { store.providers.first { $0.id == providerID } }
    private var apiKey: String { provider?.apis.first { $0.id == apiID }?.key ?? "" }

    var body: some View {
        NavigationView {
            Form {
                Section(header: Text("AI 提供商")) {
                    if store.providers.isEmpty {
                        Text("请到设置里添加 AI").foregroundColor(.secondary)
                    }
                    Picker("提供商", selection: $providerID) {
                        ForEach(store.providers) { p in Text(p.name).tag(Optional(p.id)) }
                    }
                    .onChange(of: providerID) { _ in
                        apiID = provider?.apis.first?.id
                        model = ""
                        loadModels()
                    }
                }
                Section(header: Text("API（昵称）")) {
                    if let p = provider, !p.apis.isEmpty {
                        Picker("API", selection: $apiID) {
                            ForEach(p.apis) { a in
                                Text(a.nickname.isEmpty ? "未命名" : a.nickname).tag(Optional(a.id))
                            }
                        }
                        .onChange(of: apiID) { _ in loadModels() }
                    } else {
                        Text("该 AI 还没有 API，请到设置里添加").foregroundColor(.secondary)
                    }
                }
                Section(header: Text("模型")) {
                    TextField("模型名称", text: $model)
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                    Button(loading ? "刷新中…" : "刷新模型列表") { loadModels() }
                        .disabled(loading || provider == nil)
                    let list = provider.map { store.models(for: $0) } ?? []
                    if !list.isEmpty {
                        ForEach(list) { m in
                            Button { model = m.id } label: {
                                HStack { Text(m.display); Spacer()
                                    if model == m.id { Image(systemName: "checkmark").foregroundColor(.accentColor) }
                                }
                            }
                        }
                    }
                }
            }
            .navigationTitle("选择 AI")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("确定") {
                        store.setSelection(providerID: providerID, apiID: apiID, model: model.isEmpty ? nil : model)
                        dismiss()
                    }
                }
                ToolbarItem(placement: .navigationBarLeading) { Button("取消") { dismiss() } }
            }
            .onAppear {
                let (p, a, m) = store.selection()
                providerID = p?.id ?? store.providers.first?.id
                apiID = a?.id ?? provider?.apis.first?.id
                model = m ?? ""
            }
        }
    }

    private func loadModels() {
        guard let p = provider else { return }
        let key = apiKey
        guard !key.isEmpty else { return }
        loading = true
        Task {
            await store.fetchModels(provider: p, apiKey: key)
            await MainActor.run {
                if model.isEmpty, let first = store.models(for: p).first?.id { model = first }
                loading = false
            }
        }
    }
}

// MARK: - 会话列表
struct ConversationListView: View {
    @ObservedObject var store: ChatStore
    @Environment(\.dismiss) var dismiss
    @State private var showImport = false
    @State private var exportItems: [Any] = []
    @State private var showExport = false

    var body: some View {
        NavigationView {
            List {
                Section {
                    Button { store.newConversation(); dismiss() } label: {
                        Label("新建对话", systemImage: "plus.circle.fill")
                    }
                }
                Section(header: Text("导入 / 导出")) {
                    Button { showImport = true } label: {
                        Label("导入对话（兼容 Chatbox 导出 ZIP/JSON）", systemImage: "square.and.arrow.down")
                    }
                    Button {
                        if let url = store.writeTempExport(store.conversations) { exportItems = [url]; showExport = true }
                    } label: { Label("导出全部对话（JSON）", systemImage: "square.and.arrow.up") }
                }
                Section(header: Text("历史对话")) {
                    ForEach(store.conversations) { conv in
                        HStack {
                            VStack(alignment: .leading, spacing: 3) {
                                Text(conv.title).font(.body).lineLimit(1)
                                Text("\(conv.messages.count) 条消息").font(.caption).foregroundColor(.secondary)
                            }
                            Spacer()
                            if conv.id == store.currentID { Image(systemName: "checkmark").foregroundColor(.accentColor) }
                        }
                        .contentShape(Rectangle())
                        .onTapGesture { store.select(conv.id); dismiss() }
                        .swipeActions(edge: .trailing, allowsFullSwipe: true) {
                            Button(role: .destructive) { store.delete(conv.id) } label: { Label("删除", systemImage: "trash") }
                        }
                        .contextMenu {
                            Button(role: .destructive) { store.delete(conv.id) } label: { Label("删除对话", systemImage: "trash") }
                        }
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
                ToolbarItem(placement: .navigationBarLeading) { EditButton() }
                ToolbarItem(placement: .navigationBarTrailing) { Button("完成") { dismiss() } }
            }
            .fileImporter(isPresented: $showImport, allowedContentTypes: [.zip, .json, .text, .data], allowsMultipleSelection: false) { result in
                switch result {
                case .success(let urls):
                    if let url = urls.first {
                        let n = store.importConversations(from: url)
                        if n > 0 { dismiss() }
                        else if n == 0 { store.errorText = "该文件没有可识别的对话" }
                        else { store.errorText = "无法读取该文件" }
                    }
                case .failure(let e):
                    store.errorText = "导入失败：\(e.localizedDescription)"
                }
            }
            .sheet(isPresented: $showExport) { ActivityView(items: exportItems) }
        }
    }
}

// MARK: - 设置页
struct SettingsView: View {
    @ObservedObject var store: ChatStore
    @Environment(\.dismiss) var dismiss

    var body: some View {
        NavigationView {
            Form {
                Section(header: Text("AI 提供商 / API")) {
                    NavigationLink {
                        ProvidersView(store: store)
                    } label: {
                        Label("管理 AI 与 API（可加多个、起昵称）", systemImage: "server.rack")
                    }
                    ForEach(store.providers) { p in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(p.name).font(.subheadline)
                            Text("\(p.apis.count) 个 API · \(p.baseURL)").font(.caption).foregroundColor(.secondary).lineLimit(1)
                        }
                    }
                }
                Section(header: Text("说明")) {
                    Text("每个对话可在聊天页顶部单独选择用哪个 AI / 哪个 API / 哪个模型。文件、ZIP、联网搜索为 DeepSeek 专属能力；其他 AI 仅支持文字与 ZIP 文本提取。")
                        .font(.caption).foregroundColor(.secondary)
                }
                Section {
                    Button("清空当前对话", role: .destructive) { store.clearCurrent() }
                }
            }
            .navigationTitle("设置")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) { Button("完成") { dismiss() } }
            }
        }
    }
}

// MARK: - 提供商管理
struct ProvidersView: View {
    @ObservedObject var store: ChatStore
    @State private var showAdd = false
    @State private var newName = ""
    @State private var newBase = ""

    var body: some View {
        List {
            Section {
                Button {
                    newName = ""; newBase = ""; showAdd = true
                } label: { Label("添加 AI 提供商", systemImage: "plus.circle.fill") }
            }
            Section(header: Text("AI 提供商")) {
                ForEach(store.providers) { p in
                    NavigationLink {
                        ProviderEditorView(store: store, providerID: p.id)
                    } label: {
                        VStack(alignment: .leading, spacing: 3) {
                            Text(p.name).font(.body)
                            Text("\(p.apis.count) 个 API · \(p.baseURL)").font(.caption).foregroundColor(.secondary).lineLimit(1)
                        }
                    }
                }
                .onDelete { idx in
                    let ids = idx.map { store.providers[$0].id }
                    for id in ids { store.deleteProvider(id) }
                }
            }
        }
        .navigationTitle("AI 提供商")
        .alert("添加 AI 提供商", isPresented: $showAdd) {
            TextField("名称，如 OpenAI / 硅基流动", text: $newName)
            TextField("接口地址，如 https://api.openai.com/v1", text: $newBase)
            Button("添加") { store.addProvider(name: newName.isEmpty ? "新 AI" : newName, baseURL: newBase) }
            Button("取消", role: .cancel) {}
        } message: {
            Text("填入名称和 OpenAI 兼容的接口地址（程序会在其后拼接 /chat/completions 与 /models）")
        }
    }
}

// MARK: - 单个提供商编辑（含多个 API）
struct ProviderEditorView: View {
    @ObservedObject var store: ChatStore
    let providerID: UUID
    @Environment(\.dismiss) var dismiss
    @State private var name = ""
    @State private var baseURL = ""
    @State private var apis: [APIConfig] = []

    var body: some View {
        Form {
            Section(header: Text("AI 名称")) {
                TextField("名称", text: $name)
            }
            Section(header: Text("接口地址（OpenAI 兼容）")) {
                TextField("https://api.example.com/v1", text: $baseURL)
                    .autocapitalization(.none).disableAutocorrection(true)
            }
            Section(header: Text("API（可添加多个，各起昵称）")) {
                ForEach(apis.indices, id: \.self) { i in
                    VStack(alignment: .leading, spacing: 6) {
                        TextField("昵称，如 主号 / 备用", text: Binding(
                            get: { apis[i].nickname },
                            set: { apis[i].nickname = $0 }
                        )).font(.subheadline)
                        SecureField("API Key", text: Binding(
                            get: { apis[i].key },
                            set: { apis[i].key = $0 }
                        ))
                        .autocapitalization(.none).disableAutocorrection(true)
                    }
                }
                .onDelete { idx in apis.remove(atOffsets: idx) }
                Button {
                    apis.append(APIConfig(nickname: "API \(apis.count + 1)", key: ""))
                } label: { Label("添加 API", systemImage: "plus.circle") }
            }
            Section {
                Button("保存") {
                    store.updateProvider(providerID, name: name.isEmpty ? "未命名" : name, baseURL: baseURL, apis: apis)
                    dismiss()
                }
            }
        }
        .navigationTitle("编辑")
        .onAppear {
            if let p = store.providers.first(where: { $0.id == providerID }) {
                name = p.name
                baseURL = p.baseURL
                apis = p.apis
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