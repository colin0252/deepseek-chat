import SwiftUI
import Foundation
import Security
import PhotosUI
import UIKit
import UniformTypeIdentifiers
import Compression
import AVFoundation
import Speech

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
    var imageDataBase64: String? = nil
}

struct ChatMessage: Identifiable, Codable {
    enum Role: String, Codable { case user, assistant }
    var id = UUID()
    var role: Role
    var content: String
    var attachments: [MessageAttachment] = []
}

enum ChatMode: String, Codable { case chat, work }

struct Conversation: Identifiable, Codable {
    var id = UUID()
    var title: String = "新对话"
    var messages: [ChatMessage] = []
    var updatedAt: Date = Date()
    var providerID: UUID?
    var apiID: UUID?
    var model: String?
    var mode: ChatMode? = nil
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
        return try? Data(contentsOf: url)
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

    static func base64Image(from data: Data, maxSide: CGFloat = 1024) -> String? {
        guard let ui = UIImage(data: data) else { return nil }
        let ratio = min(1, maxSide / max(ui.size.width, ui.size.height))
        let size = CGSize(width: max(1, ui.size.width * ratio), height: max(1, ui.size.height * ratio))
        UIGraphicsBeginImageContextWithOptions(size, false, 1)
        ui.draw(in: CGRect(origin: .zero, size: size))
        let img = UIGraphicsGetImageFromCurrentImageContext()
        UIGraphicsEndImageContext()
        return img?.jpegData(compressionQuality: 0.8)?.base64EncodedString()
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

// MARK: - ZIP 生成（store 方式，导出用）
enum ZipWriter {
    private static let crcTable: [UInt32] = (0..<256).map { i -> UInt32 in
        var c = UInt32(i)
        for _ in 0..<8 { c = (c & 1) != 0 ? (0xEDB88320 ^ (c >> 1)) : (c >> 1) }
        return c
    }
    private static func crc32(_ data: Data) -> UInt32 {
        var c: UInt32 = 0xFFFFFFFF
        for b in data { c = crcTable[Int((c ^ UInt32(b)) & 0xFF)] ^ (c >> 8) }
        return c ^ 0xFFFFFFFF
    }
    private static func u16le(_ v: Int) -> [UInt8] { [UInt8(v & 0xFF), UInt8((v >> 8) & 0xFF)] }
    private static func u32le(_ v: UInt32) -> [UInt8] { [UInt8(v & 0xFF), UInt8((v >> 8) & 0xFF), UInt8((v >> 16) & 0xFF), UInt8((v >> 24) & 0xFF)] }

    static func create(files: [(String, Data)]) -> Data {
        var out = Data()
        var central = Data()
        for (name, data) in files {
            let nameData = Data(name.utf8)
            let crc = crc32(data)
            let offset = UInt32(out.count)
            out.append(contentsOf: u32le(0x04034b50))
            out.append(contentsOf: u16le(20))
            out.append(contentsOf: u16le(0))
            out.append(contentsOf: u16le(0))
            out.append(contentsOf: u16le(0))
            out.append(contentsOf: u16le(0))
            out.append(contentsOf: u32le(crc))
            out.append(contentsOf: u32le(UInt32(data.count)))
            out.append(contentsOf: u32le(UInt32(data.count)))
            out.append(contentsOf: u16le(nameData.count))
            out.append(contentsOf: u16le(0))
            out.append(nameData)
            out.append(data)

            central.append(contentsOf: u32le(0x02014b50))
            central.append(contentsOf: u16le(20))
            central.append(contentsOf: u16le(20))
            central.append(contentsOf: u16le(0))
            central.append(contentsOf: u16le(0))
            central.append(contentsOf: u16le(0))
            central.append(contentsOf: u16le(0))
            central.append(contentsOf: u32le(crc))
            central.append(contentsOf: u32le(UInt32(data.count)))
            central.append(contentsOf: u32le(UInt32(data.count)))
            central.append(contentsOf: u16le(nameData.count))
            central.append(contentsOf: u16le(0))
            central.append(contentsOf: u16le(0))
            central.append(contentsOf: u16le(0))
            central.append(contentsOf: u16le(0))
            central.append(contentsOf: u32le(0))
            central.append(contentsOf: u32le(offset))
            central.append(nameData)
        }
        let cdOffset = UInt32(out.count)
        out.append(central)
        let cdSize = UInt32(central.count)
        out.append(contentsOf: u32le(0x06054b50))
        out.append(contentsOf: u16le(0))
        out.append(contentsOf: u16le(0))
        out.append(contentsOf: u16le(files.count))
        out.append(contentsOf: u16le(files.count))
        out.append(contentsOf: u32le(cdSize))
        out.append(contentsOf: u32le(cdOffset))
        out.append(contentsOf: u16le(0))
        return out
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
        let lower = filename.lowercased()
        let isZip = lower.hasSuffix(".zip") || isZipData(data)
        if isZip {
            var all: [Conversation] = []
            let entries = ZipReader.extractFiles(from: data, onlyExtensions: ["json"])
            for (_, d) in entries {
                if let root = try? JSONSerialization.jsonObject(with: d) { all.append(contentsOf: parseRoot(root)) }
            }
            if all.isEmpty {
                let entries2 = ZipReader.extractFiles(from: data, onlyExtensions: nil)
                for (name, d) in entries2 where name.lowercased().hasSuffix(".json") {
                    if let root = try? JSONSerialization.jsonObject(with: d) { all.append(contentsOf: parseRoot(root)) }
                }
            }
            return all
        }
        if let root = try? JSONSerialization.jsonObject(with: data) { return parseRoot(root) }
        let text = String(data: data, encoding: .utf8) ?? ""
        if lower.hasSuffix(".html") || lower.hasSuffix(".htm") || text.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("<") {
            let c = parseHTML(text); if !c.isEmpty { return c }
        }
        if lower.hasSuffix(".md") || lower.hasSuffix(".markdown") {
            let c = parseMarkdown(text); if !c.isEmpty { return c }
        }
        return parseText(text)
    }

    private static func parseText(_ text: String) -> [Conversation] {
        var convs: [Conversation] = []
        var messages: [ChatMessage] = []
        var title = "导入对话"
        func flush() {
            if !messages.isEmpty { var c = Conversation(); c.title = title; c.messages = messages; convs.append(c) }
            messages = []; title = "导入对话"
        }
        for raw in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = String(raw)
            let t = line.trimmingCharacters(in: .whitespaces)
            if t.isEmpty { continue }
            if t.hasPrefix("【") && t.hasSuffix("】") { flush(); title = String(t.dropFirst().dropLast()); continue }
            if line.hasPrefix("我：") {
                messages.append(ChatMessage(role: .user, content: String(line.dropFirst(2)), attachments: []))
            } else if line.hasPrefix("AI：") {
                messages.append(ChatMessage(role: .assistant, content: String(line.dropFirst(3)), attachments: []))
            } else if var last = messages.last {
                last.content += "\n" + line
                messages[messages.count - 1] = last
            } else {
                messages.append(ChatMessage(role: .user, content: line, attachments: []))
            }
        }
        flush()
        return convs
    }

    private static func parseMarkdown(_ text: String) -> [Conversation] {
        var convs: [Conversation] = []
        var messages: [ChatMessage] = []
        var title = "导入对话"
        var pendingUser = false
        func flushConv() {
            if !messages.isEmpty { var c = Conversation(); c.title = title; c.messages = messages; convs.append(c) }
            messages = []; title = "导入对话"
        }
        for blockRaw in text.components(separatedBy: "\n\n") {
            let block = blockRaw.trimmingCharacters(in: .whitespacesAndNewlines)
            if block.isEmpty { continue }
            if block.hasPrefix("# ") { flushConv(); title = String(block.dropFirst(2)); pendingUser = false; continue }
            if block == "---" { flushConv(); pendingUser = false; continue }
            if block == "**我：**" || block == "**我:**" { pendingUser = true; continue }
            let role: ChatMessage.Role = pendingUser ? .user : .assistant
            messages.append(ChatMessage(role: role, content: block, attachments: []))
            pendingUser = false
        }
        flushConv()
        return convs
    }

    private static func unescapeHTML(_ s: String) -> String {
        s.replacingOccurrences(of: "<br>", with: "\n")
         .replacingOccurrences(of: "<br/>", with: "\n")
         .replacingOccurrences(of: "&lt;", with: "<")
         .replacingOccurrences(of: "&gt;", with: ">")
         .replacingOccurrences(of: "&amp;", with: "&")
    }

    private static func parseHTML(_ html: String) -> [Conversation] {
        var convs: [Conversation] = []
        var messages: [ChatMessage] = []
        var title = "导入对话"
        func flushConv() {
            if !messages.isEmpty { var c = Conversation(); c.title = title; c.messages = messages; convs.append(c) }
            messages = []; title = "导入对话"
        }
        let pattern = "<h2>(.*?)</h2>|<p><b>(我|AI)：</b>(.*?)</p>"
        guard let re = try? NSRegularExpression(pattern: pattern, options: [.dotMatchesLineSeparators, .caseInsensitive]) else { return [] }
        let ns = html as NSString
        for m in re.matches(in: html, range: NSRange(location: 0, length: ns.length)) {
            if m.range(at: 1).location != NSNotFound {
                flushConv(); title = unescapeHTML(ns.substring(with: m.range(at: 1)))
            } else {
                let who = m.range(at: 2).location != NSNotFound ? ns.substring(with: m.range(at: 2)) : ""
                let content = m.range(at: 3).location != NSNotFound ? unescapeHTML(ns.substring(with: m.range(at: 3))) : ""
                messages.append(ChatMessage(role: who == "我" ? .user : .assistant, content: content, attachments: []))
            }
        }
        flushConv()
        return convs
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
    let temperature: Double
    let topP: Double
    let maxTokens: Int
    init(baseURL: String, apiKey: String, model: String, webSearch: Bool, isDeepSeek: Bool,
         temperature: Double = 0.7, topP: Double = 1.0, maxTokens: Int = 0) {
        self.baseURL = baseURL
        self.apiKey = apiKey
        self.model = model
        self.webSearch = webSearch
        self.isDeepSeek = isDeepSeek
        self.temperature = temperature
        self.topP = topP
        self.maxTokens = maxTokens
    }

    func cleanedBase() -> String {
        baseURL.trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
    }

    // 拉取模型列表
    func fetchModels() async throws -> [ModelInfo] {
        guard let url = URL(string: cleanedBase() + "/models") else { return [] }
        var req = URLRequest(url: url)
        req.setValue("Bearer \(apiKey)", forHTTPHeaderField: "Authorization")
        let (data, _) = try await URLSession.shared.data(for: req)
        let decoded = try JSONDecoder().decode(ModelsResponse.self, from: data)
        return decoded.data
    }

    // DeepSeek 文件上传
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
            var parts: [[String: Any]] = []
            for a in m.attachments {
                if let fid = a.fileId {
                    parts.append(["type": "file", "file_id": fid])
                } else if let b64 = a.imageDataBase64 {
                    parts.append(["type": "image_url", "image_url": ["url": "data:image/jpeg;base64,\(b64)"]])
                }
            }
            if parts.isEmpty {
                return ["role": m.role.rawValue, "content": m.content]
            }
            var content: [[String: Any]] = []
            if !m.content.isEmpty { content.append(["type": "text", "text": m.content]) }
            content.append(contentsOf: parts)
            return ["role": m.role.rawValue, "content": content]
        }
    }

    // DeepSeek 余额查询（GET /user/balance）
    func fetchBalance() async -> String {
        guard let url = URL(string: cleanedBase() + "/user/balance") else { return "地址无效" }
        var req = URLRequest(url: url)
        req.setValue("Bearer \(apiKey)", forHTTPHeaderField: "Authorization")
        do {
            let (data, resp) = try await URLSession.shared.data(for: req)
            let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
            if code != 200 { return "获取失败：HTTP \(code)" }
            if let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                if let infos = obj["balance_infos"] as? [[String: Any]], let f = infos.first {
                    let cur = f["currency"] as? String ?? ""
                    let total = f["total_balance"] as? String ?? ""
                    return "余额：\(total) \(cur)"
                }
                if let avail = obj["is_available"] as? Bool { return avail ? "可用" : "不可用" }
            }
            return "余额：未知"
        } catch {
            return "获取失败：\(error.localizedDescription)"
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
                    if temperature >= 0 { body["temperature"] = temperature }
                    if topP > 0 { body["top_p"] = topP }
                    if maxTokens > 0 { body["max_tokens"] = maxTokens }
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

// MARK: - GitHub 登录（OAuth 设备码，App 内拉起）
final class GitHubAuth {
    let clientID: String
    init(clientID: String) { self.clientID = clientID }

    struct DeviceCode {
        let deviceCode: String
        let userCode: String
        let verificationURI: String
        let interval: Int
    }
    enum AuthError: Error { case message(String) }

    private func post(_ urlStr: String, form: [String: String]) async throws -> [String: Any] {
        guard let url = URL(string: urlStr) else { throw AuthError.message("地址无效") }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        req.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        req.setValue("deepseek-chat-ios", forHTTPHeaderField: "User-Agent")
        var comps: [String] = []
        for (k, v) in form {
            let ek = k.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? k
            let ev = v.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? v
            comps.append("\(ek)=\(ev)")
        }
        req.httpBody = comps.joined(separator: "&").data(using: .utf8)
        let (data, _) = try await URLSession.shared.data(for: req)
        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw AuthError.message("返回异常\n" + (String(data: data, encoding: .utf8) ?? ""))
        }
        return obj
    }

    func requestDeviceCode(scope: String = "repo") async throws -> DeviceCode {
        let obj = try await post("https://github.com/login/device/code", form: ["client_id": clientID, "scope": scope])
        if let err = obj["error"] as? String {
            throw AuthError.message(err + " " + (obj["error_description"] as? String ?? ""))
        }
        guard let dc = obj["device_code"] as? String,
              let uc = obj["user_code"] as? String,
              let vu = obj["verification_uri"] as? String,
              let interval = obj["interval"] as? Int else {
            throw AuthError.message("解析失败")
        }
        return DeviceCode(deviceCode: dc, userCode: uc, verificationURI: vu, interval: interval)
    }

    func pollToken(deviceCode: String, interval: Int) async throws -> String {
        var wait = max(interval, 5)
        let start = Date()
        while Date().timeIntervalSince(start) < 900 {
            try? await Task.sleep(nanoseconds: UInt64(wait) * 1_000_000_000)
            let obj = try await post("https://github.com/login/oauth/access_token", form: [
                "client_id": clientID,
                "device_code": deviceCode,
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code"
            ])
            if let token = obj["access_token"] as? String { return token }
            if let err = obj["error"] as? String {
                if err == "authorization_pending" { continue }
                else if err == "slow_down" { wait += 5; continue }
                else if err == "expired_token" { throw AuthError.message("验证码已过期，请重新登录") }
                else if err == "access_denied" { throw AuthError.message("你取消了授权") }
                else { throw AuthError.message(err) }
            }
        }
        throw AuthError.message("超时")
    }
}

// MARK: - GitHub 客户端（REST API，读/改/提交）
final class GitHubClient {
    let token: String
    let owner: String
    let repo: String
    let branch: String
    init(token: String, owner: String, repo: String, branch: String) {
        self.token = token
        self.owner = owner
        self.repo = repo
        self.branch = branch.isEmpty ? "main" : branch
    }

    private func makeRequest(_ urlStr: String, method: String = "GET", body: Data? = nil) -> URLRequest {
        var req = URLRequest(url: URL(string: urlStr)!)
        req.httpMethod = method
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        req.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        req.setValue("2022-11-28", forHTTPHeaderField: "X-GitHub-Api-Version")
        req.setValue("deepseek-chat-ios", forHTTPHeaderField: "User-Agent")
        if let body = body {
            req.httpBody = body
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        return req
    }

    private func encodePath(_ path: String) -> String {
        path.split(separator: "/").map { String($0).addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? String($0) }.joined(separator: "/")
    }

    private func check(_ resp: URLResponse, _ data: Data, ok: [Int]) throws {
        guard let http = resp as? HTTPURLResponse else { throw ChatRequestError(message: "无响应") }
        if !ok.contains(http.statusCode) {
            throw ChatRequestError(message: "HTTP \(http.statusCode)\n\(String(data: data, encoding: .utf8) ?? "")")
        }
    }

    func listFiles() async throws -> [String] {
        let url = "https://api.github.com/repos/\(owner)/\(repo)/git/trees/\(branch)?recursive=1"
        let (data, resp) = try await URLSession.shared.data(for: makeRequest(url))
        try check(resp, data, ok: [200])
        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let tree = obj["tree"] as? [[String: Any]] else {
            throw ChatRequestError(message: "解析失败")
        }
        return tree.filter { ($0["type"] as? String) == "blob" }
            .compactMap { $0["path"] as? String }
            .sorted()
    }

    func getFile(path: String) async throws -> (content: String, sha: String) {
        let url = "https://api.github.com/repos/\(owner)/\(repo)/contents/\(encodePath(path))?ref=\(branch)"
        let (data, resp) = try await URLSession.shared.data(for: makeRequest(url))
        try check(resp, data, ok: [200])
        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let sha = obj["sha"] as? String else {
            throw ChatRequestError(message: "解析失败")
        }
        var content = ""
        if let c = obj["content"] as? String {
            let cleaned = c.replacingOccurrences(of: "\n", with: "").replacingOccurrences(of: "\r", with: "")
            if let d = Data(base64Encoded: cleaned) {
                content = String(data: d, encoding: .utf8) ?? ""
            }
        }
        return (content, sha)
    }

    func putFile(path: String, content: String, sha: String?, message: String) async throws {
        var body: [String: Any] = [
            "message": message,
            "content": Data(content.utf8).base64EncodedString(),
            "branch": branch
        ]
        if let sha = sha, !sha.isEmpty { body["sha"] = sha }
        let bodyData = try JSONSerialization.data(withJSONObject: body)
        let url = "https://api.github.com/repos/\(owner)/\(repo)/contents/\(encodePath(path))"
        let (data, resp) = try await URLSession.shared.data(for: makeRequest(url, method: "PUT", body: bodyData))
        try check(resp, data, ok: [200, 201])
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

    @Published var ghOwner: String = ""
    @Published var ghRepo: String = ""
    @Published var ghBranch: String = "main"
    @Published var ghClientID: String = ""
    @Published var ghLoggedIn: Bool = false
    var ghToken: String = ""

    // 全局生成参数 / 外观
    @Published var temperature: Double = 0.7
    @Published var topP: Double = 1.0
    @Published var maxTokens: Int = 0
    @Published var contextLimit: Int = 20
    @Published var fontSize: Double = 16
    @Published var appearance: Int = 0
    @Published var workStepLimit: Int = 25

    // 工作模式状态
    @Published var workPaused: Bool = false
    @Published var workStepsRun: Int = 0

    private var convURL: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0].appendingPathComponent("conversations.json")
    }
    private var provURL: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0].appendingPathComponent("providers.json")
    }

    init() {
        loadProviders()
        loadGitHub()
        loadGenSettings()
        loadConversations()
    }

    func loadGenSettings() {
        let d = UserDefaults.standard
        temperature = d.object(forKey: "temperature") as? Double ?? 0.7
        topP = d.object(forKey: "topP") as? Double ?? 1.0
        maxTokens = d.object(forKey: "maxTokens") as? Int ?? 0
        contextLimit = d.object(forKey: "contextLimit") as? Int ?? 20
        fontSize = d.object(forKey: "fontSize") as? Double ?? 16
        appearance = d.object(forKey: "appearance") as? Int ?? 0
        workStepLimit = d.object(forKey: "workStepLimit") as? Int ?? 25
    }

    func saveGenSettings() {
        let d = UserDefaults.standard
        d.set(temperature, forKey: "temperature")
        d.set(topP, forKey: "topP")
        d.set(maxTokens, forKey: "maxTokens")
        d.set(contextLimit, forKey: "contextLimit")
        d.set(fontSize, forKey: "fontSize")
        d.set(appearance, forKey: "appearance")
        d.set(workStepLimit, forKey: "workStepLimit")
    }

    func applyContextLimit(_ msgs: [ChatMessage]) -> [ChatMessage] {
        var arr = msgs
        if contextLimit > 0 && arr.count > contextLimit { arr = Array(arr.suffix(contextLimit)) }
        // 按总字符数再限一层，避免历史里旧长消息撑爆 token
        let maxTotal = 40000
        var total = 0
        var kept: [ChatMessage] = []
        for m in arr.reversed() {
            total += m.content.count
            if total > maxTotal && !kept.isEmpty { break }
            kept.append(m)
        }
        return kept.reversed()
    }

    // 导处后的会话清洗：单条消息过长时截断，防止界面卡顿/发送超限
    private func sanitize(_ convs: [Conversation]) -> [Conversation] {
        let perMsgMax = 20000
        return convs.map { c in
            var conv = c
            conv.messages = c.messages.map { m in
                var msg = m
                if msg.content.count > perMsgMax {
                    msg.content = String(msg.content.prefix(perMsgMax)) + "\n…（导入时已截断）"
                }
                return msg
            }
            return conv
        }
    }

    var currentMode: ChatMode {
        if let i = currentIndex { return conversations[i].mode ?? .chat }
        return .chat
    }

    var colorScheme: ColorScheme? {
        if appearance == 1 { return .light }
        if appearance == 2 { return .dark }
        return nil
    }

    // MARK: 备份 / 恢复
    func backupArchive() -> URL? {
        var filesOut: [(String, Data)] = []
        if let d = try? JSONEncoder().encode(conversations) { filesOut.append(("conversations.json", d)) }
        if let d = try? JSONEncoder().encode(providers) { filesOut.append(("providers.json", d)) }
        let zip = ZipWriter.create(files: filesOut)
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("备份.zip")
        do { try zip.write(to: url); return url } catch { return nil }
    }

    func restoreArchive(_ url: URL) async -> Bool {
        let filesData = await Task.detached { () -> [(String, Data)] in
            guard let data = FileClassifier.readData(url) else { return [] }
            return ZipReader.extractFiles(from: data, onlyExtensions: nil)
        }.value
        guard !filesData.isEmpty else { return false }
        var ok = false
        for (n, d) in filesData {
            let low = n.lowercased()
            if low.hasSuffix("conversations.json"), let convs = try? JSONDecoder().decode([Conversation].self, from: d), !convs.isEmpty {
                conversations = convs; ok = true
            }
            if low.hasSuffix("providers.json"), let provs = try? JSONDecoder().decode([AIProvider].self, from: d), !provs.isEmpty {
                providers = provs
                for i in providers.indices { for j in providers[i].apis.indices { providers[i].apis[j].key = Keychain.read("api_\(providers[i].apis[j].id.uuidString)") } }
                persistProviders()
            }
        }
        if ok {
            if !conversations.contains(where: { $0.id == currentID }), let f = conversations.first { currentID = f.id }
            persist()
        }
        return ok
    }

    func setMode(_ m: ChatMode) {
        guard let i = currentIndex else { return }
        conversations[i].mode = m
        workPaused = false
        persist()
    }

    func rename(_ id: UUID, title: String) {
        guard let i = conversations.firstIndex(where: { $0.id == id }) else { return }
        let t = title.trimmingCharacters(in: .whitespacesAndNewlines)
        conversations[i].title = t.isEmpty ? conversations[i].title : t
        persist()
    }

    func truncateFrom(_ messageID: UUID) -> String {
        guard let i = currentIndex else { return "" }
        var conv = conversations[i]
        guard let idx = conv.messages.firstIndex(where: { $0.id == messageID }) else { return "" }
        let content = conv.messages[idx].content
        conv.messages = Array(conv.messages.prefix(idx))
        conversations[i] = conv
        persist()
        return content
    }

    func regenerate() async {
        guard !isSending, let i = currentIndex else { return }
        var conv = conversations[i]
        guard let lastUserIdx = conv.messages.lastIndex(where: { $0.role == .user }) else { return }
        let userText = conv.messages[lastUserIdx].content
        conv.messages = Array(conv.messages.prefix(lastUserIdx))
        conversations[i] = conv
        persist()
        await send(userText, files: [])
    }

    func continueWork() async {
        guard !isSending, let i = currentIndex else { return }
        isSending = true
        workPaused = false
        let assistantIndex = conversations[i].messages.count - 1
        await runWorkMode(assistantIndex: assistantIndex)
        statusText = nil
        isSending = false
        persist()
    }

    // 会话当前
    var currentIndex: Int? { conversations.firstIndex { $0.id == currentID } }
    var messages: [ChatMessage] {
        if let i = currentIndex { return conversations[i].messages }
        return []
    }
    var currentTitle: String {
        if let i = currentIndex { return conversations[i].title }
        return "我的 AI"
    }

    // 解析当前对话使用的 提供商 / API / 模型
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
        // 填充 key
        for i in providers.indices {
            for j in providers[i].apis.indices {
                providers[i].apis[j].key = Keychain.read("api_\(providers[i].apis[j].id.uuidString)")
            }
        }
        // 迁移旧的单 key
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
        } catch {
            // 静默失败
        }
    }

    // MARK: GitHub
    func loadGitHub() {
        ghOwner = UserDefaults.standard.string(forKey: "ghOwner") ?? ""
        ghRepo = UserDefaults.standard.string(forKey: "ghRepo") ?? ""
        ghBranch = UserDefaults.standard.string(forKey: "ghBranch") ?? "main"
        ghClientID = UserDefaults.standard.string(forKey: "ghClientID") ?? ""
        ghToken = Keychain.read("github_token")
        ghLoggedIn = !ghToken.isEmpty
    }

    func saveGitHubConfig(owner: String, repo: String, branch: String, clientID: String) {
        ghOwner = owner
        ghRepo = repo
        ghBranch = branch.isEmpty ? "main" : branch
        ghClientID = clientID
        UserDefaults.standard.set(ghOwner, forKey: "ghOwner")
        UserDefaults.standard.set(ghRepo, forKey: "ghRepo")
        UserDefaults.standard.set(ghBranch, forKey: "ghBranch")
        UserDefaults.standard.set(ghClientID, forKey: "ghClientID")
    }

    func setGitHubToken(_ token: String) {
        ghToken = token
        ghLoggedIn = !token.isEmpty
        Keychain.save(token, for: "github_token")
    }

    func clearGitHubToken() {
        ghToken = ""
        ghLoggedIn = false
        Keychain.save("", for: "github_token")
    }

    var isGitHubConfigured: Bool { !ghToken.isEmpty && !ghOwner.isEmpty && !ghRepo.isEmpty }

    func ghClient() -> GitHubClient {
        GitHubClient(token: ghToken, owner: ghOwner, repo: ghRepo, branch: ghBranch)
    }

    func modifyFileWithAI(fileName: String, current: String, instruction: String) async -> (String?, String?) {
        let (providerOpt, apiOpt, modelOpt) = selection()
        guard let provider = providerOpt, let api = apiOpt, let model = modelOpt, !model.isEmpty else {
            return (nil, "请先在聊天页顶部选择 AI / API / 模型")
        }
        guard !api.key.isEmpty else { return (nil, "当前 API 未填写 Key") }
        let isDeepSeek = provider.baseURL.lowercased().contains("deepseek")
        let client = ChatClient(baseURL: provider.baseURL, apiKey: api.key, model: model, webSearch: false, isDeepSeek: isDeepSeek)
        let prompt = """
        你是一个代码修改助手。请根据下面的“修改要求”改写文件，直接输出修改后的【完整文件内容】，
        不要输出任何解释、不要用 markdown 代码块包裹。只输出文件本身。

        文件名：\(fileName)

        ===== 原文件内容开始 =====
        \(current)
        ===== 原文件内容结束 =====

        修改要求：\(instruction)
        """
        let msgs = [ChatMessage(role: .user, content: prompt, attachments: [])]
        var result = ""
        do {
            for try await ev in client.stream(messages: msgs) {
                if case .text(let t) = ev { result = t }
            }
            var cleaned = result.trimmingCharacters(in: .whitespacesAndNewlines)
            if cleaned.hasPrefix("```") {
                if let firstNL = cleaned.firstIndex(of: "\n") {
                    cleaned = String(cleaned[cleaned.index(after: firstNL)...])
                }
                if let range = cleaned.range(of: "```", options: .backwards) {
                    cleaned = String(cleaned[..<range.lowerBound])
                }
                cleaned = cleaned.trimmingCharacters(in: .whitespacesAndNewlines)
            }
            return (cleaned, nil)
        } catch {
            let msg = (error as? ChatRequestError)?.message ?? error.localizedDescription
            return (nil, msg)
        }
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
        return writeTemp(convs, ext: "zip")
    }

    func exportPlain(_ convs: [Conversation]) -> String {
        var s = ""
        for c in convs {
            s += "【\(c.title)】\n"
            for m in c.messages where !m.content.isEmpty {
                s += (m.role == .user ? "我：" : "AI：") + m.content + "\n"
            }
            s += "\n"
        }
        return s
    }

    func exportMarkdown(_ convs: [Conversation]) -> String {
        var s = ""
        for c in convs {
            s += "# \(c.title)\n\n"
            for m in c.messages where !m.content.isEmpty {
                if m.role == .user { s += "**我：**\n\n" + m.content + "\n\n" }
                else { s += m.content + "\n\n" }
            }
            s += "---\n\n"
        }
        return s
    }

    func exportHTML(_ convs: [Conversation]) -> String {
        func esc(_ t: String) -> String {
            t.replacingOccurrences(of: "&", with: "&amp;")
             .replacingOccurrences(of: "<", with: "&lt;")
             .replacingOccurrences(of: ">", with: "&gt;")
             .replacingOccurrences(of: "\n", with: "<br>")
        }
        var body = ""
        for c in convs {
            body += "<h2>\(esc(c.title))</h2>"
            for m in c.messages where !m.content.isEmpty {
                let who = m.role == .user ? "我" : "AI"
                body += "<p><b>\(who)：</b>\(esc(m.content))</p>"
            }
            body += "<hr>"
        }
        return "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>对话导出</title></head><body>" + body + "</body></html>"
    }

    func writeTemp(_ convs: [Conversation], ext: String) -> URL? {
        let dir = FileManager.default.temporaryDirectory
        let data: Data
        let name: String
        switch ext {
        case "zip":
            let json = exportJSON(convs)
            data = ZipWriter.create(files: [("conversations.json", Data(json.utf8))])
            name = "对话导出.zip"
        case "txt":
            data = Data(exportPlain(convs).utf8); name = "对话导出.txt"
        case "md":
            data = Data(exportMarkdown(convs).utf8); name = "对话导出.md"
        case "html":
            data = Data(exportHTML(convs).utf8); name = "对话导出.html"
        default:
            return nil
        }
        let url = dir.appendingPathComponent(name)
        do { try data.write(to: url); return url } catch { return nil }
    }

    @discardableResult
    func importConversations(from url: URL) -> Int {
        guard let data = FileClassifier.readData(url) else { return -1 }
        let convs = sanitize(ConversationImporter.parse(data, filename: url.lastPathComponent))
        guard !convs.isEmpty else { return 0 }
        conversations.insert(contentsOf: convs, at: 0)
        persist()
        return convs.count
    }

    // 后台读取+解析，避免主线程卡死
    func importFromURL(_ url: URL) async -> Int {
        let name = url.lastPathComponent
        let result = await Task.detached { () -> (read: Bool, convs: [Conversation]) in
            guard let data = FileClassifier.readData(url) else { return (false, []) }
            return (true, ConversationImporter.parse(data, filename: name))
        }.value
        guard result.read else { return -1 }
        let convs = sanitize(result.convs)
        guard !convs.isEmpty else { return 0 }
        conversations.insert(contentsOf: convs, at: 0)
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
        errorText = nil
        statusText = nil
        isSending = true

        let client = ChatClient(baseURL: provider.baseURL, apiKey: api.key, model: model, webSearch: isDeepSeek, isDeepSeek: isDeepSeek, temperature: temperature, topP: topP, maxTokens: maxTokens)

        var meta: [MessageAttachment] = []
        var zipText = ""
        var extraText = ""
        do {
            for f in files where f.isZip {
                statusText = "正在解析压缩包 \(f.filename)…"
                let t = ZipReader.extractText(from: f.data)
                zipText += t.isEmpty ? "\n--- \(f.filename)：未找到可读文本 ---\n" : t
            }
            for f in nonZip {
                if isDeepSeek {
                    statusText = "正在上传 \(f.filename)…"
                    let fid = try await client.uploadFile(f)
                    let thumb = f.isImage ? FileClassifier.thumbnail(from: f.data) : nil
                    meta.append(MessageAttachment(filename: f.filename, isImage: f.isImage, fileId: fid, thumbBase64: thumb))
                } else if f.isImage {
                    let b64 = FileClassifier.base64Image(from: f.data)
                    let thumb = FileClassifier.thumbnail(from: f.data)
                    meta.append(MessageAttachment(filename: f.filename, isImage: true, fileId: nil, thumbBase64: thumb, imageDataBase64: b64))
                } else if let s = String(data: f.data, encoding: .utf8) {
                    extraText += "\n\n--- \(f.filename) ---\n" + String(s.prefix(20000))
                } else {
                    extraText += "\n\n（已跳过二进制文件：\(f.filename)）"
                }
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
        if !extraText.isEmpty { finalText += extraText }
        // 限制总输入长度，避免超过模型 token 上限（约 32768 tokens）
        let maxChars = 24000
        if finalText.count > maxChars {
            finalText = String(finalText.prefix(maxChars)) + "\n\n…（内容过长已截断，仅发送前 \(maxChars) 字；如需完整处理请分段发送）"
        }
        if currentMode == .work && !finalText.isEmpty {
            finalText = "[工作模式] 请把任务拆成步骤逐步推进，每一步给出明确进展；全部完成时，最后单独一行输出：[完成]\n\n" + finalText
        }

        appendToCurrent(ChatMessage(role: .user, content: finalText, attachments: meta))
        let assistantIndex = messages.count
        appendToCurrent(ChatMessage(role: .assistant, content: "", attachments: []))
        let convo = applyContextLimit(Array(messages.prefix(assistantIndex)))

        if currentMode == .work {
            workStepsRun = 0
            await runWorkMode(assistantIndex: assistantIndex)
            statusText = nil
            isSending = false
            persist()
            return
        }

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

    // 工作模式：自动分步推进，每轮最多 workStepLimit 步（默认 25）后暂停，等用户确认再继续
    func runWorkMode(assistantIndex: Int) async {
        let (providerOpt, apiOpt, modelOpt) = selection()
        guard let provider = providerOpt, let api = apiOpt, let model = modelOpt, !model.isEmpty else { return }
        let isDeepSeek = provider.baseURL.lowercased().contains("deepseek")
        let client = ChatClient(baseURL: provider.baseURL, apiKey: api.key, model: model, webSearch: isDeepSeek, isDeepSeek: isDeepSeek, temperature: temperature, topP: topP, maxTokens: maxTokens)
        let base = workStepsRun
        var steps = 0
        while steps < workStepLimit {
            if !isSending { return }
            guard let i = currentIndex, assistantIndex < conversations[i].messages.count else { return }
            let existing = conversations[i].messages[assistantIndex].content
            var stepMessages = Array(conversations[i].messages.prefix(assistantIndex))
            if !existing.isEmpty {
                stepMessages.append(ChatMessage(role: .assistant, content: existing, attachments: []))
                stepMessages.append(ChatMessage(role: .user, content: "继续推进下一步（第 \(base + steps + 1) 步）。若任务已完成，请只回复：[完成]", attachments: []))
            }
            let stepNo = base + steps + 1
            var cur = ""
            do {
                for try await ev in client.stream(messages: applyContextLimit(stepMessages)) {
                    switch ev {
                    case .text(let t):
                        cur = t
                        let sep = existing.isEmpty ? "" : "\n\n"
                        setContent(assistantIndex, existing + sep + "【第 \(stepNo) 步】\n" + cur)
                    case .status(let s): statusText = s.isEmpty ? nil : s
                    }
                }
            } catch {
                let msg = (error as? ChatRequestError)?.message ?? error.localizedDescription
                setContent(assistantIndex, existing + "\n\n⚠️ " + msg)
                return
            }
            let sep = existing.isEmpty ? "" : "\n\n"
            setContent(assistantIndex, existing + sep + "【第 \(stepNo) 步】\n" + cur)
            steps += 1
            workStepsRun += 1
            if cur.contains("[完成]") || cur.contains("【完成】") { workPaused = false; return }
        }
        if steps >= workStepLimit { workPaused = true }
    }
}

// MARK: - 语音（TTS 朗读 + STT 语音输入）
final class SpeechManager {
    static let shared = SpeechManager()
    private let synth = AVSpeechSynthesizer()
    func speak(_ text: String) {
        if synth.isSpeaking { synth.stopSpeaking(at: .immediate) }
        let u = AVSpeechUtterance(string: text)
        u.voice = AVSpeechSynthesisVoice(language: "zh-CN")
        synth.speak(u)
    }
    func stop() { synth.stopSpeaking(at: .immediate) }
}

final class SpeechRecognizer: ObservableObject {
    @Published var isRecording = false
    @Published var transcript = ""
    private let recognizer = SFSpeechRecognizer(locale: Locale(identifier: "zh-CN"))
    private var request: SFSpeechAudioBufferRecognitionRequest?
    private var task: SFSpeechRecognitionTask?
    private let engine = AVAudioEngine()

    func toggle() { isRecording ? finish() : start() }

    func start() {
        SFSpeechRecognizer.requestAuthorization { _ in }
        transcript = ""
        do {
            let session = AVAudioSession.sharedInstance()
            try session.setCategory(.record, mode: .measurement, options: .duckOthers)
            try session.setActive(true, options: .notifyOthersOnDeactivation)
            let req = SFSpeechAudioBufferRecognitionRequest()
            req.shouldReportPartialResults = true
            request = req
            let input = engine.inputNode
            let format = input.outputFormat(forBus: 0)
            input.installTap(onBus: 0, bufferSize: 1024, format: format) { buf, _ in req.append(buf) }
            engine.prepare()
            try engine.start()
            isRecording = true
            task = recognizer?.recognitionTask(with: req) { [weak self] result, error in
                if let r = result {
                    let s = r.bestTranscription.formattedString
                    DispatchQueue.main.async { self?.transcript = s }
                }
                if error != nil || (result?.isFinal ?? false) {
                    DispatchQueue.main.async { self?.finish() }
                }
            }
        } catch {
            isRecording = false
        }
    }

    func finish() {
        engine.stop()
        engine.inputNode.removeTap(onBus: 0)
        request?.endAudio()
        task?.cancel()
        request = nil; task = nil
        isRecording = false
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

// MARK: - 原生文件选择（asCopy：先复制到本机，比 fileImporter 稳）
struct DocumentPicker: UIViewControllerRepresentable {
    var allowsMultiple: Bool = true
    var contentTypes: [UTType] = [.data]
    var onPick: ([URL]) -> Void

    func makeUIViewController(context: Context) -> UIDocumentPickerViewController {
        let vc = UIDocumentPickerViewController(forOpeningContentTypes: contentTypes, asCopy: true)
        vc.allowsMultipleSelection = allowsMultiple
        vc.delegate = context.coordinator
        return vc
    }
    func updateUIViewController(_ uiViewController: UIDocumentPickerViewController, context: Context) {}
    func makeCoordinator() -> Coordinator { Coordinator(onPick: onPick) }

    final class Coordinator: NSObject, UIDocumentPickerDelegate {
        let onPick: ([URL]) -> Void
        init(onPick: @escaping ([URL]) -> Void) { self.onPick = onPick }
        func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) { onPick(urls) }
        func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) { onPick([]) }
    }
}

// 主界面弹窗枚举（单一 sheet，避免多个弹窗互相干扰）
enum ActiveSheet: Identifiable {
    case settings, convList, ai, export, files
    var id: Int { switch self { case .settings: return 0; case .convList: return 1; case .ai: return 2; case .export: return 3; case .files: return 4 } }
}

enum ConvSheet: Identifiable {
    case importFile, export
    var id: Int { switch self { case .importFile: return 0; case .export: return 1 } }
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

// MARK: - Markdown 渲染（无三方依赖）
enum MDBlock {
    case paragraph(String)
    case heading(Int, String)
    case code(lang: String, body: String)
    case bullet(String)
    case numbered(Int, String)
}

func parseMarkdownBlocks(_ text: String) -> [MDBlock] {
    var blocks: [MDBlock] = []
    let lines = text.components(separatedBy: "\n")
    var i = 0
    var para: [String] = []
    func flush() {
        let s = para.joined(separator: "\n").trimmingCharacters(in: .whitespacesAndNewlines)
        if !s.isEmpty { blocks.append(.paragraph(s)) }
        para = []
    }
    while i < lines.count {
        let line = lines[i]
        let t = line.trimmingCharacters(in: .whitespaces)
        if t.hasPrefix("```") {
            flush()
            let lang = String(t.dropFirst(3)).trimmingCharacters(in: .whitespaces)
            var body: [String] = []
            i += 1
            while i < lines.count && !lines[i].trimmingCharacters(in: .whitespaces).hasPrefix("```") {
                body.append(lines[i]); i += 1
            }
            if i < lines.count { i += 1 }
            blocks.append(.code(lang: lang, body: body.joined(separator: "\n")))
            continue
        }
        if t.hasPrefix("#") {
            var level = 0; var h = t
            while h.hasPrefix("#") { level += 1; h = String(h.dropFirst()) }
            flush()
            if h.hasPrefix(" ") { h = String(h.dropFirst()) }
            blocks.append(.heading(min(level, 6), h))
            i += 1; continue
        }
        if t.hasPrefix("- ") || t.hasPrefix("* ") || t.hasPrefix("• ") {
            flush(); blocks.append(.bullet(String(t.dropFirst(2)))); i += 1; continue
        }
        if let dot = t.firstIndex(of: ".") {
            let afterDot = t.index(after: dot)
            if let num = Int(String(t[t.startIndex..<dot])), afterDot < t.endIndex, t[afterDot] == " " {
                flush()
                let start = t.index(after: afterDot)
                blocks.append(.numbered(num, start < t.endIndex ? String(t[start...]) : ""))
                i += 1; continue
            }
        }
        if t.isEmpty { flush(); i += 1; continue }
        para.append(line)
        i += 1
    }
    flush()
    return blocks
}

func mdInline(_ s: String) -> Text {
    let opts = AttributedString.MarkdownParsingOptions(interpretedSyntax: .inlineOnlyPreservingWhitespace)
    if let a = try? AttributedString(markdown: s, options: opts) { return Text(a) }
    return Text(s)
}

// 用 AttributedString（连续存储）避免 Text 深层拼接导致栈溢出
func highlightedCode(_ code: String) -> AttributedString {
    let keywords: Set<String> = ["func","let","var","if","else","for","while","return","struct","class","enum","import","guard","switch","case","break","continue","true","false","nil","self","init","private","public","static","try","catch","throw","throws","async","await","in","where","default","do","extension","protocol","typealias","defer","some","any","const","def","elif","lambda","None","True","False","and","or","not","from","as","with","yield","function","new","this","typeof","void","int","float","double","bool","string","package","using","namespace","template","auto","null","undefined","print","println"]
    var out = AttributedString()
    func add(_ s: String, _ col: Color?) {
        var a = AttributedString(s)
        if let col = col { a.foregroundColor = col }
        out.append(a)
    }
    let chars = Array(code)
    let n = chars.count
    var i = 0
    while i < n {
        let ch = chars[i]
        if ch == "\"" || ch == "'" || ch == "`" {
            let quote = ch
            var j = i; var s = String(ch); j += 1
            while j < n {
                let c = chars[j]; s.append(c); j += 1
                if c == "\n" { break }
                if c == quote { break }
            }
            add(s, .green); i = j
        } else if ch == "/" && i + 1 < n && chars[i + 1] == "/" {
            var j = i; var s = ""
            while j < n && chars[j] != "\n" { s.append(chars[j]); j += 1 }
            add(s, .gray); i = j
        } else if ch.isNumber {
            var j = i; var s = ""
            while j < n && (chars[j].isNumber || chars[j] == ".") { s.append(chars[j]); j += 1 }
            add(s, .orange); i = j
        } else if ch.isLetter || ch == "_" {
            var j = i; var s = ""
            while j < n && (chars[j].isLetter || chars[j].isNumber || chars[j] == "_") { s.append(chars[j]); j += 1 }
            add(s, keywords.contains(s) ? .purple : nil); i = j
        } else {
            add(String(ch), nil); i += 1
        }
    }
    return out
}

struct CodeBlockView: View {
    let code: String
    let lang: String
    var fontSize: Double
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text(lang.isEmpty ? "code" : lang).font(.caption2).foregroundColor(.secondary)
                Spacer()
                Button { UIPasteboard.general.string = code } label: {
                    Label("复制", systemImage: "doc.on.doc").font(.caption2)
                }
                .buttonStyle(.borderless)
            }
            .padding(.horizontal, 10).padding(.vertical, 6)
            .background(Color.black.opacity(0.22))
            ScrollView(.horizontal, showsIndicators: false) {
                Group {
                    if code.count > 20000 {
                        Text(code)
                    } else {
                        Text(highlightedCode(code))
                    }
                }
                .font(.system(size: CGFloat(max(11, fontSize - 2)), design: .monospaced))
                .foregroundColor(.primary)
                .fixedSize(horizontal: true, vertical: false)
                .padding(10)
            }
        }
        .background(Color(UIColor.secondarySystemBackground))
        .clipShape(RoundedRectangle(cornerRadius: 10))
    }
}

struct MarkdownView: View {
    let text: String
    var fontSize: Double = 16
    var body: some View {
        if text.count > 60000 {
            Text(String(text.prefix(60000)) + "\n…（内容过长，已截断显示，可长按复制全部）")
                .font(.system(size: CGFloat(fontSize)))
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        } else {
            let blocks = parseMarkdownBlocks(text)
            VStack(alignment: .leading, spacing: 8) {
                ForEach(Array(blocks.enumerated()), id: \.offset) { item in
                    blockView(item.element)
                }
            }
        }
    }

    @ViewBuilder
    private func blockView(_ b: MDBlock) -> some View {
        switch b {
        case .paragraph(let s):
            mdInline(s)
                .font(.system(size: CGFloat(fontSize)))
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        case .heading(let lvl, let s):
            mdInline(s)
                .font(.system(size: CGFloat(fontSize) + CGFloat(8 - min(lvl, 3) * 2), weight: .bold))
                .fixedSize(horizontal: false, vertical: true)
        case .bullet(let s):
            HStack(alignment: .top, spacing: 6) {
                Text("•").font(.system(size: CGFloat(fontSize)))
                mdInline(s).font(.system(size: CGFloat(fontSize))).textSelection(.enabled)
            }
        case .numbered(let n, let s):
            HStack(alignment: .top, spacing: 6) {
                Text("\(n).").font(.system(size: CGFloat(fontSize)))
                mdInline(s).font(.system(size: CGFloat(fontSize))).textSelection(.enabled)
            }
        case .code(let lang, let body):
            CodeBlockView(code: body, lang: lang, fontSize: fontSize)
        }
    }
}

// MARK: - 单条消息
struct MessageRow: View {
    let message: ChatMessage
    var fontSize: Double = 16
    var body: some View {
        let isUser = message.role == .user
        HStack(alignment: .top, spacing: 8) {
            if isUser { Spacer(minLength: 40) }
            VStack(alignment: isUser ? .trailing : .leading, spacing: 6) {
                ForEach(message.attachments) { att in AttachmentChip(att: att) }
                if !message.content.isEmpty {
                    MarkdownView(text: message.content, fontSize: fontSize)
                        .padding(.horizontal, 12).padding(.vertical, 9)
                        .background(isUser ? Color.accentColor.opacity(0.22) : Color(UIColor.secondarySystemBackground))
                        .foregroundColor(.primary)
                        .clipShape(RoundedRectangle(cornerRadius: 16))
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
    @StateObject private var speech = SpeechRecognizer()
    @State private var input = ""
    @State private var activeSheet: ActiveSheet?
    @State private var picked: [PickedFile] = []
    @State private var photoItems: [PhotosPickerItem] = []
    @State private var showPhotos = false
    @State private var exportItems: [Any] = []
    @FocusState private var inputFocused: Bool
    private let presets = ["翻译成英文", "润色文字", "总结要点", "写代码", "解释代码", "列大纲"]

    var body: some View {
        NavigationView {
            VStack(spacing: 0) {
                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 14) {
                            ForEach(store.messages) { m in
                                MessageRow(message: m, fontSize: store.fontSize).id(m.id)
                                    .contextMenu {
                                        Button { UIPasteboard.general.string = m.content } label: { Label("复制", systemImage: "doc.on.doc") }
                                        if m.role == .assistant {
                                            Button { Task { await store.regenerate() } } label: { Label("重新生成", systemImage: "arrow.clockwise") }
                                            Button { SpeechManager.shared.speak(m.content) } label: { Label("朗读", systemImage: "speaker.wave.2") }
                                            Button { SpeechManager.shared.stop() } label: { Label("停止朗读", systemImage: "speaker.slash") }
                                        }
                                        if m.role == .user {
                                            Button {
                                                input = store.truncateFrom(m.id)
                                                inputFocused = true
                                            } label: { Label("编辑并重新发送", systemImage: "pencil") }
                                        }
                                    }
                            }
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

                // 聊天模式 / 工作模式
                Picker("模式", selection: Binding(get: { store.currentMode }, set: { store.setMode($0) })) {
                    Text("聊天模式").tag(ChatMode.chat)
                    Text("工作模式").tag(ChatMode.work)
                }
                .pickerStyle(.segmented)
                .padding(.horizontal, 12).padding(.top, 6)

                // 选择当前 AI（每个对话独立）
                Button { activeSheet = .ai } label: {
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

                // 提示词预设
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 8) {
                        ForEach(presets, id: \.self) { p in
                            Button { input = p + "：" ; inputFocused = true } label: {
                                Text(p).font(.caption).padding(.horizontal, 10).padding(.vertical, 5)
                                    .background(Color(UIColor.secondarySystemBackground))
                                    .clipShape(Capsule())
                            }
                            .buttonStyle(.plain)
                        }
                    }
                    .padding(.horizontal, 12)
                }
                .padding(.top, 6)

                // 附件区
                HStack(spacing: 10) {
                    Button { showPhotos = true } label: { Label("照片", systemImage: "photo").font(.subheadline) }
                    Button { activeSheet = .files } label: { Label("文件", systemImage: "folder").font(.subheadline) }
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

                if store.workPaused {
                    Button { Task { await store.continueWork() } } label: {
                        Label("已运行 \(store.workStepsRun) 步（每轮上限 \(store.workStepLimit)），点此继续", systemImage: "play.fill")
                            .font(.footnote).frame(maxWidth: .infinity)
                            .padding(.vertical, 8).background(Color.accentColor.opacity(0.15))
                    }
                    .foregroundColor(.accentColor)
                }

                HStack(alignment: .bottom, spacing: 8) {
                    TextField(speech.isRecording ? "正在听…" : "输入消息…", text: $input, axis: .vertical)
                        .focused($inputFocused).lineLimit(1...5)
                        .padding(.horizontal, 10).padding(.vertical, 9)
                        .background(Color(UIColor.secondarySystemBackground))
                        .clipShape(RoundedRectangle(cornerRadius: 18))

                    Button { speech.toggle() } label: {
                        Image(systemName: speech.isRecording ? "mic.fill" : "mic")
                            .font(.system(size: 22))
                            .foregroundColor(speech.isRecording ? .red : .secondary)
                    }

                    Button {
                        var t = input; var files = picked
                        // 长文本（含粘贴的）自动转成 txt 文件上传（仅 DeepSeek 支持文件时）
                        let isDS = (store.selection().0?.baseURL.lowercased().contains("deepseek") ?? false)
                        if isDS && t.count > 8000 {
                            let ts = Int(Date().timeIntervalSince1970)
                            let pf = PickedFile(data: Data(t.utf8), filename: "长文本-\(ts).txt", isImage: false, purpose: "user_data", mimeType: "text/plain", isZip: false)
                            files.append(pf)
                            t = "（内容较长，已作为 txt 文件上传，请阅读附件后回答）"
                        }
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
            .preferredColorScheme(store.colorScheme)
            .onChange(of: speech.transcript) { v in if !v.isEmpty { input = v } }
            .toolbar {
                ToolbarItemGroup(placement: .navigationBarLeading) {
                    Button { activeSheet = .convList } label: { Image(systemName: "list.bullet") }
                    Button { store.newConversation() } label: { Image(systemName: "square.and.pencil") }
                        .accessibilityLabel("新建对话")
                }
                ToolbarItemGroup(placement: .navigationBarTrailing) {
                    Menu {
                        Button("导出为 ZIP") { exportCurrent("zip") }
                        Button("导出为 TXT") { exportCurrent("txt") }
                        Button("导出为 Markdown") { exportCurrent("md") }
                        Button("导出为 HTML") { exportCurrent("html") }
                    } label: { Image(systemName: "square.and.arrow.up") }
                    Button { activeSheet = .settings } label: { Image(systemName: "gearshape") }
                }
                ToolbarItemGroup(placement: .keyboard) {
                    Spacer()
                    Button("收起键盘") { inputFocused = false }
                }
            }
            .sheet(item: $activeSheet) { sheet in
                switch sheet {
                case .settings: SettingsView(store: store)
                case .convList: ConversationListView(store: store)
                case .ai: AISelectorView(store: store)
                case .export: ActivityView(items: exportItems)
                case .files:
                    DocumentPicker(allowsMultiple: true, contentTypes: [.data]) { urls in
                        handlePickedFiles(urls)
                    }
                }
            }
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
        }
    }

    private var canSend: Bool {
        !store.isSending && (!input.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || !picked.isEmpty)
    }

    private func exportCurrent(_ ext: String) {
        let current = store.currentIndex.map { [store.conversations[$0]] } ?? store.conversations
        if let url = store.writeTemp(current, ext: ext) { exportItems = [url]; activeSheet = .export }
    }

    private func handlePickedFiles(_ urls: [URL]) {
        activeSheet = nil
        guard !urls.isEmpty else { return }
        store.statusText = "正在读取文件…"
        Task {
            let r = await Task.detached { () -> (arr: [PickedFile], failed: [String]) in
                var arr: [PickedFile] = []
                var failed: [String] = []
                for url in urls {
                    if let pf = FileClassifier.make(from: url) { arr.append(pf) } else { failed.append(url.lastPathComponent) }
                }
                return (arr, failed)
            }.value
            await MainActor.run {
                if !r.arr.isEmpty { picked.append(contentsOf: r.arr) }
                if !r.failed.isEmpty { store.errorText = "无法读取文件：" + r.failed.joined(separator: "、") }
                store.statusText = nil
            }
        }
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
    @State private var testing = false
    @State private var testResult: String?
    @State private var balanceResult: String?

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
                Section(header: Text("连接测试")) {
                    Button(testing ? "测试中…" : "测试连接") { testConn() }
                        .disabled(testing || provider == nil)
                    if let r = testResult { Text(r).font(.caption).foregroundColor(.secondary) }
                    Button("查询余额（DeepSeek）") { queryBalance() }
                        .disabled(provider == nil)
                    if let b = balanceResult { Text(b).font(.caption).foregroundColor(.secondary) }
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

    private func queryBalance() {
        guard let p = provider, let a = (p.apis.first(where: { $0.id == apiID }) ?? p.apis.first) else { balanceResult = "请先选择提供商和 API"; return }
        guard !a.key.isEmpty else { balanceResult = "该 API 未填 Key"; return }
        guard p.baseURL.lowercased().contains("deepseek") else { balanceResult = "仅 DeepSeek 支持余额查询"; return }
        balanceResult = "查询中…"
        Task {
            let client = ChatClient(baseURL: p.baseURL, apiKey: a.key, model: "", webSearch: false, isDeepSeek: true)
            let r = await client.fetchBalance()
            await MainActor.run { balanceResult = r }
        }
    }

    private func testConn() {
        guard let p = provider, let a = (p.apis.first(where: { $0.id == apiID }) ?? p.apis.first) else {
            testResult = "请先选择提供商和 API"; return
        }
        guard !a.key.isEmpty else { testResult = "该 API 未填 Key"; return }
        testing = true; testResult = "测试中…"
        Task {
            let client = ChatClient(baseURL: p.baseURL, apiKey: a.key, model: "", webSearch: false, isDeepSeek: false)
            do {
                let list = try await client.fetchModels()
                await MainActor.run { testResult = list.isEmpty ? "连接成功（未返回模型列表）" : "连接成功，可用模型 \(list.count) 个"; testing = false }
            } catch {
                let msg = (error as? ChatRequestError)?.message ?? error.localizedDescription
                await MainActor.run { testResult = "失败：" + msg; testing = false }
            }
        }
    }
}

// MARK: - 会话列表
struct ConversationListView: View {
    @ObservedObject var store: ChatStore
    @Environment(\.dismiss) var dismiss
    @State private var activeConvSheet: ConvSheet?
    @State private var exportItems: [Any] = []
    @State private var searchText = ""
    @State private var renamingID: UUID?
    @State private var renameText = ""
    @State private var importing = false
    @State private var importMsg = ""
    @State private var importDone: String?

    private var filtered: [Conversation] {
        if searchText.trimmingCharacters(in: .whitespaces).isEmpty { return store.conversations }
        return store.conversations.filter { $0.title.localizedCaseInsensitiveContains(searchText) }
    }

    var body: some View {
        NavigationView {
            List {
                Section {
                    Button { store.newConversation(); dismiss() } label: {
                        Label("新建对话", systemImage: "plus.circle.fill")
                    }
                }
                Section(header: Text("导入 / 导出")) {
                    Button { activeConvSheet = .importFile } label: {
                        Label("导入对话（ZIP / JSON / TXT / Markdown / HTML，兼容 Chatbox）", systemImage: "square.and.arrow.down")
                    }
                    Menu {
                        Button("导出全部为 ZIP") { exportAll("zip") }
                        Button("导出全部为 TXT") { exportAll("txt") }
                        Button("导出全部为 Markdown") { exportAll("md") }
                        Button("导出全部为 HTML") { exportAll("html") }
                    } label: { Label("导出全部对话（ZIP / TXT / Markdown / HTML）", systemImage: "square.and.arrow.up") }
                }
                Section(header: Text("历史对话")) {
                    ForEach(filtered) { conv in
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
                            Button { renamingID = conv.id; renameText = conv.title } label: { Label("重命名", systemImage: "pencil") }
                            Button(role: .destructive) { store.delete(conv.id) } label: { Label("删除对话", systemImage: "trash") }
                        }
                    }
                    .onDelete { idx in
                        let ids = idx.map { filtered[$0].id }
                        for id in ids { store.delete(id) }
                    }
                }
            }
            .navigationTitle("对话")
            .navigationBarTitleDisplayMode(.inline)
            .searchable(text: $searchText, placement: .navigationBarDrawer(displayMode: .always), prompt: "搜索对话")
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) { EditButton() }
                ToolbarItem(placement: .navigationBarTrailing) { Button("完成") { dismiss() } }
            }
            .alert("重命名对话", isPresented: Binding(get: { renamingID != nil }, set: { if !$0 { renamingID = nil } })) {
                TextField("对话名称", text: $renameText)
                Button("保存") { if let id = renamingID { store.rename(id, title: renameText) }; renamingID = nil }
                Button("取消", role: .cancel) { renamingID = nil }
            }
            .sheet(item: $activeConvSheet) { sheet in
                switch sheet {
                case .importFile:
                    DocumentPicker(allowsMultiple: false, contentTypes: [.data]) { urls in
                        activeConvSheet = nil
                        guard let url = urls.first else { return }
                        importing = true
                        importMsg = "正在导入…"
                        importDone = nil
                        Task {
                            let n = await store.importFromURL(url)
                            await MainActor.run {
                                importing = false
                                if n > 0 { importDone = "已导入 \(n) 个对话，可在列表中查看" }
                                else if n == 0 { importDone = "该文件没有可识别的对话" }
                                else { importDone = "无法读取该文件" }
                            }
                        }
                    }
                case .export:
                    ActivityView(items: exportItems)
                }
            }
            .overlay {
                if importing {
                    VStack(spacing: 12) {
                        ProgressView()
                        Text(importMsg).font(.footnote).foregroundColor(.secondary)
                    }
                    .padding(24)
                    .background(.ultraThinMaterial)
                    .clipShape(RoundedRectangle(cornerRadius: 14))
                }
            }
            .alert("导入", isPresented: Binding(get: { importDone != nil }, set: { if !$0 { importDone = nil } })) {
                Button("好") { importDone = nil }
            } message: {
                Text(importDone ?? "")
            }
        }
    }

    private func exportAll(_ ext: String) {
        if let url = store.writeTemp(store.conversations, ext: ext) { exportItems = [url]; activeConvSheet = .export }
    }
}

// MARK: - 设置页
struct SettingsView: View {
    @ObservedObject var store: ChatStore
    @Environment(\.dismiss) var dismiss
    @State private var showBackup = false
    @State private var showRestore = false
    @State private var backupItems: [Any] = []
    @State private var restoreMsg: String?

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
                Section(header: Text("GitHub 代码（读 / 改 / 提交）")) {
                    NavigationLink {
                        GitHubCodeView(store: store)
                    } label: {
                        Label("打开 GitHub 代码", systemImage: "chevron.left.forwardslash.chevron.right")
                    }
                    Text(store.isGitHubConfigured ? "已配置：\(store.ghOwner)/\(store.ghRepo)@\(store.ghBranch)" : "未配置（需填令牌+仓库）")
                        .font(.caption).foregroundColor(.secondary)
                }
                Section(header: Text("模型参数")) {
                    HStack { Text("温度"); Slider(value: Binding(get: { store.temperature }, set: { store.temperature = $0; store.saveGenSettings() }), in: 0...2, step: 0.1); Text(String(format: "%.1f", store.temperature)).font(.caption).frame(width: 34) }
                    HStack { Text("Top P"); Slider(value: Binding(get: { store.topP }, set: { store.topP = $0; store.saveGenSettings() }), in: 0...1, step: 0.05); Text(String(format: "%.2f", store.topP)).font(.caption).frame(width: 44) }
                    Stepper("最大回复长度：\(store.maxTokens == 0 ? "不限" : "\(store.maxTokens)")", value: Binding(get: { store.maxTokens }, set: { store.maxTokens = $0; store.saveGenSettings() }), in: 0...32000, step: 256)
                    Stepper("上下文条数：\(store.contextLimit)", value: Binding(get: { store.contextLimit }, set: { store.contextLimit = $0; store.saveGenSettings() }), in: 1...100)
                    Stepper("工作模式每轮步数：\(store.workStepLimit)", value: Binding(get: { store.workStepLimit }, set: { store.workStepLimit = $0; store.saveGenSettings() }), in: 5...100, step: 5)
                }
                Section(header: Text("外观")) {
                    Picker("主题", selection: Binding(get: { store.appearance }, set: { store.appearance = $0; store.saveGenSettings() })) {
                        Text("跟随系统").tag(0)
                        Text("浅色").tag(1)
                        Text("深色").tag(2)
                    }
                    Stepper("字体大小：\(Int(store.fontSize))", value: Binding(get: { store.fontSize }, set: { store.fontSize = $0; store.saveGenSettings() }), in: 12...24, step: 1)
                }
                Section(header: Text("数据备份 / 恢复"), footer: Text("备份包含对话与配置（不含 API Key，换机后需重新填写 Key）。可存到 iCloud 云盘实现跨设备恢复。")) {
                    Button { if let u = store.backupArchive() { backupItems = [u]; showBackup = true } } label: {
                        Label("备份（导出对话+配置）", systemImage: "arrow.down.doc")
                    }
                    Button { showRestore = true } label: {
                        Label("从备份恢复", systemImage: "arrow.up.doc")
                    }
                    if let m = restoreMsg { Text(m).font(.caption).foregroundColor(.secondary) }
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
            .sheet(isPresented: $showBackup) { ActivityView(items: backupItems) }
            .sheet(isPresented: $showRestore) {
                DocumentPicker(allowsMultiple: false, contentTypes: [.data]) { urls in
                    showRestore = false
                    guard let url = urls.first else { return }
                    Task {
                        let ok = await store.restoreArchive(url)
                        restoreMsg = ok ? "恢复成功（\(store.conversations.count) 个对话）" : "恢复失败：文件无效"
                    }
                }
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
    @State private var detail: IndexBox?

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
                if apis.isEmpty {
                    Text("还没有 API，点下面添加").font(.caption).foregroundColor(.secondary)
                }
                ForEach(apis.indices, id: \.self) { i in
                    HStack(spacing: 10) {
                        VStack(alignment: .leading, spacing: 3) {
                            Text(apis[i].nickname.isEmpty ? "未命名" : apis[i].nickname).font(.subheadline)
                            Text(maskedKey(apis[i].key)).font(.caption).foregroundColor(.secondary)
                        }
                        Spacer()
                        Button { detail = IndexBox(id: i) } label: {
                            HStack(spacing: 2) { Image(systemName: "info.circle"); Text("详情").font(.caption) }
                        }
                        .buttonStyle(.borderless)
                        .foregroundColor(.accentColor)
                        Button(role: .destructive) { apis.remove(at: i) } label: {
                            Image(systemName: "trash")
                        }
                        .buttonStyle(.borderless)
                    }
                }
                Button {
                    apis.append(APIConfig(nickname: "API \(apis.count + 1)", key: ""))
                    detail = IndexBox(id: apis.count - 1)
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
        .sheet(item: $detail) { box in
            if box.id < apis.count {
                APIDetailEditView(
                    api: Binding(get: { apis[box.id] }, set: { apis[box.id] = $0 }),
                    onDelete: { apis.remove(at: box.id); detail = nil }
                )
            }
        }
        .onAppear {
            if let p = store.providers.first(where: { $0.id == providerID }) {
                name = p.name
                baseURL = p.baseURL
                apis = p.apis
            }
        }
    }

    private func maskedKey(_ k: String) -> String {
        if k.isEmpty { return "未填写 Key" }
        if k.count <= 6 { return String(repeating: "•", count: k.count) }
        return "••••••" + k.suffix(4)
    }
}

// 用于 sheet(item:) 的索引包装
struct IndexBox: Identifiable { let id: Int }

// MARK: - 单个 API 详情（查看/改昵称/显示隐藏 key/删除）
struct APIDetailEditView: View {
    @Binding var api: APIConfig
    var onDelete: () -> Void
    @Environment(\.dismiss) var dismiss
    @State private var showKey = false

    var body: some View {
        NavigationView {
            Form {
                Section(header: Text("昵称")) {
                    TextField("如 主号 / 备用", text: $api.nickname)
                }
                Section(header: Text("API Key")) {
                    HStack(spacing: 8) {
                        if showKey {
                            TextField("sk-...", text: $api.key)
                                .autocapitalization(.none).disableAutocorrection(true)
                                .font(.system(.caption, design: .monospaced))
                        } else {
                            SecureField("sk-...", text: $api.key)
                                .autocapitalization(.none).disableAutocorrection(true)
                        }
                        Button { showKey.toggle() } label: {
                            Image(systemName: showKey ? "eye.slash" : "eye")
                        }
                        .buttonStyle(.borderless)
                    }
                    Text("长度 \(api.key.count) 位").font(.caption2).foregroundColor(.secondary)
                }
                Section {
                    Button("删除这个 API", role: .destructive) { onDelete(); dismiss() }
                }
            }
            .navigationTitle("API 详情")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) { Button("完成") { dismiss() } }
            }
        }
    }
}

// MARK: - GitHub 代码（App 内登录 + 限制本仓库）
struct GitHubCodeView: View {
    @ObservedObject var store: ChatStore
    @State private var clientID = ""
    @State private var owner = ""
    @State private var repo = ""
    @State private var branch = "main"
    @State private var files: [String] = []
    @State private var loading = false
    @State private var status: String?
    @State private var errorText: String?

    var body: some View {
        Form {
            Section(header: Text("GitHub 登录（App 内完成，只需 OAuth App 的 Client ID）")) {
                TextField("OAuth App Client ID", text: $clientID)
                    .autocapitalization(.none).disableAutocorrection(true)
                    .font(.system(.caption, design: .monospaced))
                if store.ghLoggedIn {
                    HStack(spacing: 6) { Image(systemName: "checkmark.seal.fill").foregroundColor(.green); Text("已登录 GitHub") }
                    Button("退出登录", role: .destructive) { store.clearGitHubToken() }
                } else {
                    Button(loading ? "登录中…" : "使用 GitHub 登录") { login() }
                        .disabled(loading)
                }
                Text("首次使用：GitHub → Settings → Developer settings → OAuth Apps 新建一个，勾选 Enable Device Flow，把 Client ID 填到上面。验证码会自动复制。")
                    .font(.caption2).foregroundColor(.secondary)
            }
            Section(header: Text("目标仓库（仅此仓库会被访问）")) {
                TextField("所有者（如 colin0252）", text: $owner).autocapitalization(.none).disableAutocorrection(true)
                TextField("仓库名", text: $repo).autocapitalization(.none).disableAutocorrection(true)
                TextField("分支，如 main", text: $branch).autocapitalization(.none).disableAutocorrection(true)
                Button(loading ? "载入中…" : "保存并读取文件列表") { saveAndLoad() }.disabled(loading)
            }
            if let s = status { Section { Text(s).foregroundColor(.secondary).font(.caption) } }
            if let e = errorText { Section { Text(e).foregroundColor(.red).font(.caption) } }
            Section(header: Text("文件（\(files.count)）")) {
                if files.isEmpty {
                    Text("登录并填仓库后点上方按钮加载").foregroundColor(.secondary)
                }
                ForEach(files, id: \.self) { path in
                    NavigationLink { GitHubFileView(store: store, path: path) } label: {
                        Text(path).font(.caption).lineLimit(1)
                    }
                }
            }
        }
        .navigationTitle("GitHub 代码")
        .onAppear {
            clientID = store.ghClientID; owner = store.ghOwner; repo = store.ghRepo; branch = store.ghBranch
        }
    }

    private func login() {
        store.saveGitHubConfig(owner: owner, repo: repo, branch: branch, clientID: clientID)
        guard !clientID.isEmpty else { errorText = "请先填 OAuth App Client ID"; return }
        loading = true; errorText = nil; status = "正在请求验证码…"
        let cid = clientID
        Task { @MainActor in
            let auth = GitHubAuth(clientID: cid)
            do {
                let dc = try await auth.requestDeviceCode()
                status = "验证码：\(dc.userCode) —— 已打开浏览器，请到 GitHub 输入并授权"
                UIPasteboard.general.string = dc.userCode
                if let url = URL(string: dc.verificationURI) { UIApplication.shared.open(url, options: [:], completionHandler: nil) }
                let token = try await auth.pollToken(deviceCode: dc.deviceCode, interval: dc.interval)
                store.setGitHubToken(token)
                status = "登录成功"
                loading = false
                loadFiles()
            } catch {
                var msg = "登录失败"
                if let e = error as? GitHubAuth.AuthError, case let .message(m) = e { msg = m }
                else { msg = error.localizedDescription }
                errorText = msg; status = nil; loading = false
            }
        }
    }

    private func saveAndLoad() {
        store.saveGitHubConfig(owner: owner, repo: repo, branch: branch, clientID: clientID)
        guard store.isGitHubConfigured else { errorText = "请先登录 GitHub 并填仓库所有者/名"; return }
        loadFiles()
    }

    private func loadFiles() {
        guard store.isGitHubConfigured else { return }
        loading = true; errorText = nil
        Task {
            do {
                let list = try await store.ghClient().listFiles()
                await MainActor.run { files = list; status = "已加载 \(list.count) 个文件"; loading = false }
            } catch {
                let msg = (error as? ChatRequestError)?.message ?? error.localizedDescription
                await MainActor.run { errorText = msg; loading = false }
            }
        }
    }
}

// MARK: - GitHub 单文件（AI 改 + 提交）
struct GitHubFileView: View {
    @ObservedObject var store: ChatStore
    let path: String
    @State private var content = ""
    @State private var sha: String?
    @State private var instruction = ""
    @State private var loading = true
    @State private var busy = false
    @State private var status: String?
    @State private var errorText: String?

    private var title: String {
        path.split(separator: "/").last.map { String($0) } ?? path
    }

    var body: some View {
        VStack(spacing: 0) {
            if let e = errorText {
                Text(e).font(.caption).foregroundColor(.red)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(8).background(Color.red.opacity(0.08))
            }
            if loading {
                ProgressView("加载中…").padding()
            } else {
                TextEditor(text: $content)
                    .font(.system(.caption, design: .monospaced))
                    .autocapitalization(.none)
                    .disableAutocorrection(true)
            }
        }
        .navigationTitle(title)
        .navigationBarTitleDisplayMode(.inline)
        .safeAreaInset(edge: .bottom) {
            VStack(spacing: 8) {
                if let s = status { Text(s).font(.caption).foregroundColor(.secondary) }
                HStack(spacing: 8) {
                    TextField("让 AI 怎么改（如：修复输入框无反应）", text: $instruction)
                        .textFieldStyle(.roundedBorder)
                    Button(busy ? "处理中…" : "AI 修改") { aiModify() }
                        .disabled(busy || instruction.isEmpty)
                }
                Button(busy ? "提交中…" : "提交到仓库") { commit() }
                    .buttonStyle(.borderedProminent)
                    .disabled(busy || loading)
                    .frame(maxWidth: .infinity)
            }
            .padding(10)
            .background(.ultraThinMaterial)
        }
        .onAppear(perform: loadFile)
    }

    private func loadFile() {
        loading = true
        errorText = nil
        Task {
            do {
                let (c, s) = try await store.ghClient().getFile(path: path)
                await MainActor.run { content = c; sha = s; loading = false }
            } catch {
                let msg = (error as? ChatRequestError)?.message ?? error.localizedDescription
                await MainActor.run { errorText = msg; loading = false }
            }
        }
    }

    private func aiModify() {
        busy = true
        status = "AI 修改中…"
        errorText = nil
        Task {
            let (newContent, err) = await store.modifyFileWithAI(fileName: path, current: content, instruction: instruction)
            await MainActor.run {
                if let nc = newContent, !nc.isEmpty {
                    content = nc
                    status = "已生成修改，确认后点『提交到仓库』"
                } else {
                    errorText = err ?? "AI 未返回内容"
                    status = nil
                }
                busy = false
            }
        }
    }

    private func commit() {
        busy = true
        status = "提交中…"
        errorText = nil
        Task {
            do {
                try await store.ghClient().putFile(path: path, content: content, sha: sha, message: "更新 \(path)")
                let (_, s) = try await store.ghClient().getFile(path: path)
                await MainActor.run { sha = s; status = "已提交到分支 \(store.ghBranch)"; busy = false }
            } catch {
                let msg = (error as? ChatRequestError)?.message ?? error.localizedDescription
                await MainActor.run { errorText = msg; status = nil; busy = false }
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
