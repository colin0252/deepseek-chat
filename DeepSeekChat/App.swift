import SwiftUI
import Foundation
import Security
import PhotosUI
import UIKit
import UniformTypeIdentifiers

// MARK: - 数据模型
struct Attachment {
    var data: Data
    var filename: String
    var purpose: String      // user_data / text_recognition / rich_layout_recognition
    var isImage: Bool
    var mimeType: String
    var fileId: String?      // 上传成功后填入
}

struct ChatMessage: Identifiable {
    enum Role: String { case user, assistant }
    let id = UUID()
    var role: Role
    var content: String
    var attachment: Attachment?
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

// MARK: - 文件类型 → purpose / mime
enum FileClassifier {
    static func make(from url: URL) -> Attachment? {
        let access = url.startAccessingSecurityScopedResource()
        defer { if access { url.stopAccessingSecurityScopedResource() } }
        guard let data = try? Data(contentsOf: url) else { return nil }
        let name = url.lastPathComponent
        let ext = url.pathExtension.lowercased()
        var purpose = "user_data"
        var isImage = false
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
        case "txt", "md", "csv", "json", "xml", "html", "swift", "py", "js", "ts", "c", "cpp", "java":
            mime = "text/plain"
        default:
            mime = "application/octet-stream"
        }
        return Attachment(data: data, filename: name, purpose: purpose,
                          isImage: isImage, mimeType: mime, fileId: nil)
    }

    static func image(from data: Data) -> Attachment? {
        let jpeg: Data
        if let ui = UIImage(data: data), let j = ui.jpegData(compressionQuality: 0.85) {
            jpeg = j
        } else {
            jpeg = data
        }
        return Attachment(data: jpeg, filename: "photo.jpg", purpose: "user_data",
                          isImage: true, mimeType: "image/jpeg", fileId: nil)
    }
}

// MARK: - 钥匙串（安全保存 API Key）
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

// MARK: - DeepSeek 网络客户端（上传文件 + 流式对话 + 联网搜索）
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

    // 上传文件到 Files API，返回 file_id
    func uploadFile(_ att: Attachment) async throws -> String {
        guard let url = URL(string: cleanedBase() + "/files") else {
            throw ChatRequestError(message: "API 地址无效")
        }
        let boundary = "Boundary-\(UUID().uuidString)"
        var body = Data()
        func app(_ s: String) { if let d = s.data(using: .utf8) { body.append(d) } }
        app("--\(boundary)\r\n")
        app("Content-Disposition: form-data; name=\"purpose\"\r\n\r\n")
        app("\(att.purpose)\r\n")
        app("--\(boundary)\r\n")
        app("Content-Disposition: form-data; name=\"file\"; filename=\"\(att.filename)\"\r\n")
        app("Content-Type: \(att.mimeType)\r\n\r\n")
        body.append(att.data)
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
            if let att = m.attachment, let fid = att.fileId {
                var blocks: [[String: Any]] = []
                if !m.content.isEmpty { blocks.append(["type": "text", "text": m.content]) }
                blocks.append(["type": "file", "file_id": fid])
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
    @Published var messages: [ChatMessage] = []
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

    init() {
        apiBase = UserDefaults.standard.string(forKey: "apiBase") ?? "https://api.deepseek.com"
        selectedModel = UserDefaults.standard.string(forKey: "model") ?? "deepseek-chat"
        webSearch = UserDefaults.standard.bool(forKey: "webSearch")
        apiKey = Keychain.read("apiKey")
    }

    var currentModelDisplay: String {
        models.first(where: { $0.id == selectedModel })?.display ?? selectedModel
    }

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

    func clear() {
        messages.removeAll()
        errorText = nil
        statusText = nil
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

    func send(_ text: String, attachment: Attachment?) async {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty || attachment != nil else { return }
        guard !isSending else { return }
        guard !apiKey.isEmpty else {
            errorText = "请先在设置里填写 API Key"
            return
        }
        errorText = nil
        statusText = nil
        isSending = true

        // 1) 若有附件，先上传拿 file_id
        var att = attachment
        let needsFile = att != nil
        if var a = att {
            statusText = "正在上传文件…"
            let uploader = DeepSeekClient(apiBase: apiBase, apiKey: apiKey, model: selectedModel, webSearch: false)
            do {
                let fid = try await uploader.uploadFile(a)
                a.fileId = fid
                att = a
            } catch {
                let msg = (error as? ChatRequestError)?.message ?? error.localizedDescription
                errorText = "文件上传失败：\(msg)"
                statusText = nil
                isSending = false
                return
            }
        }
        statusText = nil

        messages.append(ChatMessage(role: .user, content: trimmed, attachment: att))
        let assistantIndex = messages.count
        messages.append(ChatMessage(role: .assistant, content: "", attachment: nil))

        let convo = Array(messages.prefix(assistantIndex))
        let effectiveModel = (needsFile || webSearch) ? "deepseek-flash" : selectedModel
        let client = DeepSeekClient(apiBase: apiBase, apiKey: apiKey, model: effectiveModel, webSearch: webSearch)
        do {
            for try await ev in client.stream(messages: convo) {
                switch ev {
                case .text(let t):
                    if assistantIndex < messages.count { messages[assistantIndex].content = t }
                case .status(let s):
                    statusText = s.isEmpty ? nil : s
                }
            }
        } catch {
            let msg = (error as? ChatRequestError)?.message ?? error.localizedDescription
            if assistantIndex < messages.count {
                if messages[assistantIndex].content.isEmpty {
                    messages[assistantIndex].content = "⚠️ " + msg
                } else {
                    errorText = msg
                }
            }
        }
        statusText = nil
        isSending = false
    }
}

// MARK: - 附件小视图
struct AttachmentChip: View {
    let att: Attachment
    var body: some View {
        if att.isImage, let ui = UIImage(data: att.data) {
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
        HStack {
            if message.role == .user { Spacer(minLength: 40) }
            VStack(alignment: message.role == .user ? .trailing : .leading, spacing: 6) {
                if let att = message.attachment {
                    AttachmentChip(att: att)
                }
                if !message.content.isEmpty {
                    Text(message.content)
                        .padding(10)
                        .background(message.role == .user
                                    ? Color.accentColor.opacity(0.22)
                                    : Color(UIColor.secondarySystemBackground))
                        .clipShape(RoundedRectangle(cornerRadius: 14))
                        .textSelection(.enabled)
                } else if message.attachment == nil {
                    Text("…")
                        .padding(10)
                        .background(Color(UIColor.secondarySystemBackground))
                        .clipShape(RoundedRectangle(cornerRadius: 14))
                }
            }
            if message.role == .assistant { Spacer(minLength: 40) }
        }
    }
}

// MARK: - 主界面
struct ContentView: View {
    @StateObject private var store = ChatStore()
    @State private var input = ""
    @State private var showSettings = false
    @State private var picked: Attachment?
    @State private var photoItem: PhotosPickerItem?
    @State private var showPhotos = false
    @State private var showFiles = false

    var body: some View {
        NavigationView {
            VStack(spacing: 0) {
                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 12) {
                            if store.messages.isEmpty {
                                Text("你好，我是你的 DeepSeek。点右上角齿轮填 API Key 就能用。")
                                    .foregroundColor(.secondary)
                                    .padding(.top, 20)
                            }
                            ForEach(store.messages) { m in
                                MessageRow(message: m).id(m.id)
                            }
                            if let s = store.statusText {
                                Text(s).font(.footnote).foregroundColor(.secondary)
                            }
                        }
                        .padding()
                    }
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
                        .padding(.horizontal)
                        .padding(.top, 4)
                }
                Divider()
                if let p = picked {
                    HStack {
                        if p.isImage, let ui = UIImage(data: p.data) {
                            Image(uiImage: ui).resizable().scaledToFit().frame(height: 60).clipShape(RoundedRectangle(cornerRadius: 8))
                        } else {
                            Label(p.filename, systemImage: "doc.fill").font(.caption)
                        }
                        Button {
                            picked = nil
                            photoItem = nil
                        } label: {
                            Image(systemName: "xmark.circle.fill").foregroundColor(.secondary)
                        }
                        Spacer()
                    }
                    .padding(.horizontal)
                    .padding(.top, 6)
                }
                HStack(alignment: .bottom, spacing: 8) {
                    Menu {
                        Button { showPhotos = true } label: { Label("照片", systemImage: "photo") }
                        Button { showFiles = true } label: { Label("文件（PDF/Word/PPT/Excel/txt…）", systemImage: "folder") }
                    } label: {
                        Image(systemName: "paperclip")
                            .font(.system(size: 20))
                    }
                    TextField("输入消息…", text: $input, axis: .vertical)
                        .lineLimit(1...5)
                        .padding(8)
                        .background(Color(UIColor.secondarySystemBackground))
                        .clipShape(RoundedRectangle(cornerRadius: 12))
                    Button {
                        let t = input
                        let img = picked
                        input = ""
                        picked = nil
                        photoItem = nil
                        Task { await store.send(t, attachment: img) }
                    } label: {
                        Image(systemName: "paperplane.fill")
                            .font(.system(size: 18))
                            .padding(8)
                    }
                    .disabled(store.isSending || (input.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && picked == nil))
                }
                .padding(10)
            }
            .navigationTitle("我的 DeepSeek")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button { store.toggleWebSearch() } label: {
                        Image(systemName: "globe")
                            .foregroundColor(store.webSearch ? .accentColor : .secondary)
                    }
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button { showSettings = true } label: {
                        Image(systemName: "gearshape")
                    }
                }
            }
            .sheet(isPresented: $showSettings) {
                SettingsView(store: store)
            }
            .photosPicker(isPresented: $showPhotos, selection: $photoItem, matching: .images)
            .onChange(of: photoItem) { newItem in
                guard let newItem = newItem else { return }
                Task {
                    if let data = try? await newItem.loadTransferable(type: Data.self),
                       let made = FileClassifier.image(from: data) {
                        await MainActor.run { picked = made }
                    }
                }
            }
            .fileImporter(isPresented: $showFiles, allowedContentTypes: [.item], allowsMultipleSelection: false) { result in
                switch result {
                case .success(let urls):
                    if let url = urls.first, let made = FileClassifier.make(from: url) {
                        picked = made
                    }
                case .failure(let e):
                    store.errorText = "选取文件失败：\(e.localizedDescription)"
                }
            }
            .task { await store.loadModels() }
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
                Section(header: Text("文件上传说明")) {
                    Text("发送文件或图片时会自动改用 deepseek-flash 模型（官方文件解析只支持该模型）。支持 PDF/Word/PPT/Excel/txt/图片等。")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                Section {
                    Button("清空对话", role: .destructive) { store.clear() }
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
