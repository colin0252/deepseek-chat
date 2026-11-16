import SwiftUI
import Foundation
import Security
import PhotosUI
import UIKit

// MARK: - 数据模型
struct ChatMessage: Identifiable {
    enum Role: String { case user, assistant }
    let id = UUID()
    var role: Role
    var content: String
    var imageBase64: String?
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
    var supportsImage: Bool { (input_modalities ?? []).contains("image") }
}

struct ModelsResponse: Decodable { let data: [ModelInfo] }

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

// MARK: - DeepSeek 网络客户端（流式 + 联网搜索 + 图片）
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

    private func cleanedBase() -> String {
        apiBase.trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
    }

    private func encodeMessages(_ msgs: [ChatMessage]) -> [[String: Any]] {
        msgs.map { m in
            if let b64 = m.imageBase64, !b64.isEmpty {
                let content: [[String: Any]] = [
                    ["type": "text", "text": m.content],
                    ["type": "image_url", "image_url": ["url": "data:image/jpeg;base64,\(b64)"]]
                ]
                return ["role": m.role.rawValue, "content": content]
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

    var currentModelSupportsImage: Bool {
        models.first(where: { $0.id == selectedModel })?.supportsImage ?? false
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

    func send(_ text: String, image: Data?) async {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty || image != nil else { return }
        guard !isSending else { return }
        guard !apiKey.isEmpty else {
            errorText = "请先在设置里填写 API Key"
            return
        }
        if image != nil && !currentModelSupportsImage {
            errorText = "当前模型（\(currentModelDisplay)）不支持图片，请换一个支持图片的模型"
            return
        }
        errorText = nil
        statusText = nil
        let b64 = image?.base64EncodedString()
        messages.append(ChatMessage(role: .user, content: trimmed, imageBase64: b64))
        let assistantIndex = messages.count
        messages.append(ChatMessage(role: .assistant, content: "", imageBase64: nil))
        isSending = true

        let convo = Array(messages.prefix(assistantIndex))
        let effectiveModel = webSearch ? "deepseek-flash" : selectedModel
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

// MARK: - 单条消息
struct MessageRow: View {
    let message: ChatMessage
    var body: some View {
        HStack {
            if message.role == .user { Spacer(minLength: 40) }
            VStack(alignment: message.role == .user ? .trailing : .leading, spacing: 6) {
                if let b64 = message.imageBase64, let d = Data(base64Encoded: b64), let ui = UIImage(data: d) {
                    Image(uiImage: ui)
                        .resizable()
                        .scaledToFit()
                        .frame(maxWidth: 180)
                        .clipShape(RoundedRectangle(cornerRadius: 10))
                }
                if !message.content.isEmpty {
                    Text(message.content)
                        .padding(10)
                        .background(message.role == .user
                                    ? Color.accentColor.opacity(0.22)
                                    : Color(UIColor.secondarySystemBackground))
                        .clipShape(RoundedRectangle(cornerRadius: 14))
                        .textSelection(.enabled)
                } else if message.imageBase64 == nil {
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
    @State private var pickedImage: Data?
    @State private var photoItem: PhotosPickerItem?

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
                if let img = pickedImage, let ui = UIImage(data: img) {
                    HStack {
                        Image(uiImage: ui).resizable().scaledToFit().frame(height: 60).clipShape(RoundedRectangle(cornerRadius: 8))
                        Button {
                            pickedImage = nil
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
                    PhotosPicker(selection: $photoItem, matching: .images) {
                        Image(systemName: "photo.on.rectangle")
                            .font(.system(size: 20))
                    }
                    .onChange(of: photoItem) { newItem in
                        guard let newItem = newItem else { return }
                        Task {
                            if let data = try? await newItem.loadTransferable(type: Data.self) {
                                let jpeg: Data
                                if let ui = UIImage(data: data), let j = ui.jpegData(compressionQuality: 0.8) {
                                    jpeg = j
                                } else {
                                    jpeg = data
                                }
                                await MainActor.run { pickedImage = jpeg }
                            }
                        }
                    }
                    TextField("输入消息…", text: $input, axis: .vertical)
                        .lineLimit(1...5)
                        .padding(8)
                        .background(Color(UIColor.secondarySystemBackground))
                        .clipShape(RoundedRectangle(cornerRadius: 12))
                    Button {
                        let t = input
                        let img = pickedImage
                        input = ""
                        pickedImage = nil
                        photoItem = nil
                        Task { await store.send(t, image: img) }
                    } label: {
                        Image(systemName: "paperplane.fill")
                            .font(.system(size: 18))
                            .padding(8)
                    }
                    .disabled(store.isSending || (input.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && pickedImage == nil))
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
