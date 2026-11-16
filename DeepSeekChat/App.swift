import SwiftUI
import Foundation
import Security

// MARK: - 数据模型
struct ChatMessage: Identifiable, Codable {
    enum Role: String, Codable { case user, assistant }
    let id: UUID
    var role: Role
    var content: String
    init(id: UUID = UUID(), role: Role, content: String) {
        self.id = id
        self.role = role
        self.content = content
    }
}

struct ChatRequestError: Error { let message: String }

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

// MARK: - DeepSeek 网络客户端（流式）
final class DeepSeekClient {
    let apiBase: String
    let apiKey: String
    let model: String
    init(apiBase: String, apiKey: String, model: String) {
        self.apiBase = apiBase
        self.apiKey = apiKey
        self.model = model
    }

    func stream(messages: [ChatMessage]) -> AsyncThrowingStream<String, Error> {
        AsyncThrowingStream { continuation in
            let task = Task {
                do {
                    let trimmed = apiBase.trimmingCharacters(in: .whitespacesAndNewlines)
                        .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
                    guard let url = URL(string: trimmed + "/chat/completions") else {
                        throw ChatRequestError(message: "API 地址无效")
                    }
                    var req = URLRequest(url: url)
                    req.httpMethod = "POST"
                    req.setValue("application/json", forHTTPHeaderField: "Content-Type")
                    req.setValue("Bearer \(apiKey)", forHTTPHeaderField: "Authorization")
                    let body: [String: Any] = [
                        "model": model,
                        "stream": true,
                        "messages": messages.map { ["role": $0.role.rawValue, "content": $0.content] }
                    ]
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
                        guard let data = payload.data(using: .utf8) else { continue }
                        if let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                           let choices = obj["choices"] as? [[String: Any]],
                           let delta = choices.first?["delta"] as? [String: Any],
                           let content = delta["content"] as? String, !content.isEmpty {
                            full += content
                            continuation.yield(full)
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
    @Published var apiBase: String
    @Published var model: String
    var apiKey: String

    init() {
        apiBase = UserDefaults.standard.string(forKey: "apiBase") ?? "https://api.deepseek.com"
        model = UserDefaults.standard.string(forKey: "model") ?? "deepseek-chat"
        apiKey = Keychain.read("apiKey")
    }

    func saveSettings(apiKey: String, apiBase: String, model: String) {
        self.apiKey = apiKey
        self.apiBase = apiBase
        self.model = model
        Keychain.save(apiKey, for: "apiKey")
        UserDefaults.standard.set(apiBase, forKey: "apiBase")
        UserDefaults.standard.set(model, forKey: "model")
    }

    func clear() {
        messages.removeAll()
        errorText = nil
    }

    func send(_ text: String) async {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !isSending else { return }
        guard !apiKey.isEmpty else {
            errorText = "请先在设置里填写 API Key"
            return
        }
        errorText = nil
        messages.append(ChatMessage(role: .user, content: trimmed))
        let assistantIndex = messages.count
        messages.append(ChatMessage(role: .assistant, content: ""))
        isSending = true

        let convo = Array(messages.prefix(assistantIndex))
        let client = DeepSeekClient(apiBase: apiBase, apiKey: apiKey, model: model)
        do {
            for try await partial in client.stream(messages: convo) {
                if assistantIndex < messages.count {
                    messages[assistantIndex].content = partial
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
        isSending = false
    }
}

// MARK: - 单条消息
struct MessageRow: View {
    let message: ChatMessage
    var body: some View {
        HStack {
            if message.role == .user { Spacer(minLength: 40) }
            Text(message.content.isEmpty ? "…" : message.content)
                .padding(10)
                .background(
                    message.role == .user
                    ? Color.accentColor.opacity(0.22)
                    : Color(UIColor.secondarySystemBackground)
                )
                .clipShape(RoundedRectangle(cornerRadius: 14))
                .textSelection(.enabled)
            if message.role == .assistant { Spacer(minLength: 40) }
        }
    }
}

// MARK: - 主界面
struct ContentView: View {
    @StateObject private var store = ChatStore()
    @State private var input = ""
    @State private var showSettings = false

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
                HStack(alignment: .bottom, spacing: 8) {
                    TextField("输入消息…", text: $input, axis: .vertical)
                        .lineLimit(1...5)
                        .padding(8)
                        .background(Color(UIColor.secondarySystemBackground))
                        .clipShape(RoundedRectangle(cornerRadius: 12))
                    Button {
                        let t = input
                        input = ""
                        Task { await store.send(t) }
                    } label: {
                        Image(systemName: "paperplane.fill")
                            .font(.system(size: 18))
                            .padding(8)
                    }
                    .disabled(store.isSending || input.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
                .padding(10)
            }
            .navigationTitle("我的 DeepSeek")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button { showSettings = true } label: {
                        Image(systemName: "gearshape")
                    }
                }
            }
            .sheet(isPresented: $showSettings) {
                SettingsView(store: store)
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
    @State private var model = "deepseek-chat"
    private let models = ["deepseek-chat", "deepseek-reasoner"]

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
                Section(header: Text("模型")) {
                    Picker("模型", selection: $model) {
                        ForEach(models, id: \.self) { Text($0) }
                    }
                    .pickerStyle(.inline)
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
                                           model: model)
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
                model = store.model
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