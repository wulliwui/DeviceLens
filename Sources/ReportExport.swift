import Foundation

final class ReportFile: Identifiable {
    let id = UUID()
    let url: URL

    init(report: DeviceReport) throws {
        let html = try ReportHTML.render(report)
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(id.uuidString, isDirectory: true)
        let timestamp = ISO8601DateFormatter().string(from: report.collectedAt).replacingOccurrences(of: ":", with: "-")
        url = directory.appendingPathComponent("DeviceLens-\(timestamp).html")

        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        do {
            try Data(html.utf8).write(to: url, options: [.atomic, .completeFileProtection])
        } catch {
            try? FileManager.default.removeItem(at: directory)
            throw error
        }
    }

    deinit { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
}

private enum ReportHTML {
    private static let sourceNames = [
        "DeviceCollector.swift", "SampleCollector.swift", "SampleLocalSources.swift", "SampleLocation.swift",
        "SampleNative.c", "SampleNative.h", "EnvironmentDetector.swift", "SampleProfiles.swift",
    ]

    private struct Source {
        let name: String
        let text: String
        let lines: [String]

        var anchor: String { "source-" + name }

        init(name: String, text: String) {
            self.name = name
            self.text = text
            lines = text.components(separatedBy: "\n")
        }

        func declaration(prefixes: [String], includeClosingBrace: Bool = false) -> (line: Int, code: String)? {
            guard let start = lines.firstIndex(where: { line in
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                return prefixes.contains { trimmed.hasPrefix($0) }
            }) else { return nil }
            let indent = lines[start].prefix(while: { $0 == " " }).count
            var end = start + 1
            while end < lines.count && lines[end].prefix(while: { $0 == " " }).count > indent {
                end += 1
            }
            if includeClosingBrace, end > start + 1, end < lines.count,
               lines[end].trimmingCharacters(in: .whitespaces) == "}" {
                end += 1
            }
            let code = lines[start..<end].map { String($0.dropFirst(indent)) }.joined(separator: "\n")
            return (start + 1, code)
        }
    }

    private enum ExportError: LocalizedError {
        case missingResource(String), invalidGuide, missingField(String)

        var errorDescription: String? {
            switch self {
            case .missingResource(let name): return "当前构建缺少导出资源（\(name)）。"
            case .invalidGuide: return "字段解释表无法读取。"
            case .missingField(let id): return "字段 \(id) 缺少解释或采集代码。"
            }
        }
    }

    static func render(_ report: DeviceReport) throws -> String {
        let guide = try fieldGuide()
        let sources = try sourceNames.map { name in
            guard let url = Bundle.main.resourceURL?.appendingPathComponent("ReportSources/\(name)") else {
                throw ExportError.missingResource(name)
            }
            return Source(name: name, text: try String(contentsOf: url, encoding: .utf8))
        }
        let indexedSources = Dictionary(uniqueKeysWithValues: sources.map { ($0.name, $0) })
        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? ""
        let sectionLinks = report.groups.map {
            "<a href=\"#group-\(escape($0.id))\">\(escape($0.title))</a>"
        }.joined(separator: "\n")
        let sections = try report.groups.map { group in
            let fields = try group.readings.map { try fieldHTML($0, guide: guide, sources: indexedSources) }
            return """
            <section id="group-\(escape(group.id))">
            <h2>\(escape(group.title)) <small>\(group.readings.count) 项</small></h2>
            \(fields.joined(separator: "\n"))
            </section>
            """
        }
        let appendix = sources.map { source in
            """
            <details id="\(source.anchor)">
            <summary>\(escape(source.name))</summary>
            <pre><code>\(escape(source.text))</code></pre>
            </details>
            """
        }
        let json = try ReportJSON.encode(report)
        return """
        <!doctype html>
        <html lang="zh-CN">
        <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'">
        <title>设备检查 · 采集报告</title>
        <style>
        :root { color-scheme: light dark; font: 16px/1.55 system-ui, sans-serif; }
        body { max-width: 66rem; margin: 0 auto; padding: 1.2rem; }
        h1, h2 { line-height: 1.2; }
        h2 { border-bottom: 1px solid GrayText; padding-bottom: .5rem; }
        nav { display: flex; flex-wrap: wrap; gap: .6rem 1rem; }
        article { padding: .7rem 0; border-bottom: 1px solid color-mix(in srgb, GrayText 30%, transparent); }
        h3, p { margin: .35rem 0; }
        small, .muted { color: GrayText; font-size: .84rem; }
        pre { overflow: auto; white-space: pre-wrap; overflow-wrap: anywhere; margin: .45rem 0;
              background: color-mix(in srgb, CanvasText 6%, Canvas); padding: .65rem; border-radius: .4rem; }
        summary { cursor: pointer; }
        details { padding: .25rem 0; }
        </style>
        </head>
        <body>
        <header>
        <h1>设备检查 · 采集报告</h1>
        <p class="muted">采集时间 \(escape(ISO8601DateFormatter().string(from: report.collectedAt))) · App \(escape(version)) · \(report.readings.count) 项</p>
        <p>文件含本次采集的原始值，可能包含标识符、网络和定位信息。分享前请核对接收方。</p>
        <p>字段代码来自生成此报告的 DeviceLens 构建。图灵和同盾的编号与含义用于对照样本，源码为本 App 的实现。</p>
        <nav>\(sectionLinks) <a href="#raw-json">原始 JSON</a> <a href="#source-appendix">源码附录</a></nav>
        </header>
        <main>
        \(sections.joined(separator: "\n"))
        <section id="raw-json"><h2>原始 JSON</h2>
        <details><summary>展开本次采集 JSON</summary><pre>\(escape(json))</pre></details></section>
        <section id="source-appendix"><h2>源码附录</h2>
        <p>包含字段取值、辅助函数、系统调用与原始数据编码的实际源码。</p>
        \(appendix.joined(separator: "\n"))
        </section>
        </main>
        </body>
        </html>
        """
    }

    private static func fieldGuide() throws -> [String: String] {
        guard let url = Bundle.main.url(forResource: "ReportFieldGuide", withExtension: "tsv") else {
            throw ExportError.missingResource("ReportFieldGuide.tsv")
        }
        let text = try String(contentsOf: url, encoding: .utf8)
        var result: [String: String] = [:]
        for line in text.split(separator: "\n") {
            let pair = line.split(separator: "\t", maxSplits: 1).map(String.init)
            guard pair.count == 2, result.updateValue(pair[1], forKey: pair[0]) == nil else {
                throw ExportError.invalidGuide
            }
        }
        return result
    }

    private static func fieldHTML(_ reading: Reading, guide: [String: String], sources: [String: Source]) throws -> String {
        let prefix = reading.id.split(separator: ".", maxSplits: 1)
        let sourceName: String
        let declarations: [String]
        let note: String
        switch prefix.first {
        case "turing":
            sourceName = "SampleCollector.swift"
            declarations = ["t(\(prefix.last ?? ""),"]
            note = "字段写入代码"
        case "tongdun":
            sourceName = "SampleCollector.swift"
            declarations = ["d(\(prefix.last ?? ""),", "n(\(prefix.last ?? ""),"]
            note = "字段写入代码"
        case "omitted":
            sourceName = "DeviceCollector.swift"
            declarations = ["(\"\(prefix.last ?? "")\","]
            note = "未采集状态的定义"
        default:
            sourceName = prefix.first == "location" ? "SampleLocation.swift" : "DeviceCollector.swift"
            declarations = ["Reading(\"\(reading.id)\","]
            note = "字段取值代码"
        }
        guard let explanation = guide[reading.id], let source = sources[sourceName],
              let snippet = source.declaration(prefixes: declarations) else {
            throw ExportError.missingField(reading.id)
        }
        let helper = sources["SampleLocalSources.swift"].map { helperHTML(for: snippet.code, source: $0) } ?? ""
        let value = reading.value.map { $0.isEmpty ? "\"\"" : $0 } ?? "—"
        let remark = reading.note.map { "<p class=\"muted\">\(escape($0))</p>" } ?? ""
        return """
        <article id="field-\(escape(reading.id))">
        <h3>\(escape(reading.label))</h3>
        <p class="muted"><code>\(escape(reading.id))</code> · \(reading.status.title)</p>
        <p>\(escape(explanation))</p>
        <pre class="value">\(escape(value))</pre>
        \(remark)
        <details><summary>\(note)</summary>
        <p class="muted"><a href="#\(source.anchor)">\(source.name):\(snippet.line)</a></p>
        <pre><code>\(escape(snippet.code))</code></pre>
        \(helper)
        </details>
        </article>
        """
    }

    private static func helperHTML(for code: String, source: Source) -> String {
        guard let reference = code.range(of: #"\bsource\.[A-Za-z_]\w*"#, options: .regularExpression) else { return "" }
        let name = code[reference].dropFirst("source.".count)
        let prefixes = ["var \(name):", "let \(name) =", "func \(name)("]
        guard let helper = source.declaration(prefixes: prefixes, includeClosingBrace: true) else { return "" }
        let native = helper.code.contains("sample_dns_servers") || helper.code.contains("sample_cell_transmitted_bytes")
            ? " · <a href=\"#source-SampleNative.c\">底层 C 代码</a>" : ""
        return """
        <p class="muted">采集实现 · <a href="#\(source.anchor)">\(source.name):\(helper.line)</a>\(native)</p>
        <pre><code>\(escape(helper.code))</code></pre>
        """
    }

    private static func escape(_ text: String) -> String {
        text.replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;")
    }
}
