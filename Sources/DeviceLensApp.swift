import SwiftUI
import UIKit

@main
struct DeviceLensApp: App {
    var body: some Scene {
        WindowGroup { InspectorView() }
    }
}

@MainActor
private struct InspectorView: View {
    enum Panel: String, CaseIterable {
        case readings = "采集报告"
        case findings = "环境判断"
    }

    @State private var panel = Panel.readings
    @State private var device: DeviceReport?
    @State private var environment: EnvironmentReport?
    @State private var collecting = false
    @State private var checking = false
    @State private var rawReport: RawReport?
    @State private var jsonError = false
    @State private var reportFile: ReportFile?
    @State private var exportError = ""
    @State private var showExportError = false

    var body: some View {
        NavigationStack {
            List {
                Section {
                    intro
                        .listRowInsets(EdgeInsets())
                        .listRowBackground(Color.clear)
                    Picker("报告", selection: $panel) {
                        ForEach(Panel.allCases, id: \.self) { Text($0.rawValue).tag($0) }
                    }
                    .pickerStyle(.segmented)
                    .accessibilityIdentifier("reportPicker")
                    .listRowInsets(EdgeInsets(top: 4, leading: 0, bottom: 4, trailing: 0))
                    .listRowBackground(Color.clear)
                }
                .listRowSeparator(.hidden)

                switch panel {
                case .readings: collectionContent
                case .findings: findingContent
                }
            }
            .listStyle(.insetGrouped)
            .navigationTitle("设备检查")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button {
                        showJSON()
                    } label: {
                        Label("查看 JSON", systemImage: "curlybraces")
                    }
                    .accessibilityIdentifier("showJSON")
                    .disabled(panel == .readings ? device == nil : environment == nil)
                }
            }
            .sheet(item: $rawReport) { raw in RawReportView(report: raw) }
            .sheet(item: $reportFile) { file in ReportShareView(file: file) }
            .alert("无法生成 JSON", isPresented: $jsonError) { Button("好", role: .cancel) {} }
            .alert("无法导出报告", isPresented: $showExportError) {
                Button("好", role: .cancel) {}
            } message: {
                Text(exportError)
            }
        }
    }

    private var intro: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .center, spacing: 13) {
                Image(systemName: "iphone")
                    .font(.system(size: 24, weight: .semibold))
                    .frame(width: 48, height: 48)
                    .background(.white.opacity(0.15), in: RoundedRectangle(cornerRadius: 13))
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 3) {
                    Text("本机诊断").font(.title2.bold())
                    Text("按需采集 · 可手动分享报告").font(.footnote).foregroundStyle(.white.opacity(0.86))
                }
            }
            ViewThatFits(in: .horizontal) {
                HStack(spacing: 10) { collectButton; judgeButton }
                VStack(spacing: 10) { collectButton; judgeButton }
            }
        }
        .foregroundStyle(.white)
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background {
            RoundedRectangle(cornerRadius: 19)
                .fill(LinearGradient(colors: [Color(red: 0.11, green: 0.23, blue: 0.39),
                                               Color(red: 0.12, green: 0.36, blue: 0.43)],
                                     startPoint: .topLeading, endPoint: .bottomTrailing))
        }
        .padding(.vertical, 2)
    }

    private var collectButton: some View {
        actionButton("开始采集", icon: "tray.and.arrow.down", busy: collecting,
                     id: "startCollection", primary: true) { startCollection() }
    }

    private var judgeButton: some View {
        actionButton("判断", icon: "checkmark.shield", busy: checking,
                     id: "checkEnvironment", primary: false, action: startCheck)
    }

    private func actionButton(_ title: String, icon: String, busy: Bool, id: String,
                              primary: Bool, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: 7) {
                if busy { ProgressView().tint(primary ? .black : .white) }
                else { Image(systemName: icon).accessibilityHidden(true) }
                Text(title).fixedSize()
            }
            .font(.subheadline.weight(.semibold))
            .frame(maxWidth: .infinity, minHeight: 44)
            .padding(.horizontal, 7)
            .foregroundStyle(primary ? Color(red: 0.12, green: 0.24, blue: 0.37) : .white)
            .background(primary ? .white : .white.opacity(0.16), in: RoundedRectangle(cornerRadius: 10))
        }
        .buttonStyle(.plain)
        .accessibilityIdentifier(id)
        .disabled(busy)
    }

    @ViewBuilder
    private var collectionContent: some View {
        if let device {
            let total = device.readings
            let count = total.filter { $0.status == .collected }.count
            Section {
                VStack(alignment: .leading, spacing: 6) {
                    Text("已读取 \(count) / \(total.count) 项").font(.headline)
                        .accessibilityIdentifier("collectionSummary")
                    Text(device.collectedAt.formatted(date: .abbreviated, time: .standard))
                        .font(.footnote).foregroundStyle(.secondary)
                }
                Button {
                    exportReport(device)
                } label: {
                    Label("导出报告文件", systemImage: "square.and.arrow.up")
                }
                .disabled(collecting)
                .accessibilityIdentifier("shareReport")
            }
            if device.sampleProfiles.location.canRequestPermission {
                Section {
                    Button("授权定位后采集") { startCollection(requestLocationPermission: true) }
                        .disabled(collecting)
                        .accessibilityIdentifier("authorizeLocationCollection")
                }
            }
            ForEach(device.groups) { group in
                Section(group.title) {
                    ForEach(group.readings) { reading in
                        VStack(alignment: .leading, spacing: 5) {
                            HStack(alignment: .firstTextBaseline) {
                                Text(reading.label).font(.subheadline.weight(.semibold))
                                Spacer(minLength: 8)
                                if reading.status != .collected {
                                    Text(reading.status.title).font(.caption).foregroundStyle(.secondary)
                                }
                            }
                            if let value = reading.value {
                                Text(value)
                                    .font(.system(.footnote, design: .monospaced))
                                    .textSelection(.enabled)
                                    .foregroundStyle(.secondary)
                            }
                            if let note = reading.note {
                                Text(note).font(.caption).foregroundStyle(.secondary)
                            }
                        }
                        .accessibilityElement(children: .combine)
                        .accessibilityIdentifier(reading.id)
                    }
                }
            }
        } else {
            Section {
                empty(icon: "doc.text.magnifyingglass", title: "还没有采集报告",
                      subtitle: "开始采集后，这里会显示字段值、读取状态和不可用的原因。")
            }
        }
    }

    @ViewBuilder
    private var findingContent: some View {
        if let environment {
            Section {
                VStack(alignment: .leading, spacing: 6) {
                    Text("检查完成").font(.headline).accessibilityIdentifier("checkSummary")
                    Text("未发现只表示本次检查没有看到迹象。点击结果可展开每一项证据。")
                        .font(.footnote).foregroundStyle(.secondary)
                }
            }
            Section("环境与证据") {
                ForEach(environment.findings) { finding in
                    DisclosureGroup {
                        ForEach(finding.evidence) { evidence in
                            VStack(alignment: .leading, spacing: 5) {
                                HStack(alignment: .firstTextBaseline) {
                                    Text(evidence.label).font(.subheadline.weight(.medium))
                                    Spacer(minLength: 4)
                                    status(evidence.state)
                                }
                                Text(evidence.detail).font(.footnote).foregroundStyle(.secondary)
                                    .textSelection(.enabled)
                            }
                            .padding(.vertical, 6)
                            .accessibilityIdentifier(evidence.id)
                        }
                    } label: {
                        HStack {
                            Text(finding.title).font(.subheadline.weight(.semibold))
                            Spacer(minLength: 8)
                            status(finding.state)
                        }
                    }
                    .accessibilityIdentifier("finding." + finding.id)
                }
            }
        } else {
            Section {
                empty(icon: "checkmark.shield", title: "还没有环境判断",
                      subtitle: "点击判断，检查越狱、Frida、调试器、动态库与模拟器迹象。")
            }
        }
    }

    private func status(_ state: FindingState) -> some View {
        let color: Color
        switch state {
        case .detected: color = .red
        case .suspicious: color = .orange
        case .notObserved: color = .teal
        case .inconclusive, .notApplicable: color = .secondary
        }
        return Text(state.title)
            .font(.caption.weight(.semibold))
            .foregroundStyle(color)
            .fixedSize()
    }

    private func empty(icon: String, title: String, subtitle: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Image(systemName: icon).font(.title2).foregroundStyle(.teal).accessibilityHidden(true)
            Text(title).font(.headline)
            Text(subtitle).font(.footnote).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.vertical, 12)
    }

    private func startCollection(requestLocationPermission: Bool = false) {
        guard !collecting else { return }
        panel = .readings
        collecting = true
        Task {
            device = await DeviceCollector.collect(requestLocationPermission: requestLocationPermission)
            collecting = false
        }
    }

    private func startCheck() {
        guard !checking else { return }
        panel = .findings
        checking = true
        Task {
            environment = await Task.detached(priority: .userInitiated) { EnvironmentDetector.check() }.value
            checking = false
        }
    }

    private func showJSON() {
        do {
            if panel == .readings, let device {
                rawReport = RawReport(title: panel.rawValue, text: try ReportJSON.encode(device))
            } else if panel == .findings, let environment {
                rawReport = RawReport(title: panel.rawValue, text: try ReportJSON.encode(environment))
            }
        } catch { jsonError = true }
    }

    private func exportReport(_ report: DeviceReport) {
        do {
            reportFile = try ReportFile(report: report)
        } catch {
            exportError = error.localizedDescription
            showExportError = true
        }
    }
}

private struct ReportShareView: UIViewControllerRepresentable {
    let file: ReportFile
    @Environment(\.dismiss) private var dismiss

    func makeUIViewController(context: Context) -> UIActivityViewController {
        let controller = UIActivityViewController(activityItems: [file.url], applicationActivities: nil)
        controller.completionWithItemsHandler = { [file] _, _, _, _ in
            withExtendedLifetime(file) { dismiss() }
        }
        return controller
    }

    func updateUIViewController(_ controller: UIActivityViewController, context: Context) {}
}

private struct RawReport: Identifiable {
    let id = UUID()
    let title: String
    let text: String
}

private struct RawReportView: View {
    let report: RawReport
    @Environment(\.dismiss) private var dismiss
    @State private var copied = false

    var body: some View {
        NavigationStack {
            ScrollView {
                Text(report.text)
                    .font(.system(.caption, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding()
                    .accessibilityIdentifier("reportJSON")
            }
            .navigationTitle(report.title + " JSON")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("关闭") { dismiss() }
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button(copied ? "已复制" : "复制") {
                        UIPasteboard.general.setItems([["public.utf8-plain-text": report.text]], options: [
                            .localOnly: true, .expirationDate: Date().addingTimeInterval(300)
                        ])
                        copied = true
                    }
                }
            }
        }
    }
}
