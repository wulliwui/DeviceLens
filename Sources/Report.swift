import Foundation

enum ReadingStatus: String, Codable, Sendable {
    case collected, unavailable, notCollected

    var title: String {
        switch self {
        case .collected: return "已采集"
        case .unavailable: return "不可用"
        case .notCollected: return "未采集"
        }
    }
}

struct Reading: Codable, Identifiable, Sendable {
    let id: String
    let label: String
    let status: ReadingStatus
    let value: String?
    let note: String?

    init(_ id: String, _ label: String, _ value: String?, note: String? = nil,
         status: ReadingStatus? = nil) {
        self.id = id
        self.label = label
        self.value = value
        self.note = note ?? (value == nil ? "系统未返回可用值。" : nil)
        self.status = status ?? (value == nil ? .unavailable : .collected)
    }
}

struct ReadingGroup: Codable, Identifiable, Sendable {
    let id: String
    let title: String
    let readings: [Reading]
}

struct DeviceReport: Encodable, Sendable {
    let schemaVersion = 1
    let collectedAt: Date
    let groups: [ReadingGroup]
    let sampleProfiles: SampleProfiles

    var readings: [Reading] { groups.flatMap(\.readings) }
}

enum FindingState: String, Codable, Sendable {
    case detected, suspicious, notObserved, inconclusive, notApplicable

    var title: String {
        switch self {
        case .detected: return "检出迹象"
        case .suspicious: return "可疑"
        case .notObserved: return "未发现"
        case .inconclusive: return "无法判断"
        case .notApplicable: return "不适用"
        }
    }
}

struct Evidence: Codable, Identifiable, Sendable {
    let id: String
    let label: String
    let state: FindingState
    let detail: String
}

struct Finding: Codable, Identifiable, Sendable {
    let id: String
    let title: String
    let state: FindingState
    let evidence: [Evidence]

    init(_ id: String, _ title: String, _ evidence: [Evidence]) {
        self.id = id
        self.title = title
        self.evidence = evidence
        let states = Set(evidence.map(\.state))
        if states.contains(.detected) { state = .detected }
        else if states.contains(.suspicious) { state = .suspicious }
        else if states.contains(.inconclusive) || states.isEmpty { state = .inconclusive }
        else if states.contains(.notObserved) { state = .notObserved }
        else { state = .notApplicable }
    }
}

struct EnvironmentReport: Encodable, Sendable {
    let schemaVersion = 1
    let checkedAt: Date
    let findings: [Finding]
}

enum ReportJSON {
    static func encode<T: Encodable>(_ value: T) throws -> String {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        return String(decoding: try encoder.encode(value), as: UTF8.self)
    }
}
