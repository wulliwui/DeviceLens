import Foundation

enum SampleValue: Encodable, Sendable {
    case text(String)
    case integer(Int64)
    case decimal(Double)
    case array([SampleValue])

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .text(let value): try container.encode(value)
        case .integer(let value): try container.encode(value)
        case .decimal(let value): try container.encode(value)
        case .array(let values): try container.encode(values)
        }
    }

    var display: String {
        switch self {
        case .text(let value): return value.isEmpty ? "\"\"" : value
        case .integer(let value): return String(value)
        case .decimal(let value): return String(value)
        case .array: return (try? ReportJSON.encode(self)) ?? "[]"
        }
    }
}

struct SampleField: Encodable, Sendable {
    let id: Int
    let label: String
    let value: SampleValue?
    let type: UInt8?
    let note: String?
    let partial: Bool?

    init(_ id: Int, _ label: String, _ value: SampleValue?, type: UInt8? = nil, note: String? = nil, partial: Bool? = nil) {
        self.id = id
        self.label = label
        self.value = value
        self.type = type
        self.note = note
        self.partial = partial
    }

    func reading(prefix: String) -> Reading {
        Reading("\(prefix).\(id)", "\(id) · \(label)", value?.display, note: note)
    }
}

struct SampleProfiles: Encodable, Sendable {
    let sample = "DeviceLens local diagnostics"
    let turing: [SampleField]
    let tongdun: [SampleField]
    let location: SampleLocationResult
    let tongdunProfileBase64: Data?

    init(turing: [SampleField], tongdun: [SampleField], location: SampleLocationResult) {
        self.turing = turing
        self.tongdun = tongdun
        self.location = location
        tongdunProfileBase64 = TongdunProfile.pack(tongdun.filter { $0.partial != true })
    }

    var groups: [ReadingGroup] {
        [
            ReadingGroup(id: "turing", title: "图灵盾样本字段", readings: turing.map { $0.reading(prefix: "turing") }),
            ReadingGroup(id: "tongdun", title: "同盾样本字段", readings: tongdun.map { $0.reading(prefix: "tongdun") }),
        ]
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(sample, forKey: .sample)
        try container.encode(turing, forKey: .turing)
        try container.encode(tongdun, forKey: .tongdun)
        try container.encode(location, forKey: .location)
        // The confirmed common tag in the collector's [tag, value] pair is an empty CFString.
        let pairs = turing.compactMap { field -> (String, [SampleValue])? in
            guard let value = field.value, field.partial != true else { return nil }
            return (String(field.id), [.text(""), value])
        }
        try container.encode(Dictionary(uniqueKeysWithValues: pairs), forKey: .turingFeaturePairs)
        try container.encodeIfPresent(tongdunProfileBase64, forKey: .tongdunProfileBase64)
    }

    private enum CodingKeys: String, CodingKey {
        case sample, turing, tongdun, location, turingFeaturePairs, tongdunProfileBase64
    }
}

enum TongdunProfile {
    static func pack(_ fields: [SampleField], xorKeys: [UInt8]? = nil) -> Data? {
        let entries = fields.compactMap { field -> (UInt8, UInt8, Data)? in
            guard let id = UInt8(exactly: field.id), let type = field.type, let value = field.value else { return nil }
            switch (type, value) {
            case (1, .integer(let value)):
                guard let byte = UInt8(exactly: value) else { return nil }
                return (id, type, Data([byte]))
            case (2, .text(let text)): return (id, type, Data(text.utf8.prefix { $0 != 0 }))
            case (3, .integer(let value)):
                guard let integer = Int32(exactly: value) else { return nil }
                return (id, type, littleEndian(integer))
            case (4, .integer(let value)), (5, .integer(let value)):
                return (id, type, littleEndian(value))
            default: return nil
            }
        }
        guard entries.count <= Int(UInt8.max) + 1, entries.count == fields.filter({ $0.value != nil }).count,
              Set(entries.map { $0.0 }).count == entries.count else { return nil }
        guard xorKeys == nil || xorKeys?.count == entries.count else { return nil }

        let keyWordCount = (entries.count + 3) / 4
        let keys = xorKeys ?? Array((0..<keyWordCount)
            .flatMap { _ in littleEndian(arc4random() &+ 0x55555555) }
            .prefix(entries.count))
        var records = Data()
        var values = Data()
        for (index, entry) in entries.enumerated() {
            guard let offset = UInt16(exactly: values.count) else { return nil }
            records.append(littleEndian(offset))
            records.append(contentsOf: [entry.0, entry.1])
            values.append(contentsOf: entry.2.map { $0 ^ keys[index] })
        }
        let body = Data(keys) + records + values
        guard let bodyLength = UInt32(exactly: body.count) else { return nil }
        return littleEndian(UInt32(0xDABCEFAC)) + littleEndian(UInt32(entries.count))
            + littleEndian(bodyLength) + littleEndian(murmur2(body)) + body
    }

    private static func littleEndian<T: FixedWidthInteger>(_ value: T) -> Data {
        withUnsafeBytes(of: value.littleEndian) { Data($0) }
    }

    private static func murmur2(_ data: Data) -> UInt32 {
        let m: UInt32 = 0x5bd1e995
        let bytes = Array(data)
        var hash = UInt32(bytes.count)
        let end = bytes.count & ~3
        for index in stride(from: 0, to: end, by: 4) {
            var k = UInt32(bytes[index]) | (UInt32(bytes[index + 1]) << 8)
            k |= (UInt32(bytes[index + 2]) << 16) | (UInt32(bytes[index + 3]) << 24)
            k = k &* m
            k = (k ^ (k >> 24)) &* m
            hash = (hash &* m) ^ k
        }
        if end < bytes.count {
            for index in end..<bytes.count { hash ^= UInt32(bytes[index]) << (8 * (index - end)) }
            hash = hash &* m
        }
        hash = (hash ^ (hash >> 13)) &* m
        return hash ^ (hash >> 15)
    }
}
