import CryptoKit
import Darwin
import Foundation
import MachO
import SystemConfiguration
import UIKit

struct LocalSources: Sendable {
    let machine = DeviceCollector.sysctlString("hw.machine")
    let hardwareModel = DeviceCollector.sysctlString("hw.model")
    let osBuild = DeviceCollector.sysctlString("kern.osversion")
    let bootSession = DeviceCollector.sysctlString("kern.bootsessionuuid")
    let boot = DeviceCollector.bootTimeval()
    let traced = EnvironmentDetector.processTraced()
    let interfaces = SampleInterface.all()
    private let images = EnvironmentDetector.imageNames()
    let imageCount = _dyld_image_count()
    let codeSignature = SampleSignature.read(Bundle.main.executableURL)

    var kernel: String? {
        var info = utsname()
        guard uname(&info) == 0 else { return nil }
        return withUnsafeBytes(of: &info.version) { String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self) }
    }

    private static let turingMemory: Int64 = {
        let host = mach_host_self()
        defer { mach_port_deallocate(mach_task_self_, host) }
        var pageSize: vm_size_t = 0
        guard host_page_size(host, &pageSize) == KERN_SUCCESS else { return 0 }
        var info = vm_statistics_data_t()
        let capacity = MemoryLayout<vm_statistics_data_t>.size / MemoryLayout<integer_t>.size
        var count = mach_msg_type_number_t(capacity)
        let status = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: capacity) {
                host_statistics(host, HOST_VM_INFO, $0, &count)
            }
        }
        guard status == KERN_SUCCESS else { return 0 }
        let pages = info.free_count &+ info.active_count &+ info.inactive_count &+ info.wire_count
        return Int64(pageSize) * Int64(pages)
    }()
    var hostMemory: Int64 { Self.turingMemory }

    private let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).last
    private let disk: [FileAttributeKey: NSNumber]
    init() {
        let path = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).last?.path
        disk = path.flatMap { try? FileManager.default.attributesOfFileSystem(forPath: $0) as? [FileAttributeKey: NSNumber] } ?? [:]
    }
    var diskFree: Int64? { disk[.systemFreeSize]?.int64Value }
    var diskTotal: Int64? { disk[.systemSize]?.int64Value }

    var turingReachability: Int64 {
        guard let target = SCNetworkReachabilityCreateWithName(nil, "8.8.8.8") else { return 0 }
        var flags = SCNetworkReachabilityFlags()
        guard SCNetworkReachabilityGetFlags(target, &flags) else { return 0 }
        guard flags.contains(.reachable) else { return 1 }
        if flags.contains(.isWWAN) { return 3 }
        if !flags.contains(.connectionRequired) { return 2 }
        let automatic = flags.contains(.connectionOnDemand) || flags.contains(.connectionOnTraffic)
        return automatic && !flags.contains(.interventionRequired) ? 2 : 1
    }

    private static func mibText(_ domain: Int32, _ item: Int32) -> String? {
        var mib = [domain, item]
        var count = 0
        guard sysctl(&mib, 2, nil, &count, nil, 0) == 0, count > 0, count < 16_384 else { return nil }
        var data = [UInt8](repeating: 0, count: count)
        let status = data.withUnsafeMutableBytes { sysctl(&mib, 2, $0.baseAddress, &count, nil, 0) }
        guard status == 0 else { return nil }
        return String(bytes: data.prefix(count).prefix { $0 != 0 }, encoding: .utf8)
    }

    private static func mibNumber<T: FixedWidthInteger>(_ domain: Int32, _ item: Int32, as: T.Type) -> T? {
        var mib = [domain, item]
        var value: T = 0
        var size = MemoryLayout<T>.size
        let status = withUnsafeMutableBytes(of: &value) { sysctl(&mib, 2, $0.baseAddress, &size, nil, 0) }
        return status == 0 ? value : nil
    }

    private static let cachedHardware = {
        let text = [1, 2, 27, 26, 12].map { mibText(CTL_HW, $0) }
        let integers = [3, 17, 18, 20, 22].map { mibNumber(CTL_HW, $0, as: Int32.self).map(String.init) }
        let architecture = mibNumber(CTL_HW, 105, as: UInt64.self).map { String(format: "0x%08llX", $0) }
        let subtype = mibNumber(CTL_HW, 106, as: Int32.self).map(String.init)
        return text + integers + [architecture, subtype]
    }()

    var turingHardware: [SampleValue] {
        let keys: [Int32] = [14, 15, 4, 24, 5, 6]
        let numbers = keys.map { key -> String? in
            if key == 4 { return Self.mibNumber(CTL_HW, key, as: Int32.self).map(String.init) }
            return Self.mibNumber(CTL_HW, key, as: UInt64.self).map(String.init)
        }
        return (Self.cachedHardware + numbers).map { .text($0 ?? "nil") }
    }

    private static let cachedKernel = [
        mibText(CTL_KERN, 1), mibText(CTL_KERN, 2),
        mibNumber(CTL_KERN, 3, as: Int32.self).map(String.init), mibText(CTL_KERN, 65),
    ]

    var turingKernel: [SampleValue] {
        let name = Self.mibText(CTL_KERN, 10) ?? ""
        let hash = SHA256.hash(data: Data(name.utf8)).map { String(format: "%02X", $0) }.joined()
        let hostID = Self.mibNumber(CTL_KERN, 11, as: Int32.self).map(String.init)
        return (Self.cachedKernel + [hash, hostID]).map { .text($0 ?? "nil") }
    }

    var turingMount: [SampleValue] {
        var info = statfs()
        guard statfs("/System", &info) == 0 else { return [] }
        return withUnsafeBytes(of: &info) { data in
            let source = String(decoding: data.dropFirst(1112).prefix { $0 != 0 }, as: UTF8.self)
            return [.text(source)] + [48, 52, 60, 68, 64].map {
                .text(String(format: "%08X", data.loadUnaligned(fromByteOffset: $0, as: UInt32.self)))
            }
        }
    }

    var memoryStatistics: String? {
        let host = mach_host_self()
        defer { mach_port_deallocate(mach_task_self_, host) }
        var pageSize: vm_size_t = 0
        guard host_page_size(host, &pageSize) == KERN_SUCCESS else { return nil }
        var info = vm_statistics64_data_t()
        let capacity = MemoryLayout<vm_statistics64_data_t>.stride / MemoryLayout<integer_t>.size
        var count = mach_msg_type_number_t(capacity)
        let status = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: capacity) {
                host_statistics64(host, HOST_VM_INFO64, $0, &count)
            }
        }
        guard status == KERN_SUCCESS, let hardware = Self.mibNumber(CTL_HW, 24, as: UInt64.self) else { return nil }
        let pages = [info.free_count, info.active_count, info.inactive_count, info.wire_count,
                     info.speculative_count, info.compressor_page_count].reduce(UInt64(0)) { $0 + UInt64($1) }
        return "\(pages * UInt64(pageSize))|\(hardware)"
    }

    @MainActor
    func extendedProfile(screens: [UIScreen]) -> String? {
        let process = ProcessInfo.processInfo
        let locale = Locale.current as NSLocale
        let bundle = Bundle.main
        let capture = screens.map { screen in
            "\(screen.mirrored == nil ? 0 : 1),\(screen.isCaptured ? 1 : 0)"
        }.joined(separator: "|")
        var entries: [String: String] = [
            "pi": "\(process.processorCount)|\(process.physicalMemory)|\(process.operatingSystemVersionString)|\(process.isiOSAppOnMac ? 1 : 0)|\(process.isMacCatalystApp ? 1 : 0)",
            "nsc": String(Thread.callStackSymbols.count),
            "sci": capture,
        ]
        entries["adn"] = bundle.infoDictionary?["CFBundleDisplayName"] as? String
        entries["ndn"] = DeviceCollector.sysctlString("kern.hostname")
        let collator = locale.object(forKey: .collatorIdentifier) as? String
        let currency = locale.object(forKey: .currencyCode) as? String
        entries["li"] = "\(collator ?? "(null)")|\(currency ?? "(null)")"
        if let path = bundle.executablePath,
           let attributes = try? FileManager.default.attributesOfItem(atPath: path),
           let creation = attributes[.creationDate] as? Date,
           let modification = attributes[.modificationDate] as? Date {
            entries["iut"] = String(format: "%f|%f", creation.timeIntervalSince1970, modification.timeIntervalSince1970)
        }
        entries["ipna"] = interfaces.last { $0.name == "anpi0" && $0.family == AF_INET6 }?.address
        return SampleCollector.compactJSON(entries)
    }

    var documentsCreated: String? {
        guard let documents, let values = try? documents.resourceValues(forKeys: [.creationDateKey]),
              let date = values.creationDate else { return nil }
        return String(format: "%lf", date.timeIntervalSince1970)
    }

    var resourceHash: String? {
        let url = Bundle.main.bundleURL.appendingPathComponent("_CodeSignature/CodeResources")
        guard let contents = try? Data(contentsOf: url) else { return nil }
        return SHA256.hash(data: contents).map { String(format: "%02x", $0) }.joined()
    }

    var rootCapacity: String? {
        var mount = statfs()
        guard statfs("/", &mount) == 0 else { return nil }
        let block = UInt64(mount.f_bsize)
        return "\(block * mount.f_blocks)|\(block * mount.f_bavail)"
    }

    var systemVersion: String? {
        let url = URL(fileURLWithPath: "/System/Library/CoreServices/SystemVersion.plist")
        guard let data = try? Data(contentsOf: url),
              let values = (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: Any]
        else { return nil }
        let keys = ["ProductName", "BuildID", "ProductVersion", "ProductBuildVersion", "", "ReleaseType", "ProductCopyright"]
        return keys.map { key in key.isEmpty ? "" : values[key].map { String(describing: $0) } ?? "(null)" }
            .joined(separator: "|")
    }

    var dns: String? {
        var output = [CChar](repeating: 0, count: 128)
        return sample_dns_servers(&output, output.count) == 0 ? String(cString: output) : nil
    }

    var turingInterfaces: [[SampleValue]] {
        var groups = [[SampleValue]](repeating: [], count: 3)
        for item in interfaces {
            let group: Int
            if item.name.hasPrefix("en") { group = 1 }
            else if item.name.hasPrefix("pdp_ip") { group = 0 }
            else if item.name.hasPrefix("utun") { group = 2 }
            else { continue }
            guard item.address != "0.0.0.0", item.address != "::", !item.address.hasPrefix("fe80::") else { continue }
            groups[group].append(.array([.text(item.name), .text(item.address)]))
        }
        return groups
    }

    var interfaceAddresses: String? {
        guard !interfaces.isEmpty else { return nil }
        return Set(interfaces.map(\.address)).joined(separator: ",")
    }

    var knownApps: String? {
        #if targetEnvironment(simulator)
        return nil
        #else
        let names = [
            "AWZ", "NZT", "igvx", "TouchElf", "TouchSprite",
            "WujiVPN", "RST", "Forge9", "Forge", "GFaker",
            "hdfakerset", "Pranava", "iG", "HiddenApi", "Xgen",
            "BirdFaker9", "VPNMasterPro", "GuizmOVPN", "OTRLocation", "rwx",
            "FakeMyLocation", "anylocation", "location360pro", "xGPS", "007gaiji",
            "ALS", "AXJ", "serialudid", "BirdFaker", "zorro",
            "YOY", "ASA", "DDYMarket", "MobileAnjian", "AutoTouch",
            "Flybird", "VBox", "KyyaiStore"
        ]
        var bits: UInt64 = 0
        for (index, name) in names.enumerated() {
            let path = "/Applications/\(name).app"
            if FileManager.default.fileExists(atPath: path) {
                bits |= 1 << index
            } else if let file = fopen(path, "r") {
                fclose(file)
                bits |= 1 << index
            } else if let directory = opendir(path) {
                closedir(directory)
                bits |= 1 << index
            }
        }
        return String(bits, radix: 16)
        #endif
    }

    var provision: [String: Any]? {
        let path = Bundle.main.bundleURL.appendingPathComponent("embedded.mobileprovision")
        guard let data = try? Data(contentsOf: path),
              let start = data.range(of: Data("<?xml".utf8))?.lowerBound,
              let end = data.range(of: Data("</plist>".utf8), in: start..<data.endIndex)?.upperBound else { return nil }
        return (try? PropertyListSerialization.propertyList(from: data[start..<end], format: nil)) as? [String: Any]
    }

    var tongdunPathMask: Int64? {
        #if targetEnvironment(simulator)
        return nil
        #else
        let paths = [
            "/bin/bash", "/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist", "/usr/libexec/cydia/startup",
            "/etc/apt", "/Applications/Cydia.app", "/User/Applications/",
            "/Library/MobileSubstrate/MobileSubstrate.dylib", "/private/var/stash", "/private/var/lib/apt",
            "/var/cache/apt", "/Library/Frameworks/CydiaSubstrate.framework", "/usr/libexec/cydia",
            "/Applications/SubstituteSettings.app", "/etc/apt/sources.list.d/saurik.list", "/private/var/db/stash",
            "/var/jb", "/var/bin", "/Applications/Sileo.app",
            "/Applications/unc0ver.app", "/Applications/Zebra.app", "/private/etc/apt/preferences.d/checkra1n",
            "/Library/LaunchDaemons/com.tigisoftware.filza.helper.plist", "/Library/LaunchDaemons/com.openssh.sshd.plist", "/private/var/lib/cydia",
            "/var/lib/apt", "/var/lib/cydia", "/var/lib/dpkg/info",
            "/var/log/syslog", "/etc/apt/sources.list.d", "/etc/ssh/sshd_config",
            "/private/etc/apt", "/usr/bin/cycript", "/usr/bin/DHPDaemon",
            "/usr/bin/ssh", "/usr/bin/sshd", "/usr/sbin/sshd",
            "/usr/lib/libcycript.dylib", "/usr/libexec/sftp-server", "/usr/local/bin/cycript",
            "/var/mobile/Library/Caches/com.saurik.Cydia/sources.list", "/var/mobile/Library/Saved Application State/com.opa334.Dopamine.savedState", "/var/mobile/Library/HTTPStorages/com.opa334.Dopamine",
            "/var/mobile/Library/Caches/com.opa334.Dopamine", "/var/mobile/Library/SplashBoard/Snapshots/com.opa334.Dopamine", "/var/mobile/Library/Caches/org.coolstar.SileoStore",
            "/var/mobile/Library/SplashBoard/Snapshots/org.coolstar.SileoStore", "/var/mobile/Library/Saved Application State/org.coolstar.SileoStore.savedState", "/var/mobile/Library/Application Support/Containers/org.coolstar.SileoStore",
            "/var/mobile/Library/SplashBoard/Snapshots/xyz.willy.Zebra", "/var/mobile/Library/Saved Application State/xyz.willy.Zebra.savedState", "/Library/dpkg/info/com.ex.substitute.list",
            "/usr/bin/cynject", "/usr/bin/sinject", "/usr/libexec/sinject-vpa",
            "/etc/rc.d/substitute-launcher", "/var/jb/etc/rc.d/ellekit-loader", "/var/mobile/Library/HTTPStorages/org.coolstar.SileoStore",
            "/var/mobile/Library/SplashBoard/Snapshots/org.coolstar.SileoStore", "var/root/Library/Preferences/com.opa334.Dopamine.plist", "/var/mobile/Library/Preferences/com.opa334.Dopamine.plist",
            "/var/root/Library/Preferences/com.xina.jailbreak.plist", "/var/mobile/Library/Preferences/com.xina.jailbreak.plist"
        ]
        var mask: UInt64 = 0
        for (index, path) in paths.enumerated() {
            var metadata = stat()
            if FileManager.default.fileExists(atPath: path) || stat(path, &metadata) == 0 || lstat(path, &metadata) == 0 {
                mask |= 1 << (index < 35 ? index : index + 1)
            }
        }
        return Int64(bitPattern: mask)
        #endif
    }

    var configurationProfilesCreated: String? {
        let path = "/private/var/mobile/Library/UserConfigurationProfiles/PublicInfo/MCMeta.plist"
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: path),
              let creation = attributes[.creationDate] as? Date else { return nil }
        return String(format: "%f", creation.timeIntervalSince1970)
    }

    var cellTransmittedBytes: Int64? {
        var bytes: UInt64 = 0
        guard sample_cell_transmitted_bytes(&bytes) == 0 else { return nil }
        return Int64(bitPattern: bytes)
    }

    var turingRoot: Int64? {
        #if targetEnvironment(simulator)
        return nil
        #else
        let manager = FileManager.default
        let paths: [(String, Int64)] = [
            ("/private/var/lib/apt/", 1), ("/var/jb/var/lib/apt/", 0x10000001),
            ("/Applications/Cydia.app", 2),
            ("/Library/MobileSubstrate/MobileSubstrate.dylib", 4),
            ("/var/jb/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate", 0x10000004),
            ("/etc/apt", 8), ("/var/jb/etc/apt", 0x10000008),
            ("/Applications/Sileo.app", 0x20), ("/var/jb/Applications/Sileo.app", 0x10000020),
            ("/usr/lib/libsubstrate.dylib", 0x40), ("/var/jb/usr/lib/libsubstrate.dylib", 0x10000040),
            ("/var/jb/Applications", 0x10000100), ("/usr/lib/substitute-inserter.dylib", 0x200),
            ("/usr/lib/libsubstitute.dylib", 0x400), ("/usr/bin/ssh", 0x800), ("/var/jb/usr/bin/ssh", 0x10000800),
        ]
        let attributes = try? manager.attributesOfItem(atPath: "/Applications")
        let isLink = (attributes?[.type] as? FileAttributeType) == .typeSymbolicLink
        return paths.reduce(isLink ? 0x100 : 0) { mask, entry in
            manager.fileExists(atPath: entry.0) ? mask | entry.1 : mask
        }
        #endif
    }

    var slide: String {
        var candidate = 0
        var votes = 0
        for index in 0..<imageCount {
            let current = _dyld_get_image_vmaddr_slide(index)
            if votes == 0 { candidate = current }
            votes += current == candidate ? 1 : -1
        }
        return String(candidate)
    }

    var cryptID: UInt32? {
        guard let header = _dyld_get_image_header(0), header.pointee.magic == MH_MAGIC_64 else { return nil }
        let base = UnsafeRawPointer(header)
        let commands = Int(header.pointee.sizeofcmds)
        let first = base.advanced(by: MemoryLayout<mach_header_64>.size)
        var offset = 0
        for _ in 0..<header.pointee.ncmds {
            guard offset + MemoryLayout<load_command>.size <= commands else { return nil }
            let cursor = first.advanced(by: offset)
            let load = cursor.loadUnaligned(as: load_command.self)
            guard load.cmdsize >= MemoryLayout<load_command>.size, offset + Int(load.cmdsize) <= commands else { return nil }
            if load.cmd == LC_ENCRYPTION_INFO_64 && load.cmdsize >= MemoryLayout<encryption_info_command_64>.size {
                return cursor.loadUnaligned(as: encryption_info_command_64.self).cryptid
            }
            offset += Int(load.cmdsize)
        }
        return 0
    }

    var simulatorMask: Int {
        images.reduce(0) { mask, path in
            mask | (path.hasSuffix("usr/lib/dyld_sim") ? 1 : 0)
                | (path.contains("Library/Developer/CoreSimulator") ? 2 : 0)
        }
    }

    var macMask: Int {
        let executable = Bundle.main.executableURL?.lastPathComponent ?? ""
        return images.reduce(0) { mask, path in
            mask | (path.contains("System/iOSSupport") ? 1 : 0)
                | (path.hasSuffix("Wrapper/\(executable).app/\(executable)") ? 2 : 0)
        }
    }

    var hookSymbols: String? {
        let handle = UnsafeMutableRawPointer(bitPattern: -2)
        let groups = [
            ("Dobby", ["DobbyHook", "DobbySymbolResolver"]),
            ("CydiaSubstrate", ["MSHookMessageEx"]),
        ]
        let names = groups.compactMap { group in
            group.1.contains { dlsym(handle, $0) != nil } ? group.0 : nil
        }
        return names.isEmpty ? nil : names.joined(separator: "|")
    }

    var volumeUUID: String? {
        (try? URL(fileURLWithPath: "/").resourceValues(forKeys: [.volumeUUIDStringKey]))?.volumeUUIDString
    }
}

struct SampleInterface: Sendable {
    let name: String
    let family: Int32
    let address: String
    let mask: String?

    static func all() -> [SampleInterface] {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let head else { return [] }
        defer { freeifaddrs(head) }
        var current: UnsafeMutablePointer<ifaddrs>? = head
        var result = [SampleInterface]()
        while let node = current {
            let item = node.pointee
            current = item.ifa_next
            guard let address = item.ifa_addr, let name = item.ifa_name, let text = addressString(address) else { continue }
            let mask: UnsafeMutablePointer<sockaddr>? = item.ifa_netmask
            let family = Int32(address.pointee.sa_family)
            result.append(SampleInterface(name: String(cString: name), family: family,
                                          address: text, mask: mask.flatMap { addressString($0, family: family) }))
        }
        return result
    }

    private static func addressString(_ address: UnsafePointer<sockaddr>, family override: Int32? = nil) -> String? {
        let family = override ?? Int32(address.pointee.sa_family)
        let offset: Int
        let length: Int
        switch family {
        case AF_INET:
            offset = 4
            length = MemoryLayout<in_addr>.size
        case AF_INET6:
            offset = 8
            length = MemoryLayout<in6_addr>.size
        default: return nil
        }
        let count = min(length, max(0, Int(address.pointee.sa_len) - offset))
        var bytes = [UInt8](repeating: 0, count: length)
        if count > 0 {
            bytes.withUnsafeMutableBytes {
                $0.copyBytes(from: UnsafeRawBufferPointer(start: UnsafeRawPointer(address) + offset, count: count))
            }
        }
        var text = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        let textSize = socklen_t(text.count)
        let result = bytes.withUnsafeBytes { inet_ntop(family, $0.baseAddress, &text, textSize) }
        return result.map { _ in String(cString: text) }
    }
}


struct SampleSignature: Sendable {
    let applicationID: String?

    static func read(_ url: URL?) -> SampleSignature? {
        guard let url, let file = try? Data(contentsOf: url, options: .mappedIfSafe),
              file.count >= MemoryLayout<mach_header_64>.size else { return nil }
        let header = file.withUnsafeBytes { $0.loadUnaligned(as: mach_header_64.self) }
        guard header.magic == MH_MAGIC_64 else { return nil }
        var offset = MemoryLayout<mach_header_64>.size
        let end = offset + Int(header.sizeofcmds)
        guard end <= file.count else { return nil }
        for _ in 0..<header.ncmds {
            guard offset + MemoryLayout<load_command>.size <= end else { return nil }
            let command = file.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: offset, as: load_command.self) }
            guard command.cmdsize >= MemoryLayout<load_command>.size,
                  offset + Int(command.cmdsize) <= end else { return nil }
            if command.cmd == LC_CODE_SIGNATURE, command.cmdsize >= MemoryLayout<linkedit_data_command>.size {
                let entry = file.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: offset, as: linkedit_data_command.self) }
                let start = Int(entry.dataoff)
                let stop = start + Int(entry.datasize)
                guard stop <= file.count else { return nil }
                return readSuperBlob(file[start..<stop])
            }
            offset += Int(command.cmdsize)
        }
        return nil
    }

    private static func readSuperBlob(_ blob: Data) -> SampleSignature? {
        func word(_ offset: Int) -> UInt32? {
            guard offset >= 0, offset <= blob.count - 4 else { return nil }
            return blob.withUnsafeBytes { UInt32(bigEndian: $0.loadUnaligned(fromByteOffset: offset, as: UInt32.self)) }
        }
        guard word(0) == 0xfade0cc0, let length = word(4).map(Int.init), length <= blob.count,
              length >= 12, let count = word(8).map(Int.init), count <= (length - 12) / 8 else { return nil }
        for entry in 0..<count {
            let index = 12 + entry * 8
            guard word(index) == 5, let offset = word(index + 4).map(Int.init), word(offset) == 0xfade7171,
                  let size = word(offset + 4).map(Int.init), size >= 8, offset + size <= length else { continue }
            let start = blob.startIndex + offset + 8
            let end = blob.startIndex + offset + size
            guard let values = (try? PropertyListSerialization.propertyList(from: blob[start..<end],
                format: nil)) as? [String: Any] else { continue }
            return SampleSignature(applicationID: values["application-identifier"] as? String)
        }
        return nil
    }
}
