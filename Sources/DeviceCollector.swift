import AdSupport
import AppTrackingTransparency
import CFNetwork
import CoreMotion
import CoreTelephony
import Darwin
import Foundation
import Network
import UIKit

enum DeviceCollector {
    @MainActor
    static func collect(requestLocationPermission: Bool = false) async -> DeviceReport {
        let started = Date()
        async let sample = SampleCollector.collect(started: started, requestLocationPermission: requestLocationPermission)
        async let network = networkGroup()
        async let system = Task.detached(priority: .userInitiated) { systemGroup() }.value
        let device = deviceGroup()
        let app = appGroup()
        let sensors = sensorGroup()
        let profiles = await sample
        return await DeviceReport(collectedAt: started, groups: [
            device, system, app, network, sensors,
            ReadingGroup(id: "location", title: "定位与来源", readings: profiles.location.readings),
            excludedGroup()
        ] + profiles.groups, sampleProfiles: profiles)
    }

    @MainActor
    private static func deviceGroup() -> ReadingGroup {
        let device = UIDevice.current
        let screen = UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .first { $0.activationState == .foregroundActive }?.screen ?? UIScreen.main
        let previous = device.isBatteryMonitoringEnabled
        device.isBatteryMonitoringEnabled = true
        defer { device.isBatteryMonitoringEnabled = previous }

        let batteryLevel = device.batteryLevel
        let batteryState: String?
        switch device.batteryState {
        case .unknown: batteryState = nil
        case .unplugged: batteryState = "未充电"
        case .charging: batteryState = "充电中"
        case .full: batteryState = "已充满"
        @unknown default: batteryState = nil
        }

        return ReadingGroup(id: "device", title: "设备与屏幕", readings: [
            Reading("device.model", "设备型号", device.model),
            Reading("device.localized_model", "本地化型号", device.localizedModel),
            Reading("device.name", "设备名称（系统返回值）", device.name,
                    note: "系统可能返回通用名称。"),
            Reading("device.os", "系统名称", device.systemName),
            Reading("device.os_version", "系统版本", device.systemVersion),
            Reading("device.idfv", "IDFV", device.identifierForVendor?.uuidString,
                    note: "仅供本机查看，作用域由 iOS 决定。"),
            Reading("screen.points", "屏幕逻辑尺寸", dimensions(screen.bounds.size)),
            Reading("screen.pixels", "屏幕像素尺寸", dimensions(screen.nativeBounds.size)),
            Reading("screen.scale", "屏幕倍率", String(describing: screen.scale)),
            Reading("screen.native_scale", "原生倍率", String(describing: screen.nativeScale)),
            Reading("screen.brightness", "亮度", percent(Double(screen.brightness))),
            Reading("screen.capture", "系统报告屏幕被捕获", flag(screen.isCaptured),
                    note: "录屏或镜像可能触发；截图不是持续捕获。"),
            Reading("power.level", "电量", batteryLevel >= 0 ? percent(Double(batteryLevel)) : nil),
            Reading("power.state", "充电状态", batteryState),
            Reading("power.low_power", "低电量模式", flag(ProcessInfo.processInfo.isLowPowerModeEnabled)),
        ])
    }

    private static func systemGroup() -> ReadingGroup {
        let process = ProcessInfo.processInfo
        let disk = try? FileManager.default.attributesOfFileSystem(forPath: NSHomeDirectory())
        let total = (disk?[.systemSize] as? NSNumber)?.uint64Value
        let free = (disk?[.systemFreeSize] as? NSNumber)?.uint64Value
        var kernel = utsname()
        let kernelVersion = uname(&kernel) == 0 ? withUnsafeBytes(of: &kernel.version) {
            String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self)
        } : nil
        let boot = bootTime()
        #if targetEnvironment(simulator)
        let model = process.environment["SIMULATOR_MODEL_IDENTIFIER"] ?? sysctlString("hw.machine")
        let modelNote = "模拟器型号；部分内核、内存和磁盘读数来自运行模拟器的 Mac。"
        #else
        let model = sysctlString("hw.machine")
        let modelNote: String? = nil
        #endif
        return ReadingGroup(id: "system", title: "硬件与系统", readings: [
            Reading("system.machine", "硬件机型标识", model, note: modelNote),
            Reading("system.hw_model", "硬件平台", sysctlString("hw.model")),
            Reading("system.os_build", "系统构建号", sysctlString("kern.osversion")),
            Reading("system.kernel", "内核版本", kernelVersion),
            Reading("system.boot_time", "系统启动时间", boot.map { ISO8601DateFormatter().string(from: $0) }),
            Reading("system.cpu_count", "逻辑核心数", String(process.processorCount)),
            Reading("system.cpu_active", "活跃核心数", String(process.activeProcessorCount)),
            Reading("system.cpu_arch", "应用架构", architecture),
            Reading("system.ram", "物理内存", bytes(process.physicalMemory)),
            Reading("system.storage_total", "文件系统总容量", total.map(bytes)),
            Reading("system.storage_free", "文件系统可用容量", free.map(bytes)),
            Reading("system.locale", "区域设置", Locale.current.identifier),
            Reading("system.region", "地区代码", Locale.current.region?.identifier),
            Reading("system.languages", "首选语言", Locale.preferredLanguages.joined(separator: ", ")),
            Reading("system.timezone", "时区", TimeZone.current.identifier),
            Reading("system.gmt_offset", "当前 UTC 偏移", "\(TimeZone.current.secondsFromGMT() / 60) 分钟"),
        ])
    }

    @MainActor
    private static func appGroup() -> ReadingGroup {
        let bundle = Bundle.main
        let status = ATTrackingManager.trackingAuthorizationStatus
        let idfa = status == .authorized ? ASIdentifierManager.shared().advertisingIdentifier.uuidString : nil
        let visibleIDFA = idfa == "00000000-0000-0000-0000-000000000000" ? nil : idfa
        let statusText: String
        switch status {
        case .authorized: statusText = "已授权"
        case .denied: statusText = "已拒绝"
        case .restricted: statusText = "受限制"
        case .notDetermined: statusText = "未请求"
        @unknown default: statusText = "未知状态"
        }
        return ReadingGroup(id: "app", title: "本应用与标识", readings: [
            Reading("app.bundle", "Bundle ID", bundle.bundleIdentifier),
            Reading("app.version", "应用版本", bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String),
            Reading("app.build", "构建版本", bundle.object(forInfoDictionaryKey: "CFBundleVersion") as? String),
            Reading("app.process", "进程名称", ProcessInfo.processInfo.processName),
            Reading("app.pid", "进程 ID", String(getpid())),
            Reading("app.att", "广告跟踪授权", statusText),
            Reading("app.idfa", "IDFA", visibleIDFA, note: "只读取已有授权，本应用不会弹出跟踪授权。"),
        ])
    }

    private static func networkGroup() async -> ReadingGroup {
        async let currentPath = pathReadings()
        let interfaces = interfaceReadings()
        let proxy = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any]
        let proxyMode = proxy.map { values in
            ["HTTPEnable", "HTTPSEnable", "SOCKSEnable", "ProxyAutoConfigEnable"]
                .filter { (values[$0] as? NSNumber)?.boolValue == true }
                .map { String($0.dropLast(6)) }
        }
        let endpoints = ["HTTP", "HTTPS", "SOCKS"].compactMap { key -> String? in
            guard (proxy?[key + "Enable"] as? NSNumber)?.boolValue == true,
                  let host = proxy?[key + "Proxy"] as? String else { return nil }
            let port = proxy?[key + "Port"] as? NSNumber
            return "\(key) \(host)" + (port.map { ":\($0)" } ?? "")
        }
        let telephony = CTTelephonyNetworkInfo()
        let carriers = (telephony.serviceSubscriberCellularProviders ?? [:]).values
        let carrierNames = Set(carriers.compactMap(\.carrierName)
            .filter { !$0.isEmpty && $0 != "--" }).sorted()
        let carrierCodes = Set(carriers.compactMap { carrier -> String? in
            guard let mcc = carrier.mobileCountryCode, let mnc = carrier.mobileNetworkCode,
                  !mcc.isEmpty, !mnc.isEmpty, mcc != "65535", mnc != "65535" else { return nil }
            return "\(mcc)/\(mnc)"
        }).sorted()
        let radio = Set((telephony.serviceCurrentRadioAccessTechnology ?? [:]).values).sorted()
        let tunnel = interfaces.values.map { $0.filter { value in
            ["utun", "tap", "tun", "ppp", "ipsec"].contains { value.hasPrefix($0) }
        } }

        let rows = await currentPath
        return ReadingGroup(id: "network", title: "网络与运营商", readings: rows + [
            Reading("network.interfaces", "活动接口、地址与掩码",
                    interfaces.values.map { $0.isEmpty ? "没有可见接口" : $0.joined(separator: "\n") },
                    note: interfaces.error),
            Reading("network.tunnel", "可见隧道接口",
                    tunnel.map { $0.isEmpty ? "未发现" : $0.joined(separator: "\n") },
                    note: "隧道接口只是一项迹象，不能单独确认正在使用 VPN。"),
            Reading("network.proxy_mode", "代理配置",
                    proxyMode.map { $0.isEmpty ? "未启用" : $0.joined(separator: ", ") }),
            Reading("network.proxy_address", "代理地址", joined(endpoints),
                    note: "代理未启用时通常无地址。"),
            Reading("network.proxy_pac", "PAC 地址", proxy?["ProxyAutoConfigURLString"] as? String),
            Reading("network.carrier", "运营商", joined(carrierNames),
                    note: "旧 CoreTelephony 接口；新系统可能返回空值或占位。"),
            Reading("network.carrier_codes", "运营商 MCC/MNC", joined(carrierCodes)),
            Reading("network.radio", "蜂窝制式", joined(radio)),
        ])
    }

    private static func pathReadings() async -> [Reading] {
        let monitor = NWPathMonitor()
        let queue = DispatchQueue(label: "org.devicelens.app.network-snapshot")
        let path: NWPath? = await withCheckedContinuation { continuation in
            let result = FirstPath(monitor, continuation)
            monitor.pathUpdateHandler = { result.finish($0) }
            queue.asyncAfter(deadline: .now() + .milliseconds(700)) { result.finish(nil) }
            monitor.start(queue: queue)
        }
        let names: [(NWInterface.InterfaceType, String)] = [
            (.wifi, "Wi-Fi"), (.cellular, "蜂窝"), (.wiredEthernet, "有线"), (.loopback, "回环"), (.other, "其他")
        ]
        let transports = path.map { path in names.filter { path.usesInterfaceType($0.0) }.map { $0.1 } }
        let state = path.map { path -> String in
            switch path.status {
            case .satisfied: return "可用"
            case .unsatisfied: return "不可用"
            case .requiresConnection: return "需要连接"
            @unknown default: return "未知状态"
            }
        }
        return [
            Reading("network.status", "网络路径状态", state, note: path == nil ? "系统没有及时返回路径。": nil),
            Reading("network.transport", "网络类型", transports.map { $0.isEmpty ? "无" : $0.joined(separator: ", ") }),
            Reading("network.dns", "路径支持 DNS", path.map { flag($0.supportsDNS) }),
            Reading("network.metered", "计费网络 / 低数据模式", path.map { "\(flag($0.isExpensive)) / \(flag($0.isConstrained))" }),
        ]
    }

    // All calls to finish are serialized on the monitor queue.
    private final class FirstPath: @unchecked Sendable {
        private let monitor: NWPathMonitor
        private var continuation: CheckedContinuation<NWPath?, Never>?

        init(_ monitor: NWPathMonitor, _ continuation: CheckedContinuation<NWPath?, Never>) {
            self.monitor = monitor
            self.continuation = continuation
        }

        func finish(_ path: NWPath?) {
            guard let continuation else { return }
            self.continuation = nil
            monitor.pathUpdateHandler = nil
            monitor.cancel()
            continuation.resume(returning: path)
        }
    }

    private static func interfaceReadings() -> (values: [String]?, error: String?) {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let head else {
            return (nil, "getifaddrs 未返回接口。")
        }
        defer { freeifaddrs(head) }
        var cursor: UnsafeMutablePointer<ifaddrs>? = head
        var result = Set<String>()
        while let node = cursor {
            let item = node.pointee
            cursor = item.ifa_next
            guard item.ifa_flags & UInt32(IFF_UP) != 0, let name = item.ifa_name,
                  let address = item.ifa_addr, let ip = numericHost(address) else { continue }
            let mask = item.ifa_netmask.flatMap { numericHost($0) }
            result.insert("\(String(cString: name)) · \(ip)" + (mask.map { " · \($0)" } ?? ""))
        }
        return (result.sorted(), nil)
    }

    private static func numericHost(_ address: UnsafePointer<sockaddr>) -> String? {
        let family = Int32(address.pointee.sa_family)
        guard family == AF_INET || family == AF_INET6 else { return nil }
        var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        let length = socklen_t(address.pointee.sa_len)
        guard length > 0,
              getnameinfo(address, length, &buffer, socklen_t(buffer.count), nil, 0, NI_NUMERICHOST) == 0
        else { return nil }
        return String(cString: buffer)
    }

    @MainActor
    private static func sensorGroup() -> ReadingGroup {
        let motion = CMMotionManager()
        return ReadingGroup(id: "sensors", title: "传感器能力", readings: [
            Reading("sensor.accelerometer", "加速度计", flag(motion.isAccelerometerAvailable)),
            Reading("sensor.gyro", "陀螺仪", flag(motion.isGyroAvailable)),
            Reading("sensor.magnetometer", "磁力计", flag(motion.isMagnetometerAvailable)),
            Reading("sensor.device_motion", "设备运动融合", flag(motion.isDeviceMotionAvailable)),
        ])
    }

    private static func excludedGroup() -> ReadingGroup {
        let omissions: [(String, String, String)] = [
            ("public_ip", "公网 IP", "通常由接收端观测；本应用没有公网请求。"),
            ("cell_tower", "基站标识", "定位结果不会提供基站标识。"),
            ("hardware_ids", "IMEI、IMSI、序列号、MAC", "普通 iOS 应用没有可靠的公开接口。"),
            ("app_inventory", "其他应用列表和账户", "iOS 沙盒不提供完整的其他应用或账户清单。"),
            ("behavior", "触摸轨迹与传感器原始序列", "仅检测传感器能力。"),
            ("vendor_state", "厂商私有标识和服务端配置", "不读取其他应用的 Keychain 或发送厂商请求。"),
        ]
        return ReadingGroup(id: "omissions", title: "未采集与原因", readings: omissions.map {
            Reading("omitted." + $0.0, $0.1, nil, note: $0.2, status: .notCollected)
        })
    }

    static func sysctlString(_ key: String) -> String? {
        var size = 0
        guard sysctlbyname(key, nil, &size, nil, 0) == 0, size > 0, size <= 16_384 else { return nil }
        var buffer = [UInt8](repeating: 0, count: size)
        let error = buffer.withUnsafeMutableBytes { sysctlbyname(key, $0.baseAddress, &size, nil, 0) }
        guard error == 0 else { return nil }
        return String(decoding: buffer.prefix { $0 != 0 }, as: UTF8.self)
    }

    private static func bootTime() -> Date? {
        bootTimeval().map { Date(timeIntervalSince1970: Double($0.tv_sec) + Double($0.tv_usec) / 1_000_000) }
    }

    static func bootTimeval() -> timeval? {
        var mib = [CTL_KERN, KERN_BOOTTIME]
        var time = timeval()
        var length = MemoryLayout<timeval>.size
        guard sysctl(&mib, UInt32(mib.count), &time, &length, nil, 0) == 0,
              length == MemoryLayout<timeval>.size, time.tv_sec > 0 else { return nil }
        return time
    }

    private static var architecture: String {
        #if arch(arm64)
        return "arm64"
        #elseif arch(x86_64)
        return "x86_64"
        #else
        return "其他"
        #endif
    }

    private static func dimensions(_ value: CGSize) -> String { "\(Int(value.width)) × \(Int(value.height))" }
    private static func percent(_ value: Double) -> String { "\(Int((value * 100).rounded()))%" }
    private static func flag(_ value: Bool) -> String { value ? "是" : "否" }
    private static func bytes(_ value: UInt64) -> String { "\(value) B" }
    private static func joined(_ values: [String]) -> String? { values.isEmpty ? nil : values.joined(separator: ", ") }
}
