import AdSupport
import AppTrackingTransparency
import AVFAudio
import CFNetwork
import CoreLocation
import CoreTelephony
import Darwin
import Foundation
import QuartzCore
import SystemConfiguration.CaptiveNetwork
import UIKit

enum SampleCollector {
    private static let wifiUnavailable = "需要当前 Wi-Fi、系统授权和签名的 Access WiFi Information 能力。"

    @MainActor
    static func collect(started: Date, requestLocationPermission: Bool) async -> SampleProfiles {
        async let local = Task.detached(priority: .userInitiated) { LocalSources() }.value
        let location = await SampleLocation().read(requestPermission: requestLocationPermission)
        let source = await local

        let device = UIDevice.current
        let screen = UIScreen.main
        let screenBounds = screen.bounds.size
        let nativeBounds = screen.nativeBounds.size
        let brightness = Double(screen.brightness)
        let batteryMonitoring = device.isBatteryMonitoringEnabled
        device.isBatteryMonitoringEnabled = true
        let batteryState = device.batteryState.rawValue
        let batteryLevel = device.batteryLevel
        device.isBatteryMonitoringEnabled = batteryMonitoring
        let captures = UIScreen.screens
        let telephony = CTTelephonyNetworkInfo()
        let primaryCarrier = telephony.subscriberCellularProvider
        let carriers = Array((telephony.serviceSubscriberCellularProviders ?? [:]).values)
        let idfa = ATTrackingManager.trackingAuthorizationStatus == .authorized
            ? ASIdentifierManager.shared().advertisingIdentifier.uuidString : nil
        let idfv = device.identifierForVendor?.uuidString
        let bundle = Bundle.main
        let proxy = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any] ?? [:]
        let scoped = proxy["__SCOPED__"] as? [String: Any]
        let http = (proxy["HTTPEnable"] as? NSNumber)?.intValue == 1
        let pac = (proxy["ProxyAutoConfigEnable"] as? NSNumber)?.intValue == 1
        let proxyAddress: String? = http
            ? "\(proxy["HTTPProxy"] ?? "(null)"):\(proxy["HTTPPort"] ?? "(null)")"
            : pac ? (proxy["ProxyAutoConfigURLString"] as? String ?? "") : ""
        let wifi = CNCopyCurrentNetworkInfo("en0" as CFString) as? [String: Any]
        let country = (Locale.current as NSLocale).object(forKey: .countryCode) as? String
        let languages = Locale.preferredLanguages
        let turing = [
            t(1001, "IDFA", uuid(idfa), note: "系统跟踪授权允许时读取。"),
            t(1002, "IDFV", uuid(idfv)),
            t(1003, "开机时间（秒）", .decimal(source.boot.map { Double($0.tv_sec) + Double($0.tv_usec) / 1_000_000 } ?? 0)),
            t(1004, "采集时间（秒）", .decimal(Date().timeIntervalSince1970)),
            t(1005, "文件系统空闲字节", .integer(source.diskFree ?? 0)),
            t(1006, "文件系统总字节", .integer(source.diskTotal ?? 0)),
            t(1007, "物理内存（字节）", .integer(source.hostMemory)),
            t(1008, "亮度", .decimal(brightness)),
            t(1009, "en 接口", .array(source.turingInterfaces[1])),
            t(1010, "pdp_ip 接口", .array(source.turingInterfaces[0])),
            t(1011, "utun 接口", .array(source.turingInterfaces[2])),
            t(1012, "样本占位", .text("")),
            t(1013, "Reachability 状态", .integer(source.turingReachability)),
            t(1014, "样本占位", .text("")),
            t(1015, "样本占位", .text("")),
            t(1016, "代理模式", .integer(http ? 1 : pac ? 2 : 0)),
            t(1017, "代理地址", proxyAddress.map(SampleValue.text)),
            t(1019, "越狱位图", source.turingRoot.map(SampleValue.integer), note: "真机路径检查。"),
            t(1020, "机型", .text(source.machine ?? source.hardwareModel ?? device.model)),
            t(1021, "系统版本", .text(device.systemVersion)),
            t(1022, "设备名称", .text(device.name)),
            t(1023, "运营商", .text(primaryCarrier?.carrierName ?? "")),
            t(1024, "国家或地区", .text(country ?? "")),
            t(1025, "运营商 MCC", .text(primaryCarrier?.mobileCountryCode ?? "")),
            t(1026, "运营商 MNC", .text(primaryCarrier?.mobileNetworkCode ?? "")),
            t(1027, "Bundle ID", bundle.bundleIdentifier.map(SampleValue.text)),
            t(1028, "首选语言", .array(languages.map(SampleValue.text))),
            t(1042, "样本空数组", .array([])),
            t(1051, "调试状态", source.traced.map { .integer($0 ? 1 : 0) }),
            t(1054, "主程序 CryptID", source.cryptID.map { .integer(Int64($0)) }),
            t(1055, "电池状态", .integer(Int64(batteryState))),
            t(1056, "硬件 sysctl 属性", .array(source.turingHardware)),
            t(1057, "内核 sysctl 属性", .array(source.turingKernel)),
            t(1060, "/System 挂载元数据", .array(source.turingMount)),
            t(1061, "录屏状态", .array([.text(screen.isCaptured ? "1" : "0")])),
            t(1063, "作用域代理 JSON", .text(scoped.flatMap(compactJSON) ?? "")),
        ]
        let appVersion = bundle.infoDictionary?["CFBundleShortVersionString"] as? String
        let bootUs = source.boot.map { Int64($0.tv_sec) * 1_000_000 + Int64($0.tv_usec) }
        let epoch = started.timeIntervalSince1970
        let ipv4Wifi = source.interfaces.last { $0.name == "en0" && $0.family == AF_INET }
        let ipv4VPN = source.interfaces.last { $0.family == AF_INET && vpn($0.name) }
        let radio = telephony.serviceCurrentRadioAccessTechnology?.values.first ?? telephony.currentRadioAccessTechnology
        let audio = AVAudioSession.sharedInstance()
        let audioState = audio.availableInputs?.isEmpty != false ? -1 : audio.currentRoute.inputs.contains {
            $0.selectedDataSource == nil
        } ? 1 : 0
        let pidFlags = (source.traced != false ? 1 : 0) | (getppid() != 1 ? 2 : 0) | (isatty(STDOUT_FILENO) != 0 ? 4 : 0)
        let scopeVPN = scoped.map { $0.keys.filter(vpn).joined(separator: ",") }
        let requestID = String(format: "%.0lf%d", epoch * 1_000, Int32(arc4random() % 899_999 + 100_000))
        let tongdun = [
            d(0, "SDK 默认版本", "5.2.5.2"),
            d(1, "平台", "iOS"),
            d(5, "IDFA", idfa, note: "在已有跟踪授权时读取。"),
            d(6, "IDFV", idfv),
            n(7, "采集时间（微秒）", Int64(epoch * 1_000_000), type: 4),
            n(8, "开机时间（微秒）", bootUs, type: 4),
            n(9, "文件系统总字节", source.diskTotal, type: 4),
            n(10, "文件系统空闲字节", source.diskFree, type: 4),
            n(11, "物理内存（字节）", Int64(ProcessInfo.processInfo.physicalMemory), type: 4),
            d(12, "蜂窝 IPv4", source.interfaces.last { $0.name == "pdp_ip0" && $0.family == AF_INET }?.address),
            d(13, "Wi-Fi IPv4", ipv4Wifi?.address),
            d(14, "Wi-Fi IPv4 掩码", ipv4Wifi?.mask),
            d(15, "VPN IPv4", ipv4VPN?.address),
            d(16, "VPN IPv4 掩码", ipv4VPN?.mask),
            d(18, "接口 IP 汇总", source.interfaceAddresses),
            d(23, "前十种首选语言", languages.prefix(10).joined(separator: ":")),
            d(24, "机型", source.machine),
            d(25, "系统版本", device.systemVersion),
            d(27, "运营商", carrierString(carriers, \.carrierName)),
            d(28, "运营商 MNC", carrierString(carriers, \.mobileNetworkCode)),
            d(29, "运营商 MCC", carrierString(carriers, \.mobileCountryCode)),
            d(30, "蜂窝接入制式", radio),
            d(31, "国家或地区", country),
            d(32, "包名及版本", bundle.bundleIdentifier.flatMap { id in appVersion.map { "\(id)_\($0)" } }),
            d(34, "样本占位", ""),
            d(35, "Wi-Fi SSID", wifi?["SSID"] as? String, note: wifi == nil ? wifiUnavailable : nil),
            d(36, "Wi-Fi BSSID", wifi?["BSSID"] as? String, note: wifi == nil ? wifiUnavailable : "当前接入点地址。"),
            d(37, "解析器 IPv4 DNS", source.dns, note: "res_9_ninit 返回的传统 IPv4 槽。"),
            d(38, "亮度百分比", String(format: "%.0lf", brightness * 100)),
            d(39, "电池状态及百分比", batteryInfo(state: batteryState, level: batteryLevel)),
            n(44, "定位授权状态", location.authorizationCode, type: 3),
            d(45, "内核版本", source.kernel),
            d(46, "时区", (NSTimeZone.local as NSTimeZone).name),
            d(47, "CodeResources SHA-256", source.resourceHash),
            n(48, "调试位图", Int64(pidFlags), type: 3),
            d(55, "镜像 slide 候选", source.slide),
            d(58, "内核构建", source.osBuild),
            n(59, "蜂窝已发送字节", source.cellTransmittedBytes, type: 4),
            d(60, "屏幕尺寸", String(format: "%.0f,%.0f", Double(screenBounds.width), Double(screenBounds.height))),
            d(63, "物理内存对照", source.memoryStatistics),
            d(64, "statfs 总量与可用量", source.rootCapacity),
            d(67, "单调运行时间", String(format: "%f", CACurrentMediaTime())),
            d(70, "Wi-Fi IPv6", source.interfaces.last { $0.name == "en0" && $0.family == AF_INET6 }?.address),
            d(76, "awdl0 IPv6", source.interfaces.last { $0.name == "awdl0" && $0.family == AF_INET6 }?.address),
            d(80, "已知工具位图", source.knownApps),
            d(84, "应用沙盒目录", NSHomeDirectory()),
            d(85, "描述文件团队名", source.provision?["TeamName"] as? String),
            d(86, "描述文件应用标识", (source.provision?["Entitlements"] as? [String: Any])?["application-identifier"] as? String),
            d(87, "主程序 CryptID", source.cryptID.map(String.init)),
            n(100, "采集器标记", 1, type: 3),
            n(101, "已加载镜像数", Int64(source.imageCount), type: 3),
            d(111, "配置描述文件元数据时间", source.configurationProfilesCreated),
            n(136, "越狱位图（路径部分）", source.tongdunPathMask, type: 4,
              note: "只含样本 62 条路径，附加分支未复现，本字段不进入二进制 profile。", partial: true),
            d(137, "完整屏幕几何", String(format: "%g|%g|%g|%g|%g|%g",
                Double(screenBounds.width), Double(screenBounds.height), Double(screen.scale),
                Double(screen.nativeScale), Double(nativeBounds.width), Double(nativeBounds.height))),
            d(138, "启动会话 UUID", source.bootSession),
            n(139, "录屏状态", captures.isEmpty ? -1 : captures.contains { $0.isCaptured } ? 1 : 0, type: 3),
            d(140, "运营商 ISO 地区", carrierString(carriers, \.isoCountryCode)),
            n(200, "采集耗时（微秒）", Int64(Date().timeIntervalSince(started) * 1_000_000), type: 4,
              note: "计时区间为本 App 的采集流程。", partial: true),
            d(201, "采集编号", requestID),
            d(205, "模拟器镜像位图", String(source.simulatorMask)),
            d(206, "iOS on Mac 镜像位图", String(source.macMask)),
            d(207, "SystemVersion.plist", source.systemVersion),
            d(208, "程序签名应用标识", source.codeSignature?.applicationID),
            d(215, "扩展采集 JSON（子集）", source.extendedProfile(screens: captures),
              note: "其余子键仍待复现，本字段不进入二进制 profile。", partial: true),
            d(216, "Documents 创建时间", source.documentsCreated),
            n(220, "音频输入状态", Int64(audioState), type: 3),
            d(222, "代理作用域 VPN 接口", scopeVPN),
            d(229, "Hook 框架符号", source.hookSymbols),
            d(230, "根卷 UUID", source.volumeUUID),
            d(235, "收据 URL", bundle.appStoreReceiptURL.flatMap { ($0 as NSURL).resourceSpecifier }),
        ]
        return SampleProfiles(turing: turing, tongdun: tongdun, location: location)
    }

    private static func batteryInfo(state: Int, level: Float) -> String {
        let name: String
        switch state {
        case 0: name = "unknown"
        case 1: name = "unplugged"
        default: name = "charging"
        }
        return String(format: "%@/%.0lf%%", name, level > 0 ? Double(level * 100) : 0)
    }

    private static func t(_ id: Int, _ label: String, _ value: SampleValue?, note: String? = nil) -> SampleField {
        SampleField(id, label, value, note: note)
    }

    private static func d(_ id: Int, _ label: String, _ value: String?, note: String? = nil, partial: Bool? = nil) -> SampleField {
        SampleField(id, label, value.map(SampleValue.text), type: 2, note: note, partial: partial)
    }

    private static func n(_ id: Int, _ label: String, _ value: Int64?, type: UInt8, note: String? = nil, partial: Bool? = nil) -> SampleField {
        SampleField(id, label, value.map(SampleValue.integer), type: type, note: note, partial: partial)
    }

    private static func uuid(_ value: String?) -> SampleValue? {
        guard let value, !value.isEmpty, value != "00000000-0000-0000-0000-000000000000" else { return nil }
        return .text(value)
    }

    private static func carrierString(_ carriers: [CTCarrier], _ path: KeyPath<CTCarrier, String?>) -> String? {
        let values = carriers.compactMap { $0[keyPath: path] }
        return values.isEmpty ? nil : values.joined(separator: ",")
    }

    static func compactJSON(_ value: Any) -> String? {
        guard JSONSerialization.isValidJSONObject(value),
              let data = try? JSONSerialization.data(withJSONObject: value) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private static func vpn(_ name: String) -> Bool {
        ["tun", "ipsec", "tap", "ppp"].contains { name.contains($0) }
    }
}
