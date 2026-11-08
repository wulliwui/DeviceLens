import Darwin
import Foundation
import MachO

enum EnvironmentDetector {
    static func check() -> EnvironmentReport {
        let date = Date()
        let simulator = isSimulator
        let onMac = ProcessInfo.processInfo.isiOSAppOnMac
        let deviceOnly = !simulator && !onMac
        let images = imageNames()

        let jailbreakPaths = [
            "/var/jb", "/Applications/Cydia.app", "/Applications/Sileo.app", "/Applications/Zebra.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib", "/usr/lib/libsubstitute.dylib",
            "/private/var/lib/apt", "/var/jb/Applications/Sileo.app",
            "/var/jb/Library/MobileSubstrate/DynamicLibraries", "/var/jb/usr/lib/ellekit/loader.dylib"
        ]
        let fridaPaths = [
            "/usr/sbin/frida-server", "/usr/bin/frida-server", "/usr/lib/frida/frida-agent.dylib",
            "/Library/LaunchDaemons/re.frida.server.plist",
            "/var/jb/usr/sbin/frida-server", "/var/jb/usr/bin/frida-server",
            "/var/jb/Library/LaunchDaemons/re.frida.server.plist"
        ]
        let fridaImages = images.filter { isFridaImage(URL(fileURLWithPath: $0).lastPathComponent) }
        let injectionImages = images.filter { isInjectionImage($0) }
        let environment = ProcessInfo.processInfo.environment["DYLD_INSERT_LIBRARIES"] ?? ""
        let injectedLibraries = environment.split(separator: ":").map(String.init)
        let relevantLibraries = injectedLibraries.filter { !isDeveloperLibrary($0) }
        let fridaLibraries = relevantLibraries.filter { isFridaImage(URL(fileURLWithPath: $0).lastPathComponent) }
        let debugger = debuggerEvidence()

        return EnvironmentReport(checkedAt: date, findings: [
            Finding("jailbreak", "越狱迹象", [
                pathEvidence("jailbreak.paths", "越狱文件路径", jailbreakPaths, enabled: deviceOnly),
                deviceOnly
                    ? matches("jailbreak.runtime", "越狱注入框架", injectionImages, empty: "当前进程未见已知越狱框架。")
                    : Evidence(id: "jailbreak.runtime", label: "越狱注入框架", state: .notApplicable, detail: "此运行平台不适用。"),
            ]),
            Finding("frida", "Frida 迹象", [
                matches("frida.images", "当前进程的 Frida 镜像", fridaImages, empty: "未发现已知名称。"),
                matches("frida.dyld_env", "环境变量中的 Frida 镜像", fridaLibraries, empty: "未发现已知名称。"),
                fridaThreadEvidence(),
                fridaSymbols(),
                pathEvidence("frida.paths", "Frida 服务文件", fridaPaths, enabled: deviceOnly),
                loopbackEvidence(),
            ]),
            Finding("debugger", "调试器", [debugger]),
            Finding("injection", "动态库与函数来源", [
                matches("injection.images", "已知注入框架镜像", injectionImages, empty: "未发现已知名称。"),
                matches("injection.env", "动态库注入环境变量", relevantLibraries,
                        empty: injectedLibraries.isEmpty ? "未发现 DYLD_INSERT_LIBRARIES。" : "只发现已知的开发工具库。",
                        positive: .suspicious),
                symbolSourceEvidence(enabled: deviceOnly),
            ]),
            Finding("simulator", "模拟器 / 在 Mac 上运行", [
                Evidence(id: "platform.simulator", label: "Simulator", state: simulator ? .detected : .notObserved,
                         detail: simulator ? "这是为 iOS Simulator 构建的应用。" : "当前构建未标记为模拟器。"),
                Evidence(id: "platform.mac", label: "iOS App on Mac", state: onMac ? .detected : .notObserved,
                         detail: onMac ? "系统报告应用正在 Mac 上运行。" : "系统未报告此运行方式。"),
            ]),
        ])
    }

    static func isFridaImage(_ filename: String) -> Bool {
        let leaf = filename.lowercased()
        return leaf == "frida" || leaf == "fridagadget" || leaf == "frida-server"
            || ["fridagadget.", "frida-gadget.", "frida-agent.", "frida-agent-", "frida-server.", "libfrida-"]
                .contains { leaf.hasPrefix($0) }
    }

    private static func isInjectionImage(_ path: String) -> Bool {
        let path = path.lowercased()
        let leaf = URL(fileURLWithPath: path).lastPathComponent
        return ["/mobilesubstrate/dynamiclibraries/", "/tweakinject/", "/var/jb/"]
            .contains { path.contains($0) }
            || ["mobilesubstrate.dylib", "substitute-inserter.dylib", "libsubstitute.dylib",
                "libellekit.dylib", "libhooker.dylib", "systemhook.dylib"].contains(leaf)
    }

    private static func isDeveloperLibrary(_ path: String) -> Bool {
        let name = URL(fileURLWithPath: path).lastPathComponent.lowercased()
        return ["libviewdebugsupport.dylib", "libmainthreadchecker.dylib", "libgmldebugger.dylib",
                "libbacktracerecording.dylib", "libmtdiagnostics.dylib", "libxcuitestautomation.dylib",
                "liblogredirect.dylib"].contains(name)
    }

    private static var isSimulator: Bool {
        #if targetEnvironment(simulator)
        return true
        #else
        return false
        #endif
    }

    static func imageNames() -> [String] {
        (0..<_dyld_image_count()).compactMap { _dyld_get_image_name($0).map(String.init(cString:)) }
    }

    private static func matches(_ id: String, _ label: String, _ values: [String],
                                empty: String, positive: FindingState = .detected) -> Evidence {
        Evidence(id: id, label: label, state: values.isEmpty ? .notObserved : positive,
                 detail: values.isEmpty ? empty : Array(Set(values)).sorted().joined(separator: "\n"))
    }

    private static func pathEvidence(_ id: String, _ label: String, _ paths: [String],
                                     enabled: Bool) -> Evidence {
        guard enabled else {
            return Evidence(id: id, label: label, state: .notApplicable, detail: "只在 iPhone / iPad 真机检查。")
        }
        var found = [String]()
        var errors = [String]()
        for path in paths {
            if access(path, F_OK) == 0 {
                found.append(path)
            } else {
                let code = errno
                if code != ENOENT && code != ENOTDIR { errors.append("\(path) · errno \(code)") }
            }
        }
        if !found.isEmpty {
            return matches(id, label, found, empty: "")
        }
        if !errors.isEmpty {
            return Evidence(id: id, label: label, state: .inconclusive,
                            detail: "部分路径不可检查：\n" + errors.joined(separator: "\n"))
        }
        return Evidence(id: id, label: label, state: .notObserved,
                        detail: "检查了 \(paths.count) 个固定位置。沙盒可能隐藏路径。")
    }

    static func processTraced() -> Bool? {
        var mib = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.size
        guard sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0) == 0,
              size == MemoryLayout<kinfo_proc>.size else { return nil }
        return info.kp_proc.p_flag & P_TRACED != 0
    }

    private static func debuggerEvidence() -> Evidence {
        guard let traced = processTraced() else {
            return Evidence(id: "debugger.p_traced", label: "进程调试标志", state: .inconclusive,
                            detail: "系统未返回当前进程的完整状态。")
        }
        return Evidence(id: "debugger.p_traced", label: "进程调试标志", state: traced ? .detected : .notObserved,
                        detail: traced ? "P_TRACED 已置位。Xcode / LLDB 调试也会触发。" : "P_TRACED 未置位。")
    }

    private static func fridaThreadEvidence() -> Evidence {
        let id = "frida.threads"
        let label = "当前进程的 Frida 线程"
        var threads: thread_act_array_t?
        var count: mach_msg_type_number_t = 0
        let kernelResult = task_threads(mach_task_self_, &threads, &count)
        guard kernelResult == KERN_SUCCESS, let threads else {
            return Evidence(id: id, label: label, state: .inconclusive, detail: "无法读取本进程的线程列表。")
        }
        defer {
            for index in 0..<Int(count) { mach_port_deallocate(mach_task_self_, threads[index]) }
            vm_deallocate(mach_task_self_, vm_address_t(UInt(bitPattern: threads)),
                          vm_size_t(Int(count) * MemoryLayout<thread_t>.stride))
        }
        let names: [String] = (0..<Int(count)).compactMap { index in
            guard let thread = pthread_from_mach_thread_np(threads[index]) else { return nil }
            var buffer = [CChar](repeating: 0, count: 64)
            guard pthread_getname_np(thread, &buffer, buffer.count) == 0 else { return nil }
            let name = String(cString: buffer)
            let key = name.lowercased()
            return key == "gum-js-loop" || key.hasPrefix("frida-") ? name : nil
        }
        return matches(id, label, names, empty: "可读线程中未发现已知名称。")
    }

    private static var defaultSymbols: UnsafeMutableRawPointer? { UnsafeMutableRawPointer(bitPattern: -2) }

    private static func fridaSymbols() -> Evidence {
        let names = ["frida_agent_main", "frida_gadget_load", "gum_interceptor_obtain"]
        let symbols = names.filter { name in name.withCString { dlsym(defaultSymbols, $0) != nil } }
        return matches("frida.symbols", "当前进程的 Frida / Gum 符号", symbols,
                       empty: "未发现已知导出符号；隐藏符号不在此检查范围。")
    }

    private static func symbolSourceEvidence(enabled: Bool) -> Evidence {
        let id = "injection.symbol_origin"
        let label = "系统函数实现来源"
        guard enabled else {
            return Evidence(id: id, label: label, state: .notApplicable, detail: "模拟器或 Mac 的库路径与真机不同。")
        }
        var anomalous = [String]()
        var missing = [String]()
        for name in ["getifaddrs", "sysctl", "objc_msgSend", "dladdr", "open"] {
            guard let pointer = name.withCString({ dlsym(defaultSymbols, $0) }) else { missing.append(name); continue }
            var info = Dl_info()
            guard dladdr(pointer, &info) != 0, let filename = info.dli_fname else { missing.append(name); continue }
            let path = String(cString: filename)
            if !path.hasPrefix("/usr/lib/") && !path.hasPrefix("/System/Library/") {
                anomalous.append("\(name) → \(path)")
            }
        }
        if !anomalous.isEmpty { return matches(id, label, anomalous, empty: "", positive: .suspicious) }
        if !missing.isEmpty {
            return Evidence(id: id, label: label, state: .inconclusive,
                            detail: "未解析：\(missing.joined(separator: ", "))")
        }
        return Evidence(id: id, label: label, state: .notObserved, detail: "五个被检函数解析到系统库。此检查不读取入口指令。")
    }

    private enum Probe: Equatable { case open, refused, unknown }

    private static func loopbackEvidence() -> Evidence {
        let probes = ["127.0.0.1", "::1"].map { ($0, loopbackProbe($0)) }
        let open = probes.filter { $0.1 == .open }.map(\.0)
        let unknown = probes.filter { $0.1 == .unknown }.map(\.0)
        let id = "frida.loopback"
        let label = "本机 TCP 27042"
        if !open.isEmpty {
            return Evidence(id: id, label: label, state: .suspicious,
                            detail: "\(open.joined(separator: ", ")) 可连接。其他程序也能监听该端口。")
        }
        if !unknown.isEmpty {
            return Evidence(id: id, label: label, state: .inconclusive,
                            detail: "连接超时、被限制或地址族不可用：\(unknown.joined(separator: ", "))。")
        }
        return Evidence(id: id, label: label, state: .notObserved,
                        detail: "IPv4 和 IPv6 回环地址均拒绝连接。")
    }

    private static func loopbackProbe(_ host: String) -> Probe {
        var hints = addrinfo()
        hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV
        hints.ai_socktype = SOCK_STREAM
        hints.ai_protocol = IPPROTO_TCP
        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, "27042", &hints, &result) == 0, let result else { return .unknown }
        defer { freeaddrinfo(result) }
        let address = result.pointee
        let fd = socket(address.ai_family, address.ai_socktype, address.ai_protocol)
        guard fd >= 0 else { return .unknown }
        defer { close(fd) }
        let flags = fcntl(fd, F_GETFL)
        guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 else { return .unknown }
        if connect(fd, address.ai_addr, address.ai_addrlen) == 0 { return .open }
        let initialError = errno
        if initialError == ECONNREFUSED { return .refused }
        guard initialError == EINPROGRESS else { return .unknown }
        var pollFD = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
        guard poll(&pollFD, 1, 250) > 0 else { return .unknown }
        var error: Int32 = 0
        var length = socklen_t(MemoryLayout<Int32>.size)
        guard getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0 else { return .unknown }
        if error == 0 { return .open }
        return error == ECONNREFUSED ? .refused : .unknown
    }
}
