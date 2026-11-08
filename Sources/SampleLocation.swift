import CoreLocation
import Foundation

struct SampleLocationResult: Encodable, Sendable {
    let servicesEnabled: Bool
    let authorization: Int32
    let accuracyAuthorization: Int
    let latitude: Double?
    let longitude: Double?
    let altitude: Double?
    let horizontalAccuracy: Double?
    let verticalAccuracy: Double?
    let timestamp: Date?
    let simulatedBySoftware: Bool?
    let producedByAccessory: Bool?
    let note: String?

    var authorizationCode: Int64 { Int64(authorization) | (servicesEnabled ? 16 : 0) }
    var canRequestPermission: Bool { servicesEnabled && authorization == CLAuthorizationStatus.notDetermined.rawValue }

    var readings: [Reading] {
        [
            Reading("location.authorization", "定位授权（原始值）", String(authorizationCode)),
            Reading("location.accuracy_authorization", "定位精度授权",
                    accuracyAuthorization == CLAccuracyAuthorization.fullAccuracy.rawValue ? "完整精度" : "降低精度"),
            Reading("location.coordinate", "经纬度",
                    latitude.flatMap { latitude in longitude.map { "\(latitude), \($0)" } }, note: note),
            Reading("location.altitude", "高度（米）", altitude.map { String($0) }),
            Reading("location.horizontal_accuracy", "水平精度（米）", horizontalAccuracy.map { String($0) }),
            Reading("location.vertical_accuracy", "垂直精度（米）", verticalAccuracy.map { String($0) }),
            Reading("location.timestamp", "定位时间", timestamp.map { ISO8601DateFormatter().string(from: $0) }),
            Reading("location.simulated", "系统报告位置来自软件模拟", simulatedBySoftware.map { $0 ? "是" : "否" }),
            Reading("location.accessory", "系统报告位置来自外部配件", producedByAccessory.map { $0 ? "是" : "否" }),
        ]
    }
}

@MainActor
final class SampleLocation: NSObject, @preconcurrency CLLocationManagerDelegate {
    private let manager = CLLocationManager()
    private var result: CheckedContinuation<SampleLocationResult, Never>?
    private var timeout: Task<Void, Never>?
    private var servicesEnabled = false
    private var requestedFix = false

    func read(requestPermission: Bool) async -> SampleLocationResult {
        servicesEnabled = await Task.detached { CLLocationManager.locationServicesEnabled() }.value
        guard servicesEnabled else { return snapshot(nil, note: "系统定位服务已关闭。") }
        switch manager.authorizationStatus {
        case .authorizedAlways, .authorizedWhenInUse, .notDetermined:
            guard requestPermission || manager.authorizationStatus != .notDetermined else {
                return snapshot(nil, note: "可点击授权定位后采集。")
            }
            return await withCheckedContinuation { continuation in
                result = continuation
                manager.delegate = self
                if manager.authorizationStatus == .notDetermined {
                    manager.requestWhenInUseAuthorization()
                } else {
                    advance()
                }
            }
        default:
            return snapshot(nil, note: "当前没有定位授权。")
        }
    }

    func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) { advance() }

    func locationManager(_ manager: CLLocationManager, didUpdateLocations locations: [CLLocation]) {
        let location = locations.last { $0.horizontalAccuracy >= 0 }
        finish(location, note: location == nil ? "系统未返回有效位置。" : nil)
    }

    func locationManager(_ manager: CLLocationManager, didFailWithError error: Error) {
        finish(nil, note: "定位失败（\((error as NSError).code)）。")
    }

    private func advance() {
        guard result != nil else { return }
        switch manager.authorizationStatus {
        case .authorizedAlways, .authorizedWhenInUse:
            guard !requestedFix else { return }
            requestedFix = true
            manager.desiredAccuracy = kCLLocationAccuracyBest
            manager.requestLocation()
            timeout = Task { [weak self] in
                try? await Task.sleep(nanoseconds: 5_000_000_000)
                guard !Task.isCancelled else { return }
                self?.finish(nil, note: "系统未在五秒内返回位置。")
            }
        case .notDetermined: break
        default: finish(nil, note: "当前没有定位授权。")
        }
    }

    private func finish(_ location: CLLocation?, note: String?) {
        guard let result else { return }
        self.result = nil
        timeout?.cancel()
        timeout = nil
        manager.stopUpdatingLocation()
        manager.delegate = nil
        result.resume(returning: snapshot(location, note: note))
    }

    private func snapshot(_ location: CLLocation?, note: String?) -> SampleLocationResult {
        SampleLocationResult(servicesEnabled: servicesEnabled, authorization: manager.authorizationStatus.rawValue,
            accuracyAuthorization: manager.accuracyAuthorization.rawValue,
            latitude: location?.coordinate.latitude, longitude: location?.coordinate.longitude,
            altitude: location.flatMap { $0.verticalAccuracy >= 0 ? $0.altitude : nil },
            horizontalAccuracy: location?.horizontalAccuracy,
            verticalAccuracy: location.flatMap { $0.verticalAccuracy >= 0 ? $0.verticalAccuracy : nil },
            timestamp: location?.timestamp,
            simulatedBySoftware: location?.sourceInformation?.isSimulatedBySoftware,
            producedByAccessory: location?.sourceInformation?.isProducedByAccessory, note: note)
    }
}
