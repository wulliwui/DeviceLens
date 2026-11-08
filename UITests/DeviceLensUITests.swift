import Darwin
import XCTest

final class DeviceLensUITests: XCTestCase {
    override func setUpWithError() throws { continueAfterFailure = false }

    func testCollectionShowsRealFieldsAndReportJSON() throws {
        let app = XCUIApplication()
        app.launch()
        XCTAssertTrue(app.staticTexts["还没有采集报告"].exists)
        app.buttons["startCollection"].tap()
        XCTAssertTrue(app.staticTexts["collectionSummary"].waitForExistence(timeout: 12))
        attachScreenshot(app, name: "采集报告")

        app.buttons["showJSON"].tap()
        let raw = app.staticTexts["reportJSON"]
        XCTAssertTrue(raw.waitForExistence(timeout: 5))
        let data = try XCTUnwrap(raw.label.data(using: .utf8))
        let report = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        let groups = try XCTUnwrap(report["groups"] as? [[String: Any]])
        let readings = groups.flatMap { $0["readings"] as? [[String: Any]] ?? [] }
        XCTAssertEqual(report["schemaVersion"] as? Int, 1)
        XCTAssertEqual(readings.count, Set(readings.compactMap { $0["id"] as? String }).count)
        XCTAssertEqual(readings.first { $0["id"] as? String == "device.model" }?["status"] as? String, "collected")
        XCTAssertEqual(readings.first { $0["id"] as? String == "omitted.hardware_ids" }?["status"] as? String, "notCollected")
        let profiles = try XCTUnwrap(report["sampleProfiles"] as? [String: Any])
        let pairs = try XCTUnwrap(profiles["turingFeaturePairs"] as? [String: [Any]])
        XCTAssertEqual(pairs["1012"] as? [String], ["", ""])
        XCTAssertEqual(pairs["1013"]?.last as? Int != nil, true)
        XCTAssertEqual((pairs["1042"]?.last as? [Any])?.count, 0)
        XCTAssertEqual((pairs["1056"]?.last as? [String])?.count, 18)
        XCTAssertEqual((pairs["1057"]?.last as? [String])?.count, 6)
        let tongdun = try XCTUnwrap(profiles["tongdun"] as? [[String: Any]])
        XCTAssertEqual(tongdun.first { $0["id"] as? Int == 38 }?["type"] as? Int, 2)
        XCTAssertEqual(tongdun.first { $0["id"] as? Int == 44 }?["type"] as? Int, 3)
        XCTAssertEqual(tongdun.first { $0["id"] as? Int == 9 }?["value"] as? Int, pairs["1006"]?.last as? Int)
        let profileBase64 = try XCTUnwrap(profiles["tongdunProfileBase64"] as? String)
        let bytes = try XCTUnwrap(Data(base64Encoded: profileBase64))
        XCTAssertEqual(Array(bytes.prefix(4)), [0xAC, 0xEF, 0xBC, 0xDA])
        let attachment = XCTAttachment(data: data, uniformTypeIdentifier: "public.json")
        attachment.name = "sample-collection.json"
        attachment.lifetime = .keepAlways
        add(attachment)
    }

    func testCollectionOpensShareSheet() {
        let app = XCUIApplication()
        app.launch()
        app.buttons["startCollection"].tap()
        XCTAssertTrue(app.staticTexts["collectionSummary"].waitForExistence(timeout: 12))
        app.buttons["shareReport"].tap()
        let saveToFiles = app.descendants(matching: .any).matching(NSPredicate(
            format: "label IN %@", ["保存到“文件”", "存储到“文件”", "Save to Files"]
        )).firstMatch
        XCTAssertTrue(saveToFiles.waitForExistence(timeout: 10))
        let filename = app.otherElements["LP.CaptionBar.TopCaption"].firstMatch
        XCTAssertTrue(filename.label.hasPrefix("DeviceLens-"))
        attachScreenshot(app, name: "采集报告分享面板")
        XCTAssertFalse(app.alerts["无法导出报告"].exists)
    }

    func testSimulatorVerdictAndFridaEvidenceJSON() throws {
        let app = XCUIApplication()
        app.launch()
        app.buttons["checkEnvironment"].tap()
        XCTAssertTrue(app.staticTexts["checkSummary"].waitForExistence(timeout: 12))
        XCTAssertTrue(app.staticTexts["Frida 迹象"].exists)
        XCTAssertTrue(app.staticTexts["模拟器 / 在 Mac 上运行"].exists)
        attachScreenshot(app, name: "环境判断")

        app.buttons["showJSON"].tap()
        let raw = app.staticTexts["reportJSON"]
        XCTAssertTrue(raw.waitForExistence(timeout: 5))
        let data = try XCTUnwrap(raw.label.data(using: .utf8))
        let report = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        let findings = try XCTUnwrap(report["findings"] as? [[String: Any]])
        let platform = try XCTUnwrap(findings.first { $0["id"] as? String == "simulator" })
        XCTAssertEqual(platform["state"] as? String, "detected")
        let jailbreak = try XCTUnwrap(findings.first { $0["id"] as? String == "jailbreak" })
        XCTAssertEqual(jailbreak["state"] as? String, "notApplicable")
        let frida = try XCTUnwrap(findings.first { $0["id"] as? String == "frida" })
        let evidence = try XCTUnwrap(frida["evidence"] as? [[String: Any]])
        let port = try XCTUnwrap(evidence.first { $0["id"] as? String == "frida.loopback" })
        XCTAssertNotEqual(port["state"] as? String, "detected")
    }

    func testLocalListenerIsOnlySuspicious() throws {
        let fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        guard fd >= 0 else { return XCTFail("socket: \(errno)") }
        defer { close(fd) }
        var reuse: Int32 = 1
        XCTAssertEqual(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size)), 0)
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = UInt16(27042).bigEndian
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard result == 0 else { return XCTFail("bind: \(errno)") }
        XCTAssertEqual(listen(fd, 4), 0)

        let app = XCUIApplication()
        app.launch()
        app.buttons["checkEnvironment"].tap()
        XCTAssertTrue(app.staticTexts["checkSummary"].waitForExistence(timeout: 12))
        app.buttons["showJSON"].tap()
        let raw = app.staticTexts["reportJSON"]
        XCTAssertTrue(raw.waitForExistence(timeout: 5))
        let data = try XCTUnwrap(raw.label.data(using: .utf8))
        let report = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        let findings = try XCTUnwrap(report["findings"] as? [[String: Any]])
        let frida = try XCTUnwrap(findings.first { $0["id"] as? String == "frida" })
        let evidence = try XCTUnwrap(frida["evidence"] as? [[String: Any]])
        let port = try XCTUnwrap(evidence.first { $0["id"] as? String == "frida.loopback" })
        XCTAssertEqual(port["state"] as? String, "suspicious")
        XCTAssertEqual(frida["state"] as? String, "suspicious")
    }

    private func attachScreenshot(_ app: XCUIApplication, name: String) {
        let attachment = XCTAttachment(screenshot: app.screenshot())
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }
}
