# DeviceLens

[中文文档](README.zh-CN.md)

DeviceLens is an iOS diagnostic app for inspecting device information and runtime signals on your own iPhone or iPad. It runs on demand and requires no server or third-party dependencies.

## Features

- **Collect** reads device, display, system, network, application, and permission information. The report explains unavailable values and includes numbered fields for comparison with TuringShield and Tongdun profile formats.
- **Check** shows evidence of jailbreaking, Frida, debugging, library injection, and simulator or Mac execution. An open loopback port alone is treated as suspicious.
- **Export** creates one self-contained HTML report with field explanations, the acquisition code used by this build, and raw JSON. You can open it offline on a computer or share it from iOS with AirDrop or Files.

## Build and run

1. Open [DeviceLens.xcodeproj](DeviceLens.xcodeproj) in Xcode and select the **DeviceLens** scheme. The deployment target is iOS 16.0.
2. Select an iOS Simulator and press **⌘R**. For a physical device, select your development team in **Signing & Capabilities**, then use a bundle identifier available to your team.
3. Tap **开始采集** to collect or **判断** to check the environment. Tap **导出报告文件** to share the report.

The UI and per-field explanations are currently in Simplified Chinese. Access to SSID and BSSID depends on signing entitlements and iOS conditions. Location collection requires user authorization. CoreTelephony can return placeholders on newer iOS versions.

## Data handling

The repository contains source and tests. Reports are generated on the device and can contain the owner's device identifiers, network details, and coordinates when authorized. DeviceLens sends no diagnostic reports automatically. Sharing is initiated through the iOS share sheet.

The numbered profiles are local diagnostic representations. Third-party SDKs and their online services are outside the scope of this app.
