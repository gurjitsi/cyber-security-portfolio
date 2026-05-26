# MobSF Security Audit — SixRPM iOS App

**App:** SixRPM AI — Freight Platform iOS Application  
**Analyst:** Gurjit Singh  
**Tool:** MobSF (Mobile Security Framework) v3.x  
**Type:** Static Analysis  
**Date:** May 2026  
**Status:** 🔄 In progress — findings being documented

---

## Methodology

1. Exported IPA from development build
2. Uploaded to local MobSF instance
3. Reviewed static analysis findings by severity
4. Mapped each finding to OWASP Mobile Top 10
5. Documented remediation steps with Swift code fixes

---

## Findings Summary

| Severity | Count | Status |
|----------|-------|--------|
| 🔴 Critical | 0 | — |
| 🟠 High | 2 | In remediation |
| 🟡 Medium | 3 | Documented |
| 🔵 Low / Info | 4 | Accepted / monitoring |

---

## Finding 1 — Insecure Logging in Production Build

**Severity:** 🟠 High  
**OWASP:** M8 — Security Misconfiguration  
**CVSS Base Score:** 7.1

**Description:**  
Debug print statements and `NSLog` calls in production code were outputting sensitive freight load data and carrier identifiers to the device console. On a non-jailbroken device this is limited risk, but on a compromised device or during USB debugging sessions this data is readable.

**Evidence (MobSF finding):**
```
Insecure Logging: NSLog/print statements found in production code
Files affected: LoadDispatcher.swift, FreightAPIManager.swift
```

**Vulnerable code pattern:**
```swift
// Logging sensitive freight data to console
print("Loading freight data for carrier: \(carrier.id) - \(carrier.secretKey)")
NSLog("API Response: %@", responseData.description)
```

**Remediation:**
```swift
// Use a debug-only logging wrapper
struct AppLogger {
    static func debug(_ message: String) {
        #if DEBUG
        print("[DEBUG] \(message)")
        #endif
    }
}
// Sensitive data never logged even in debug
AppLogger.debug("Freight request sent") // ✅ No sensitive values
```

**Status:** ✅ Fixed — all production logging now wrapped in DEBUG preprocessor flags

---

## Finding 2 — Weak Transport Security Exception

**Severity:** 🟠 High  
**OWASP:** M5 — Insecure Communication  
**CVSS Base Score:** 7.4

**Description:**  
Info.plist contained an `NSAllowsArbitraryLoads` exception in the App Transport Security configuration — a broad exception that disables ATS for all connections, not just specific required domains.

**Evidence:**
```xml
<!-- Info.plist — overly broad ATS exception -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>  <!-- ❌ Too broad -->
    <true/>
</dict>
```

**Remediation:**
```xml
<!-- Scope exceptions to specific domains only -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <false/>
    <key>NSExceptionDomains</key>
    <dict>
        <key>legacy-api.specific-domain.com</key>
        <dict>
            <key>NSExceptionAllowsInsecureHTTPLoads</key>
            <true/>
            <key>NSIncludesSubdomains</key>
            <false/>
        </dict>
    </dict>
</dict>
```

**Status:** ✅ Fixed — scoped to required domain only, `NSAllowsArbitraryLoads` removed

---

## Finding 3 — Sensitive Data in UserDefaults

**Severity:** 🟡 Medium  
**OWASP:** M9 — Insecure Data Storage  
**CVSS Base Score:** 5.3

**Description:**  
Carrier session tokens were stored in `NSUserDefaults` which is unencrypted and accessible on jailbroken devices or via iTunes backup.

**Remediation:** Migrated to Keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` attribute.

**Status:** 🔄 In remediation

---

## Finding 4 — Binary Debug Symbols Present

**Severity:** 🟡 Medium  
**OWASP:** M7 — Insufficient Binary Protections  
**CVSS Base Score:** 4.3

**Description:**  
Development build contained debug symbols that could assist reverse engineering efforts.

**Remediation:** Ensure release builds have `Strip Debug Symbols` enabled in Xcode build settings. Strip Swift symbols in release configuration.

**Status:** 🔄 In remediation

---

## Finding 5 — URL Scheme Without Source Validation

**Severity:** 🟡 Medium  
**OWASP:** M1 — Improper Credential Usage  
**CVSS Base Score:** 4.8

**Description:**  
Custom URL scheme handler accepted deep link parameters without validating the calling application source, potentially allowing malicious apps to trigger actions.

**Remediation:**
```swift
func application(_ app: UIApplication, open url: URL,
                 options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {
    // Validate source application
    guard let sourceApp = options[.sourceApplication] as? String,
          allowedSourceApps.contains(sourceApp) else {
        return false // ✅ Reject unknown sources
    }
    return handleDeepLink(url)
}
```

**Status:** ✅ Fixed

---

## Key Learnings

Running MobSF on an app I built myself was revealing in a way that pure theory never is. As the developer, I knew the codebase — but the audit found issues I had normalised during development:

- Debug logging that "didn't matter" in development genuinely matters in production
- ATS exceptions added to "fix a networking issue quickly" and never revisited
- UserDefaults used for convenience that should have been Keychain from day one

**The developer-to-security perspective matters:** I could understand immediately *why* each vulnerability existed (time pressure, convenience, not security-first thinking) and could remediate faster than someone who hadn't built the app.

---

*Full dynamic analysis (runtime testing with Frida) planned as next phase.*  
*Last updated: May 2026*
