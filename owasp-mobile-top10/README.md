# OWASP Mobile Top 10 — iOS Developer's Practical Guide

> Written by a developer who built iOS apps for 10 years before studying security.  
> Every risk below includes a **real Swift code example** of the vulnerability and the fix.

---

## The 10 Risks at a Glance

| # | Risk | iOS Relevance | Severity |
|---|------|--------------|----------|
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

**❌ Vulnerable Swift code:**
```swift
// Never do this — visible in binary and source control
let apiKey = "sk-prod-abc123xyz789secretkey"
let baseURL = "https://api.example.com?key=\(apiKey)"
```

**✅ Secure fix:**
```swift
// Store in environment config, never in source
// Retrieve from Keychain at runtime
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
```

**Real-world impact:** Hardcoded keys in iOS binaries can be extracted with tools like `strings` or `otool` in under 60 seconds.

---

## M5 — Insecure Communication

**What it is:** Transmitting sensitive data without proper TLS validation, allowing man-in-the-middle attacks.

**❌ Vulnerable — disabling SSL validation:**
```swift
// Dangerous — accepts any certificate including attacker's
class InsecureDelegate: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        completionHandler(.useCredential, URLCredential(trust: challenge.protectionSpace.serverTrust!))
    }
}
```

**✅ Secure fix — certificate pinning:**
```swift
// Pin to your server's specific certificate
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
    let match = serverCerts.contains { SecCertificateGetData($0) == SecCertificateGetData(pinnedCert) }
    completionHandler(match ? .useCredential : .cancelAuthenticationChallenge,
                      match ? URLCredential(trust: serverTrust) : nil)
}
```

---

## M9 — Insecure Data Storage

**What it is:** Storing sensitive data in insecure locations — NSUserDefaults, plaintext files, or unencrypted databases.

**❌ Vulnerable:**
```swift
// NSUserDefaults is NOT encrypted — readable by anyone with device access
UserDefaults.standard.set(authToken, forKey: "user_auth_token")
UserDefaults.standard.set(userPassword, forKey: "user_password")
```

**✅ Secure fix — use Keychain:**
```swift
func saveToKeychain(key: String, value: String) -> Bool {
    guard let data = value.data(using: .utf8) else { return false }
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: key,
        kSecValueData as String: data,
        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    ]
    SecItemDelete(query as CFDictionary) // Remove existing
    return SecItemAdd(query as CFDictionary, nil) == errSecSuccess
}
```

**Key rule:** Anything sensitive (tokens, passwords, PII) → Keychain. Everything else → encrypted CoreData or UserDefaults for non-sensitive preferences only.

---

## M10 — Insufficient Cryptography

**What it is:** Using weak/broken algorithms (MD5, SHA1, DES), hardcoded encryption keys, or insecure modes (ECB).

**❌ Vulnerable:**
```swift
// MD5 is broken — do not use for security purposes
import CryptoKit
let data = Data(password.utf8)
let hash = Insecure.MD5.hash(data: data) // ❌ Broken
```

**✅ Secure fix:**
```swift
// Use SHA-256 minimum, or better — use dedicated password hashing
import CryptoKit

// For data integrity
let hash = SHA256.hash(data: data)

// For password storage — use a proper KDF
// Consider CryptoKit's HKDF or a library implementing Argon2/bcrypt
let key = HKDF<SHA256>.deriveKey(
    inputKeyMaterial: SymmetricKey(data: passwordData),
    salt: saltData,
    info: Data("app-context".utf8),
    outputByteCount: 32
)
```

---

*Full notes for all 10 risks coming — M2, M3, M4, M6, M7, M8 in progress.*

*Last updated: May 2026*
