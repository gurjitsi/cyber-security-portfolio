# ImageGalleryApp MobSF Audit Report

**Project:** ImageGalleryApp  
**Repository:** `gurjitsi/ImageGalleryApp`  
**Assessment:** Static analysis with MobSF  
**Overall score:** 40/100  
**Risk level:** Medium

## Executive summary

MobSF identified two high-severity issues and one informational issue in the ImageGalleryApp iOS project. The main concerns are globally disabled App Transport Security, a likely hardcoded Flickr API key, and logging in production code. The app does not appear to use trackers, which is a positive privacy signal.

## Scope

This assessment covers the public Swift-based iOS app ImageGalleryApp, which uses the Flickr API and follows an MVVM-style structure. The review focused on transport security, hardcoded secrets, logging behavior, and privacy-related findings surfaced by MobSF.

## Findings

| ID | Severity | Finding | Evidence | Risk |
|---|---|---|---|---|
| IMG-01 | High | App Transport Security allows arbitrary loads | MobSF flags `App Transport Security AllowsArbitraryLoads is allowed` | Weakens network security and can allow insecure HTTP traffic or reduced TLS protections. |
| IMG-02 | High | Possible hardcoded sensitive information | MobSF flags hardcoded sensitive data and highlights `Constants.swift` plus a Flickr API key pattern | API keys may be extracted and abused, especially if the app is distributed publicly. |
| IMG-03 | Info | Application logs information | MobSF flags logging in `FlickrCollectionViewController.swift`, `FullScreenViewController.swift`, and `FlickrImageSource.swift` | Logs may leak internal state or sensitive values if debug output reaches production builds. |

## Risk analysis

The most important issue is the ATS configuration because it affects the entire app’s network posture. The hardcoded key is also important because it may allow unauthorized use of the Flickr API or expose build-time secrets. Logging is lower severity, but it still matters because AppSec work expects production builds to avoid unnecessary information exposure.

## Remediation

- **IMG-01:** Remove global ATS exceptions from `Info.plist` and only allow specific exceptions if there is a documented business need.
- **IMG-02:** Move the Flickr API key out of source control, rotate it if it has been exposed, and consider using a server-side proxy or provider-side restrictions.
### IMG-02: Possible hardcoded sensitive information

**Evidence**
```swift
let flickrKey = "f9cc014fa76b098f9e82f1c288379ea1"
```

**Risk**
The API key is exposed in source code and can be extracted from the app.

**Remediation**
```swift
let flickrKey = Bundle.main.object(forInfoDictionaryKey: "FLICKR_API_KEY") as? String ?? ""
```
- **IMG-03:** Remove debug logging from release builds and ensure no sensitive request, response, or user data is written to logs.

## Evidence

### MobSF scorecard
![image alt](https://github.com/gurjitsi/cyber-security-portfolio/blob/14c231adee3b495d5cc96f28bb9b07e70611e8c4/mobsf-audit/imagegalleryapp.png)


## Retest notes

After remediation, rerun MobSF to confirm that ATS warnings disappear, the hardcoded secret finding is gone, and logging is reduced or disabled in production paths. A retest with an improved score would make this a stronger portfolio case study.

## Conclusion

This audit is a solid portfolio project because it shows both static-analysis findings and concrete remediation opportunities. The app is simple enough to finish quickly, but the issues are realistic and relevant for AppSec roles.
