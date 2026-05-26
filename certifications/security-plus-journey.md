# How I Passed CompTIA Security+ (SY0-701) in 9 Days

**Result:** ✅ Passed — May 2026  
**Background:** iOS/Android developer, no prior security certifications  
**Study time:** ~2 hours/day for 9 days  
**Resources used:** Professor Messer (free), Jason Dion (Udemy), practice tests

---

## Background

I spent 10 years building iOS and Android applications — payment platforms, logistics systems, language learning apps. I understood APIs, encryption, authentication flows, and data storage from the developer side. But I had no formal security credentials.

In May 2026 I decided to transition fully into cybersecurity. Security+ was the first step.

---

## Practice Test Scores (Before Studying by Domain)

| Test | Score | Notes |
|------|-------|-------|
| Test 1 | 65% | Cold start |
| Test 2 | 55% | Harder domain set |
| Test 3 | 65% | Consistent baseline |
| Test 4 | 68% | Small improvement |
| Test 5 | 62% | Dip — tired |
| Test 6 | 72% | Domain drilling paying off |
| Test 7 | 70% | Consistent |
| Test 8 | 72% | Ready |

**Average:** 66% → needed 75% to pass → gap = 9%

---

## Domain Weakness Analysis

After reviewing all 8 tests by domain:

| Domain | Weight | My Level | Priority |
|--------|--------|----------|----------|
| D4 — Security Operations | 28% | Weakest | 🔴 Day 1–2 |
| D2 — Threats & Vulnerabilities | 22% | Weak | 🔴 Day 3–4 |
| D5 — GRC & Oversight | 20% | Medium | 🟡 Day 5 |
| D3 — Security Architecture | 18% | Medium | 🟡 Day 6 |
| D1 — General Concepts | 12% | Strongest | 🟢 Day 7 |

**Key insight:** D4 + D2 = 50% of the exam. Fixing just these two domains = passing.

---

## 9-Day Sprint Plan

**Days 1–2:** Domain 4 only — SIEM triage, incident response (PICERL), vulnerability scanning  
**Days 3–4:** Domain 2 only — malware types, social engineering, network/app attacks  
**Day 5:** Domain 5 — NIST CSF, risk management, compliance (GDPR, PCI-DSS)  
**Day 6:** Domain 3 + ports/protocols cram (free marks — 4–6 guaranteed questions)  
**Day 7:** Full timed practice test — scored 72%  
**Day 8:** PBQ practice + surgical drill on remaining weak spots  
**Day 9 (day before exam):** Light review of cheat sheets only. No new content. Slept at 10pm.  
**Day 10:** Exam day ✅

---

## What Actually Worked

**1. Domain filtering, not full tests**  
Stop doing full practice tests and drill by domain. Full tests just confirm your average. Domain drilling fixes the specific gaps.

**2. The PICERL mnemonic**  
Preparation → Identification → Containment → Eradication → Recovery → Lessons Learned  
This came up multiple times. Write it from memory every morning.

**3. Ports memorisation = free marks**  
22 SSH · 25 SMTP · 53 DNS · 80 HTTP · 443 HTTPS · 445 SMB · 3389 RDP · 389 LDAP  
20 minutes to memorise = 4–6 guaranteed correct answers.

**4. PBQ strategy — skip and return**  
PBQs appear first. Flag them all, skip to MCQs, return at the end. Never spend 15 minutes on a PBQ at the start.

**5. Trust your first instinct**  
Statistically, changing answers on MCQs hurts more than it helps. Mark and move.

---

## What I'd Do Differently

- Start domain drilling from day 1 — I wasted 3 days doing full practice tests
- Use Professor Messer AND Jason Dion from the start (different question styles = better preparation)
- Do PBQ practice earlier — I underestimated how different they are from MCQs

---

## My Developer Advantage

Having built production apps gave me a genuine edge in:
- **Application security questions** — I'd seen these vulnerabilities from the code side
- **Cryptography** — iOS Secure Enclave and TLS/certificate handling in Swift meant crypto wasn't abstract
- **API security** — I'd built REST APIs with auth, understood token handling, OAuth flows
- **CI/CD security** — Fastlane pipelines meant DevSecOps concepts clicked immediately

The gaps were in areas pure developers don't touch: network protocols, IR procedures, compliance frameworks. Those needed the most drilling.

---

## Next Certifications

- **CompTIA CySA+** — in progress (2026)
- **eJPT** — planned (2026)
- **OSCP** — target (2027)

---

*Questions about the Security+ journey? Reach out: contact@gurjit.co*
