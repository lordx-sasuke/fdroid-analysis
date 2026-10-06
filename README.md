# Android APK Static Analysis: F-Droid Client Security Audit

**Target:** `org.fdroid.fdroid` (v1.20)
**Methodology:** Static Analysis (Manifest Auditing, Component Mapping, Cryptographic Review)
**Framework Alignment:** OWASP MASVS (Mobile Application Security Verification Standard)

## Executive Summary
This project is a comprehensive static security assessment of the official F-Droid Android client. Using automated Python tooling and manual reverse engineering via JADX, this audit maps the application attack surface, validates its cryptographic trust mechanisms, and reviews high-privilege permissions against the OWASP MASVS framework.

---

## 1. Automated Manifest Auditing (MASVS-PLATFORM)
Using a custom Python parser (`scripts/analyze.py`), the `AndroidManifest.xml` was audited to extract permission requests and map the exported attack surface.

### Key Findings:
*   **Total Permissions Requested:** 30
*   **High-Privilege Observations:**
    *   `android.permission.REQUEST_INSTALL_PACKAGES`: Required for core functionality (installing third-party APKs).
    *   `android.permission.WRITE_EXTERNAL_STORAGE`: Required for caching downloaded binaries and managing local repositories.

### Attack Surface Mapping (Exported Components)
An exported component can be invoked by any other application on the device. Seven entry points were identified:
*   **Activities:** `PanicActivity`, `PanicResponderActivity`, `MainActivity`, `UpdateRepoActivity`
*   **Services:** `SystemJobService`
*   **Receivers:** `DiagnosticsReceiver`, `ProfileInstallReceiver`

---

## 2. Component Analysis: The Panic Protocol
A deep dive was conducted into `PanicActivity` and `PanicResponderActivity`, which are triggered via the intent filter `info.guardianproject.panic.action.TRIGGER`.

*   **Observation:** The application implements an emergency wipe mechanism (the "Panic Button" standard by Guardian Project).
*   **Execution Flow:** When triggered by an external application, `PanicResponderActivity` catches the intent and routes execution to background coroutines via `PanicSettingsViewModel.kt`.
*   **Security Impact:** This is a privacy feature, not a vulnerability. It allows users in hostile environments to rapidly purge application data, cached APKs, and repository configurations.

---

## 3. Trust Mechanisms (MASVS-CRYPTO)
F-Droid circumvents the Google Play Store, meaning it must manage its own root of trust.

*   **Trust Anchor:** The repository public signing keys are hardcoded into the APK asset directory (`assets/default_repos.json`).
*   **Integrity Verification:** During the update cycle, the client fetches the repository index and verifies the embedded cryptographic signature against the hardcoded public key before displaying available applications to the user. This mitigates Man-in-the-Middle (MitM) attacks during repository syncs.

---

## Usage Instructions

To reproduce the automated manifest audit:
1. Clone the repository: `git clone https://github.com/lordx-sasuke/fdroid-analysis.git`
2. Ensure you have the extracted F-Droid `AndroidManifest.xml` available.
3. Run the analysis script:
   `python3 scripts/analyze.py /path/to/AndroidManifest.xml`
