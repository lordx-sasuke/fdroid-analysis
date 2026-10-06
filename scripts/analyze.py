import xml.etree.ElementTree as ET
import sys
import os

def audit_manifest(manifest_path):
    if not os.path.exists(manifest_path):
        print(f"[-] Error: {manifest_path} not found.")
        return

    tree = ET.parse(manifest_path)
    root = tree.getroot()
    
    pkg = root.attrib.get("package", "Unknown")

    print("==================================================")
    print("   ANDROID STATIC ANALYSIS AUDITOR (OWASP MASVS)  ")
    print("==================================================")
    print(f"Target: {pkg}")

    ns_name = "{http://schemas.android.com/apk/res/android}name"
    ns_exported = "{http://schemas.android.com/apk/res/android}exported"

    permissions = [elem.attrib.get(ns_name) for elem in root.findall("uses-permission")]
    print(f"\n[*] Total Permissions Requested: {len(permissions)}")
    
    high_risk = ["REQUEST_INSTALL_PACKAGES", "WRITE_EXTERNAL_STORAGE", "ACCESS_FINE_LOCATION"]
    for perm in permissions:
        if perm and any(hr in str(perm) for hr in high_risk):
            clean_perm = perm.split(".")[-1]
            print(f"  [!] High-Privilege: {clean_perm}")

    print("\n[*] Auditing Exported Components:")
    components = ["activity", "service", "receiver", "provider"]
    exported_count = 0

    for comp in components:
        for item in root.iter(comp):
            is_exported = item.attrib.get(ns_exported)
            name = item.attrib.get(ns_name)
            if is_exported == "true" and name:
                exported_count += 1
                clean_name = name.split(".")[-1]
                print(f"  [!] Exported {comp.capitalize()}: {clean_name}")

    print(f"\n[+] Total Exposed Entry Points: {exported_count}")
    print("==================================================")

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "../fdroid_java/resources/AndroidManifest.xml"
    audit_manifest(path)

