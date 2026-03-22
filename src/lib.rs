#![allow(clippy::module_name_repetitions)]

use std::net::SocketAddrV4;

use adb_client::ADBDeviceExt;
use adb_client::server_device::ADBServerDevice;

/// ADB-based transport implementing `kantei::DeviceTransport`.
///
/// Connects to an ADB server and executes commands on a specific device
/// identified by its serial number.
pub struct AdbTransport {
    server_addr: SocketAddrV4,
    serial: String,
}

impl AdbTransport {
    /// Create a new ADB transport targeting the given device.
    ///
    /// # Arguments
    ///
    /// * `host` - ADB server hostname or IP address
    /// * `port` - ADB server port (typically 5037)
    /// * `serial` - Device serial number (as shown by `adb devices`)
    #[must_use]
    pub fn new(host: &str, port: u16, serial: &str) -> Self {
        let addr: SocketAddrV4 = format!("{host}:{port}")
            .parse()
            .unwrap_or_else(|_| {
                format!("127.0.0.1:{port}")
                    .parse()
                    .expect("default address should parse")
            });
        Self {
            server_addr: addr,
            serial: serial.to_string(),
        }
    }

    /// Create a mutable `ADBServerDevice` connected to this transport's device.
    fn device(&self) -> ADBServerDevice {
        ADBServerDevice::new(self.serial.clone(), Some(self.server_addr))
    }
}

impl kantei::DeviceTransport for AdbTransport {
    fn exec(&self, command: &str) -> kantei::Result<kantei::CommandOutput> {
        let mut device = self.device();
        let mut stdout_buf = Vec::new();
        let mut stderr_buf = Vec::new();

        let exit_code = device
            .shell_command(&command, Some(&mut stdout_buf), Some(&mut stderr_buf))
            .map_err(|e| kantei::KanteiError::CommandFailed(format!("adb shell failed: {e}")))?;

        Ok(kantei::CommandOutput {
            stdout: String::from_utf8_lossy(&stdout_buf).to_string(),
            stderr: String::from_utf8_lossy(&stderr_buf).to_string(),
            exit_code: exit_code.map_or(0, i32::from),
        })
    }

    fn get_property(&self, key: &str) -> kantei::Result<String> {
        let output = self.exec(&format!("getprop {key}"))?;
        let value = output.stdout.trim().to_string();
        if value.is_empty() {
            return Err(kantei::KanteiError::PropertyNotFound(key.to_string()));
        }
        Ok(value)
    }

    fn read_file(&self, path: &str) -> kantei::Result<Vec<u8>> {
        let mut device = self.device();
        let mut output = Vec::new();

        device
            .shell_command(&format!("cat {path}"), Some(&mut output), None)
            .map_err(|e| kantei::KanteiError::CommandFailed(format!("adb cat failed: {e}")))?;

        if output.is_empty() {
            return Err(kantei::KanteiError::FileNotFound(path.to_string()));
        }

        Ok(output)
    }

    fn transport_id(&self) -> &str {
        &self.serial
    }
}

// ── Built-in GrapheneOS Profile ─────────────────────────────────────────

/// YAML source for the built-in GrapheneOS hardened device profile.
pub const GRAPHENEOS_HARDENED_PROFILE: &str = r#"
profile:
  name: "GrapheneOS Hardened Device"
  version: "1.0.0"
  platform: android
checks:
  - type: property
    id: "GOS-AVB-001"
    title: "Verified boot state is green"
    severity: Critical
    property: "ro.boot.verifiedbootstate"
    expected: "green"
    controls:
      - { framework: nist, control_id: "AC-3" }
      - { framework: cis_android, control_id: "1.1" }
  - type: property
    id: "GOS-ENC-001"
    title: "File-based encryption is active"
    severity: Critical
    property: "ro.crypto.state"
    expected: "encrypted"
    controls:
      - { framework: nist, control_id: "SC-28" }
  - type: command
    id: "GOS-SEL-001"
    title: "SELinux is enforcing"
    severity: Critical
    command: "getenforce"
    expected: "Enforcing"
    controls:
      - { framework: nist, control_id: "AC-3" }
  - type: patch_age
    id: "GOS-PATCH-001"
    title: "Security patches within 90 days"
    severity: High
    property: "ro.build.version.security_patch"
    max_age_days: 90
    controls:
      - { framework: nist, control_id: "SI-2" }
  - type: property
    id: "GOS-USB-001"
    title: "USB debugging is disabled"
    severity: High
    property: "persist.sys.usb.config"
    expected: "none"
    controls:
      - { framework: nist, control_id: "CM-7" }
  - type: property
    id: "GOS-GOS-001"
    title: "Device is running GrapheneOS"
    severity: Info
    property: "ro.grapheneos.release_version"
    expected: "*"
    controls: []
"#;

/// Parse and return the built-in GrapheneOS hardened device profile.
///
/// # Panics
///
/// Panics if the embedded YAML is malformed (should never happen in
/// a correctly built release).
#[must_use]
pub fn grapheneos_profile() -> kantei::ComplianceProfile {
    kantei::ComplianceProfile::from_yaml(GRAPHENEOS_HARDENED_PROFILE)
        .expect("built-in GrapheneOS profile YAML should be valid")
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use kantei::{CheckStatus, ComplianceProfile, MockTransport};

    // ── AdbTransport trait bounds ───────────────────────────────────

    #[test]
    fn adb_transport_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<AdbTransport>();
    }

    #[test]
    fn adb_transport_is_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<AdbTransport>();
    }

    // ── Profile parsing ─────────────────────────────────────────────

    #[test]
    fn grapheneos_profile_parses() {
        let profile = grapheneos_profile();
        assert_eq!(profile.meta.name, "GrapheneOS Hardened Device");
        assert_eq!(profile.meta.version, "1.0.0");
        assert_eq!(profile.meta.platform, "android");
    }

    #[test]
    fn grapheneos_profile_has_expected_check_count() {
        let profile = grapheneos_profile();
        assert_eq!(profile.checks.len(), 6);
    }

    // ── Full evaluate with MockTransport ────────────────────────────

    fn compliant_transport() -> MockTransport {
        MockTransport::new("pixel-8")
            .with_property("ro.boot.verifiedbootstate", "green")
            .with_property("ro.crypto.state", "encrypted")
            .with_command("getenforce", "Enforcing")
            .with_property("ro.build.version.security_patch", "2026-03-01")
            .with_property("persist.sys.usb.config", "none")
            .with_property("ro.grapheneos.release_version", "2026030100")
    }

    #[test]
    fn evaluate_all_passing() {
        let profile = grapheneos_profile();
        let transport = compliant_transport();
        let results = profile.evaluate_all(&transport);

        assert_eq!(results.len(), 6);
        assert!(
            results.iter().all(|r| r.status == CheckStatus::Pass),
            "all checks should pass for compliant device"
        );
    }

    #[test]
    fn evaluate_avb_unlocked_fails() {
        let profile = grapheneos_profile();
        let transport = MockTransport::new("pixel-8")
            .with_property("ro.boot.verifiedbootstate", "orange")
            .with_property("ro.crypto.state", "encrypted")
            .with_command("getenforce", "Enforcing")
            .with_property("ro.build.version.security_patch", "2026-03-01")
            .with_property("persist.sys.usb.config", "none")
            .with_property("ro.grapheneos.release_version", "2026030100");

        let results = profile.evaluate_all(&transport);
        let avb = results.iter().find(|r| r.check_id == "GOS-AVB-001").unwrap();
        assert_eq!(avb.status, CheckStatus::Fail);
    }

    #[test]
    fn evaluate_old_patch_fails() {
        let profile = grapheneos_profile();
        let transport = MockTransport::new("pixel-8")
            .with_property("ro.boot.verifiedbootstate", "green")
            .with_property("ro.crypto.state", "encrypted")
            .with_command("getenforce", "Enforcing")
            .with_property("ro.build.version.security_patch", "2020-01-01")
            .with_property("persist.sys.usb.config", "none")
            .with_property("ro.grapheneos.release_version", "2026030100");

        let results = profile.evaluate_all(&transport);
        let patch = results.iter().find(|r| r.check_id == "GOS-PATCH-001").unwrap();
        assert_eq!(patch.status, CheckStatus::Fail);
    }

    #[test]
    fn evaluate_no_encryption_fails() {
        let profile = grapheneos_profile();
        let transport = MockTransport::new("pixel-8")
            .with_property("ro.boot.verifiedbootstate", "green")
            .with_property("ro.crypto.state", "unencrypted")
            .with_command("getenforce", "Enforcing")
            .with_property("ro.build.version.security_patch", "2026-03-01")
            .with_property("persist.sys.usb.config", "none")
            .with_property("ro.grapheneos.release_version", "2026030100");

        let results = profile.evaluate_all(&transport);
        let enc = results.iter().find(|r| r.check_id == "GOS-ENC-001").unwrap();
        assert_eq!(enc.status, CheckStatus::Fail);
    }

    // ── Compliance report ───────────────────────────────────────────

    #[test]
    fn compliance_report_hash_is_deterministic() {
        let profile = grapheneos_profile();
        let transport = compliant_transport();
        let r1 = profile.report(&transport);
        let r2 = profile.report(&transport);
        assert_eq!(r1.compliance_hash, r2.compliance_hash);
        assert!(!r1.compliance_hash.is_empty());
    }

    #[test]
    fn compliance_report_is_compliant() {
        let profile = grapheneos_profile();
        let transport = compliant_transport();
        let report = profile.report(&transport);
        assert!(report.is_compliant());
    }

    #[test]
    fn critical_failures_count() {
        let profile = grapheneos_profile();
        let transport = MockTransport::new("pixel-8")
            .with_property("ro.boot.verifiedbootstate", "orange")
            .with_property("ro.crypto.state", "unencrypted")
            .with_command("getenforce", "Permissive")
            .with_property("ro.build.version.security_patch", "2026-03-01")
            .with_property("persist.sys.usb.config", "none")
            .with_property("ro.grapheneos.release_version", "2026030100");

        let report = profile.report(&transport);
        // AVB (critical), encryption (critical), SELinux (critical) = 3 critical failures
        assert_eq!(report.critical_failures().len(), 3);
        assert!(!report.is_compliant());
    }

    // ── Profile from_yaml roundtrip ─────────────────────────────────

    #[test]
    fn from_yaml_const_is_valid() {
        let profile = ComplianceProfile::from_yaml(GRAPHENEOS_HARDENED_PROFILE).unwrap();
        assert_eq!(profile.checks.len(), 6);
    }

    #[test]
    fn adb_transport_send_and_sync_bounds() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AdbTransport>();
    }

    #[test]
    fn profile_check_ids_are_unique() {
        let profile = grapheneos_profile();
        let mut ids = std::collections::HashSet::new();
        for check in &profile.checks {
            assert!(
                ids.insert(check.id()),
                "duplicate check id: {}",
                check.id()
            );
        }
    }

    #[test]
    fn profile_has_at_least_five_checks() {
        let profile = grapheneos_profile();
        assert!(
            profile.checks.len() >= 5,
            "profile should have at least 5 checks, got {}",
            profile.checks.len()
        );
    }

    #[test]
    fn mock_transport_selinux_enforcing_passes() {
        let profile = grapheneos_profile();
        let transport = compliant_transport();
        let results = profile.evaluate_all(&transport);
        let selinux = results.iter().find(|r| r.check_id == "GOS-SEL-001").unwrap();
        assert_eq!(selinux.status, CheckStatus::Pass);
    }

    #[test]
    fn mock_transport_selinux_permissive_fails() {
        let profile = grapheneos_profile();
        let transport = MockTransport::new("pixel-8")
            .with_property("ro.boot.verifiedbootstate", "green")
            .with_property("ro.crypto.state", "encrypted")
            .with_command("getenforce", "Permissive")
            .with_property("ro.build.version.security_patch", "2026-03-01")
            .with_property("persist.sys.usb.config", "none")
            .with_property("ro.grapheneos.release_version", "2026030100");

        let results = profile.evaluate_all(&transport);
        let selinux = results.iter().find(|r| r.check_id == "GOS-SEL-001").unwrap();
        assert_eq!(selinux.status, CheckStatus::Fail);
    }

    #[test]
    fn mock_transport_usb_debugging_enabled_fails() {
        let profile = grapheneos_profile();
        let transport = MockTransport::new("pixel-8")
            .with_property("ro.boot.verifiedbootstate", "green")
            .with_property("ro.crypto.state", "encrypted")
            .with_command("getenforce", "Enforcing")
            .with_property("ro.build.version.security_patch", "2026-03-01")
            .with_property("persist.sys.usb.config", "mtp,adb")
            .with_property("ro.grapheneos.release_version", "2026030100");

        let results = profile.evaluate_all(&transport);
        let usb = results.iter().find(|r| r.check_id == "GOS-USB-001").unwrap();
        assert_eq!(usb.status, CheckStatus::Fail);
    }

    #[test]
    fn empty_property_causes_check_failure() {
        let profile = grapheneos_profile();
        // Transport with no properties at all — all property checks should error
        let transport = MockTransport::new("pixel-8")
            .with_command("getenforce", "Enforcing");

        let results = profile.evaluate_all(&transport);
        // All property-based checks should have Error status (property not found)
        let property_checks: Vec<_> = results
            .iter()
            .filter(|r| r.check_id != "GOS-SEL-001")
            .collect();
        assert!(
            property_checks.iter().all(|r| r.status == CheckStatus::Error),
            "missing properties should produce Error status"
        );
    }

    #[test]
    fn compliance_report_json_serialization_roundtrip() {
        let profile = grapheneos_profile();
        let transport = compliant_transport();
        let report = profile.report(&transport);

        let json = report.to_json().unwrap();
        let parsed: kantei::ComplianceReport = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.profile_name, report.profile_name);
        assert_eq!(parsed.device_id, report.device_id);
        assert_eq!(parsed.total, report.total);
        assert_eq!(parsed.passed, report.passed);
        assert_eq!(parsed.failed, report.failed);
        assert_eq!(parsed.compliance_hash, report.compliance_hash);
        assert!(parsed.is_compliant());
    }
}
