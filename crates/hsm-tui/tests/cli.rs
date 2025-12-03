#[cfg(test)]
mod tests {
    use assert_cmd::assert::OutputAssertExt;
    use escargot::CargoBuild;
    use predicates::prelude::*;

    #[test]
    fn test_help_output() {
        let mut cmd = CargoBuild::new().bin("hsm-tui").run().unwrap().command();
        cmd.arg("--help");
        cmd.assert()
            .success()
            .stdout(predicate::str::contains("FerroHSM TUI"))
            .stdout(predicate::str::contains(
                "Text-based User Interface for FerroHSM",
            ));
    }

    #[test]
    fn test_version_output() {
        let mut cmd = CargoBuild::new().bin("hsm-tui").run().unwrap().command();
        cmd.arg("--version");
        cmd.assert()
            .success()
            .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn test_binary_exists() {
        // Test that the binary can be executed and returns a proper error code
        // when run without a terminal (which is expected)
        let mut cmd = CargoBuild::new().bin("hsm-tui").run().unwrap().command();
        let output = cmd.output().expect("Failed to execute hsm-tui binary");
        let exit_code = output.status.code();
        assert!(
            matches!(exit_code, Some(0) | Some(1)),
            "Unexpected exit status: {:?}\nstderr: {:?}",
            exit_code,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn test_endpoint_argument() {
        let mut cmd = CargoBuild::new().bin("hsm-tui").run().unwrap().command();
        cmd.arg("--endpoint")
            .arg("https://test.example.com")
            .arg("--help"); // Add help to prevent the app from trying to run
        cmd.assert()
            .success()
            .stdout(predicate::str::contains("--endpoint <ENDPOINT>"))
            .stdout(predicate::str::contains(
                "[default: https://localhost:8443]",
            ));
    }
}
