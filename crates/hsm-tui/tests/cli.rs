#[cfg(test)]
mod tests {
    use assert_cmd::assert::OutputAssertExt;
    use predicates::prelude::*;
    use escargot::CargoBuild;

    #[test]
    fn test_help_output() {
        let mut cmd = CargoBuild::new().bin("hsm-tui").run().unwrap().command();
        cmd.arg("--help");
        cmd.assert()
            .success()
            .stdout(predicate::str::contains("FerroHSM TUI"))
            .stdout(predicate::str::contains("Text-based User Interface for FerroHSM"));
    }

    #[test]
    fn test_version_output() {
        let mut cmd = CargoBuild::new().bin("hsm-tui").run().unwrap().command();
        cmd.arg("--version");
        cmd.assert()
            .success()
            .stdout(predicate::str::contains("0.2.1"));
    }

    #[test]
    fn test_binary_exists() {
        // Test that the binary can be executed and returns a proper error code
        // when run without a terminal (which is expected)
        let mut cmd = CargoBuild::new().bin("hsm-tui").run().unwrap().command();
        cmd.assert()
            .failure(); // Expected to fail without a terminal
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
            .stdout(predicate::str::contains("[default: https://localhost:8443]"));
    }
}