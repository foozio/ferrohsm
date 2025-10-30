#[cfg(test)]
mod tests {
    use assert_cmd::Command;
    use predicates::prelude::*;

    #[test]
    fn test_help_output() {
        let mut cmd = Command::cargo_bin("hsm-tui").unwrap();
        cmd.arg("--help");
        cmd.assert()
            .success()
            .stdout(predicate::str::contains("FerroHSM TUI"))
            .stdout(predicate::str::contains("Text-based User Interface for FerroHSM"));
    }

    #[test]
    fn test_version_output() {
        let mut cmd = Command::cargo_bin("hsm-tui").unwrap();
        cmd.arg("--version");
        cmd.assert()
            .success()
            .stdout(predicate::str::contains("0.2.1"));
    }

    #[test]
    fn test_binary_exists() {
        // Test that the binary can be executed and returns a proper error code
        // when run without a terminal (which is expected)
        let mut cmd = Command::cargo_bin("hsm-tui").unwrap();
        cmd.assert()
            .failure(); // Expected to fail without a terminal
    }
    
    #[test]
    fn test_endpoint_argument() {
        let mut cmd = Command::cargo_bin("hsm-tui").unwrap();
        cmd.arg("--endpoint")
            .arg("https://test.example.com")
            .arg("--help"); // Add help to prevent the app from trying to run
        cmd.assert()
            .success()
            .stdout(predicate::str::contains("https://test.example.com"));
    }
}