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
}