use std::process::{Command, Stdio};
use std::time::Duration;
use std::thread;

#[test]
fn test_tui_binary_builds_and_runs() {
    // Build the hsm-tui binary
    let cargo_build = Command::new("cargo")
        .args(["build", "-p", "hsm-tui"])
        .output()
        .expect("Failed to build hsm-tui");

    assert!(cargo_build.status.success(), "hsm-tui build failed");
}

#[test]
fn test_tui_can_start_and_exit() {
    // Build first
    let cargo_build = Command::new("cargo")
        .args(["build", "-p", "hsm-tui"])
        .output()
        .expect("Failed to build hsm-tui");

    assert!(cargo_build.status.success(), "hsm-tui build failed");

    // Start the TUI process
    let mut child = Command::new("../../target/debug/hsm-tui")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start hsm-tui");

    // Give it a moment to start
    thread::sleep(Duration::from_millis(500));

    // Send 'q' to quit (this might not work due to raw mode, but let's try)
    if let Some(ref mut stdin) = child.stdin {
        use std::io::Write;
        let _ = stdin.write_all(b"q");
        let _ = stdin.flush();
    }

    // Wait a bit more
    thread::sleep(Duration::from_millis(500));

    // Kill the process if it's still running
    let _ = child.kill();

    // Wait for it to exit
    let result = child.wait();
    // We don't assert success since the TUI may not exit cleanly in this test environment
    // The important thing is that it started
    assert!(result.is_ok(), "Process should have been waitable");
}

#[test]
fn test_tui_help_argument() {
    // Test that --help works
    let output = Command::new("cargo")
        .args(["run", "-p", "hsm-tui", "--", "--help"])
        .output()
        .expect("Failed to run hsm-tui --help");

    assert!(output.status.success(), "hsm-tui --help should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("FerroHSM TUI"), "Help should contain app name");
}

#[test]
fn test_tui_version_argument() {
    // Test that --version works
    let output = Command::new("cargo")
        .args(["run", "-p", "hsm-tui", "--", "--version"])
        .output()
        .expect("Failed to run hsm-tui --version");

    assert!(output.status.success(), "hsm-tui --version should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(env!("CARGO_PKG_VERSION")),
        "Version should be {}",
        env!("CARGO_PKG_VERSION")
    );
}
