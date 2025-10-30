# frozen_string_literal: true
class Ferrohsm < Formula
  desc "Software-based HSM with dual control, JWT auth, and tamper-evident audit logging"
  homepage "https://github.com/foozio/ferrohsm"
  url "https://github.com/foozio/ferrohsm/releases/download/v0.2.1/ferrohsm-0.2.1-linux-x86_64.tar.gz"
  sha256 "2c8eaae6b753c5d4dc89477f3409378f2cdc542a55112d368e4a0d2e1aea0a6b"
  version "0.2.1"
  license "MIT"

  def install
    bin.install "hsm-cli"
    bin.install "hsm-server"
  end

  test do
    assert_match "FerroHSM", shell_output("#{bin}/hsm-cli --help")
    assert_match "FerroHSM", shell_output("#{bin}/hsm-server --help")
  end
end