# frozen_string_literal: true
class Ferrohsm < Formula
  desc "Software-based HSM with dual control, JWT auth, and tamper-evident audit logging"
  homepage "https://github.com/foozio/ferrohsm"
  url "https://github.com/foozio/ferrohsm/releases/download/v0.2.1/ferrohsm-0.2.1-macos.tar.gz"
  sha256 "93138a8d3d580c1c427bb31f34167cb0fbe6cada132716d5199ef74ace89a53a"
  version "0.2.1"
  license "MIT"

  def install
    bin.install "hsm-cli"
  end

  test do
    assert_match "FerroHSM", shell_output("#{bin}/hsm-cli --help")
  end
end
