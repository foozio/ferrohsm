# frozen_string_literal: true
class Ferrohsm < Formula
  desc "Software-based Hardware Security Module implemented in Rust"
  homepage "https://github.com/foozio/ferrohsm"
  url "https://github.com/foozio/ferrohsm/releases/download/v0.3.0/ferrohsm-0.3.0-macos.tar.gz"
  sha256 "852b89a1cb835a18e6ec5f585b0d5d7bbe821855b6b5318ef3b8e61f961ab59b"
  version "0.3.0"
  license "MIT"

  def install
    bin.install "hsm-cli" => "ferrohsm"
    bin.install "hsm-server"
    bin.install "hsm-tui"
  end

  test do
    assert_match "hsm-cli", shell_output("#{bin}/ferrohsm --help")
  end
end
