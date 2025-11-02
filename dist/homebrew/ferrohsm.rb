# frozen_string_literal: true
class Ferrohsm < Formula
  desc "Software-based Hardware Security Module implemented in Rust"
  homepage "https://github.com/foozio/ferrohsm"
  url "https://github.com/foozio/ferrohsm/releases/download/v0.4.0/ferrohsm-0.4.0-macos.tar.gz"
  sha256 "42c81fe7febf52766f291a7cecb32e1c162d2797a02e0a838a886b7fed9ee4d4"
  version "0.4.0"
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
