# frozen_string_literal: true
class Ferrohsm < Formula
  desc "Software-based Hardware Security Module implemented in Rust"
  homepage "https://github.com/foozio/ferrohsm"
  url "https://github.com/foozio/ferrohsm/releases/download/v0.4.0/ferrohsm-0.4.0-linux.tar.gz"
  sha256 "9578d80bf04acd9c63912ccd2f214fc4a84f5f29d33b84ec0c1e8799eb7b04d5"
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