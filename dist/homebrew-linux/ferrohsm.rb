# frozen_string_literal: true
class Ferrohsm < Formula
  desc "Software-based Hardware Security Module implemented in Rust"
  homepage "https://github.com/foozio/ferrohsm"
  url "https://github.com/foozio/ferrohsm/releases/download/v0.3.0/ferrohsm-0.3.0-linux.tar.gz"
  sha256 "6ba9e8b3f4d0e514b35d5dadc8401dd1d3733a5835e453af663787a41cdf5fb6"
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