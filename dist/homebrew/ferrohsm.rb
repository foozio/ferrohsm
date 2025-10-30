# frozen_string_literal: true
class Ferrohsm < Formula
  desc "Software-based Hardware Security Module implemented in Rust"
  homepage "https://github.com/foozio/ferrohsm"
  url "https://github.com/foozio/ferrohsm/releases/download/v0.2.1/ferrohsm-0.2.1-macos.tar.gz"
  sha256 "e421211b1f9f8a2517f1de3960ae20a82bf7c363dddcbd4402a249cecb6e505e"
  version "0.2.1"
  license "MIT"

  def install
    bin.install "hsm-cli" => "ferrohsm"
  end

  test do
    assert_match "hsm-cli", shell_output("#{bin}/ferrohsm --help")
  end
end
