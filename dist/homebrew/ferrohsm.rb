class Ferrohsm < Formula
  desc "Software-based HSM with dual control, JWT auth, and tamper-evident audit logging"
  homepage "https://github.com/foozio/ferrohsm"
  version "0.1.0"
  url "https://github.com/foozio/ferrohsm/releases/download/v0.1.0/ferrohsm-0.1.0-macos.tar.gz"
  sha256 "6a522f21f009ebf72be7be832c75509b866cc840c831269cbe421924491867ed"
  license "MIT"

  def install
    bin.install "hsm-cli"
  end

  test do
    assert_match "FerroHSM", shell_output("#{bin}/hsm-cli --help")
  end
end
