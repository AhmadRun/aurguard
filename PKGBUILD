# Maintainer: AhmadRun
pkgname=aurguard
pkgver=0.1.0
pkgrel=1
pkgdesc="Self-updating malware scanner for AUR packages"
arch=('any')
url="https://github.com/AhmadRun/aurguard"
license=('MIT')
depends=('python' 'pacman')
optdepends=('libnotify: desktop notifications')
makedepends=('python-build' 'python-installer' 'python-setuptools' 'python-wheel')
source=("$pkgname-$pkgver.tar.gz::$url/archive/v$pkgver.tar.gz")
sha256sums=('SKIP')

build() {
  cd "$pkgname-$pkgver"
  python -m build --wheel --no-isolation
}

package() {
  cd "$pkgname-$pkgver"
  python -m installer --destdir="$pkgdir" dist/*.whl
  install -Dm644 systemd/aurguard-* -t "$pkgdir/usr/lib/systemd/user/"
  install -Dm644 LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
}
