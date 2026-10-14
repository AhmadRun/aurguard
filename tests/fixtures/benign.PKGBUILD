# Maintainer: someone
pkgname=hello-git
pkgver=1.0
source=("git+https://github.com/foo/hello.git")
sha256sums=('SKIP')
# curl https://x | sh   <- commented out, must not match
build() { cd hello; make; }
package() { cd hello; make DESTDIR="$pkgdir" install; }
