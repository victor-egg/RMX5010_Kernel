make distclean
rm -rf out 
export PATH="$HOME/android/clang-18/bin:$PATH"
export PATH="$HOME/android/build-tools/bin:$PATH"
make -j$(nproc --all) LLVM=1 ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- CC=clang LD=ld.lld HOSTCC=clang HOSTLD=ld.lld O=out KCFLAGS="-O2 -Wno-error" gki_defconfig Image
