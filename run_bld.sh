(
cd build
options="--enable-version3 --enable-libx264 --enable-nonfree --enable-gpl"
options="$options --enable-libdrm --enable-rkmpp"
options="$options --disable-decoder=wmapro --disable-decoder=xma1 --disable-decoder=xma2"
../configure $options
)
