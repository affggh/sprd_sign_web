# SPRD Signature on web
This is a simple sprd boot/recovery or etc image signature static web    
## build on msys2/ucrt64
```sh
# make sure install all toolchains
pacman -S pactoys
pacboy -S emscripten cmake ninja
pacman -S patch

# build
./build.sh
```

