#!/usr/bin/sh


# Stuck on msys environment
unset CC CXX
unset PKG_CONFIG_PATH PKG_CONFIG_SYSTEM_INCLUDE_PATH PKG_CONFIG_SYSTEM_LIBRARY_PATH

# Emscripten
if [ -d "build" ]; then
    echo "Remove exist build dir."
    rm -rf build
fi

emcmake cmake -B build -G Ninja -DCMAKE_BUILD_TYPE="Release"
cmake --build build