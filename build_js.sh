#!/bin/sh

# Set up emscripten

if [[ -z "${EMSDK}" ]]; then
  echo "Installing emscripten..."
  echo ""
  if [[ ! -e ./emsdk ]]; then
    git clone https://github.com/juj/emsdk.git
  fi
  cd emsdk && git pull
  ./emsdk install latest && ./emsdk activate latest
  source ./emsdk_env.sh
  cd ..
fi

mkdir -p jsbuild && cd jsbuild && rm -rf *
emconfigure cmake .. -DBUILD_WASM=1 -DBUILD_JS=0
make
emconfigure cmake .. -DBUILD_WASM=0 -DBUILD_JS=1
make
