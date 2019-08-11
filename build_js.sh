#!/bin/sh

# Set up emscripten

# If you need React Native Support, you'll need to edit emsdk/fastcomp/emscripten/src/shell.js to include this AFTER #endif // ENVIRONMENT
#
#
# /* React native should be treated like a node environment */
# if (typeof navigator !== 'undefined' && typeof navigator.product === 'string' && navigator.product.toLowerCase() === 'reactnative') {
#   ENVIRONMENT_IS_NODE = true;
#   ENVIRONMENT_IS_WEB = false;
#   ENVIRONMENT_IS_WORKER = false;
# }
#
#
#

if [[ -z "${EMSDK}" ]]; then
  echo "Installing emscripten..."
  echo ""
  if [[ ! -e ./emsdk ]]; then
    git clone https://github.com/emscripten-core/emsdk
  fi
  cd emsdk && git pull
  ./emsdk install latest && ./emsdk activate latest
  source ./emsdk_env.sh
  cd ..
fi

mkdir -p jsbuild && cd jsbuild && rm -rf *
emconfigure cmake .. -DNO_AES=1 -DARCH=default -DBUILD_WASM=1 -DBUILD_JS=0
make
emconfigure cmake .. -DNO_AES=1 -DARCH=default -DBUILD_WASM=0 -DBUILD_JS=1
make
