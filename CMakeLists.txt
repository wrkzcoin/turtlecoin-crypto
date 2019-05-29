# Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
# Copyright (c) 2018-2019, The TurtleCoin Developers
#
# Please see the included LICENSE file for more information.

cmake_minimum_required(VERSION 3.8)

project(turtlecoin-crypto)

enable_language(C)
enable_language(CXX)

find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
  message(STATUS "Found ccache package... Activating...")
  set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE "${CCACHE_PROGRAM}")
endif()

# Enable c++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build statically
add_definitions(-DSTATICLIB)

if(FORCE_USE_HEAP)
  add_definitions(-DFORCE_USE_HEAP)
  message(STATUS "FORCE_USE_HEAP: ENABLED")
else()
  message(STATUS "FORCE_USE_HEAP: DISABLED")
endif()

if(NO_AES)
  add_definitions(-DNO_AES)
  message(STATUS "HW AES: DISABLED")
else()
  message(STATUS "HW AES: ENABLED")
endif()

if(NO_OPTIMIZED_MULTIPLY_ON_ARM)
  add_definitions(-DNO_OPTIMIZED_MULTIPLY_ON_ARM)
  message(STATUS "OPTIMIZED_ARM_MULTIPLICATION: DISABLED")
else()
  message(STATUS "OPTIMIZED_ARM_MULTIPLICATION: ENABLED")
endif()

## Platform specific code base information is applied here
if(MSVC)
  add_definitions(-DCRYPTO_EXPORTS)
  add_definitions("/bigobj /MP /W3 /GS- /D_CRT_SECURE_NO_WARNINGS /wd4996 /wd4345 /D_WIN32_WINNT=0x0600 /DWIN32_LEAN_AND_MEAN /DGTEST_HAS_TR1_TUPLE=0 /D_VARIADIC_MAX=8 /D__SSE4_1__")
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /STACK:10485760")
  foreach(VAR CMAKE_C_FLAGS_DEBUG CMAKE_CXX_FLAGS_DEBUG CMAKE_C_FLAGS_RELWITHDEBINFO CMAKE_CXX_FLAGS_RELWITHDEBINFO CMAKE_C_FLAGS_RELEASE CMAKE_CXX_FLAGS_RELEASE)
    string(REPLACE "/MD" "/MT" ${VAR} "${${VAR}}")
  endforeach()
  include_directories(SYSTEM ${CMAKE_CURRENT_SOURCE_DIR}/src/platform/msc)
elseif(APPLE)
  include_directories(SYSTEM /usr/include/malloc)
  enable_language(ASM)
endif()

if(NOT MSVC)
  if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    # This option has no effect in glibc version less than 2.20.
    # Since glibc 2.20 _BSD_SOURCE is deprecated, this macro is recomended instead
    add_definitions("-D_DEFAULT_SOURCE -D_GNU_SOURCE")
  endif()

  ## This is here to support building for multiple architecture types... but we all know how well that usually goes...
  set(ARCH default CACHE STRING "CPU to build for: -march value or default")
  if("${ARCH}" STREQUAL "default")
    set(ARCH_FLAG "")
  else()
    set(ARCH_FLAG "-march=${ARCH}")
  endif()

  ## These options generate all those nice warnings we see while building
  set(WARNINGS "-Wall -Wextra -Wpointer-arith -Wvla -Wwrite-strings  -Wno-error=extra -Wno-error=unused-function -Wno-error=sign-compare -Wno-error=strict-aliasing -Wno-error=type-limits -Wno-unused-parameter -Wno-error=unused-variable -Wno-error=undef -Wno-error=uninitialized -Wno-error=unused-result")
  if(CMAKE_C_COMPILER_ID STREQUAL "Clang")
    set(WARNINGS "${WARNINGS} -Wno-error=mismatched-tags -Wno-error=null-conversion -Wno-overloaded-shift-op-parentheses -Wno-error=shift-count-overflow -Wno-error=tautological-constant-out-of-range-compare -Wno-error=unused-private-field -Wno-error=unneeded-internal-declaration -Wno-error=unused-function -Wno-error=missing-braces -Wno-error=unused-command-line-argument")
  else()
    set(WARNINGS "${WARNINGS} -Wlogical-op -Wno-error=maybe-uninitialized -Wno-error=clobbered -Wno-error=unused-but-set-variable")
  endif()

  set(C_WARNINGS "-Waggregate-return -Wnested-externs -Wold-style-definition -Wstrict-prototypes")
  set(CXX_WARNINGS "-Wno-reorder -Wno-missing-field-initializers")

  if(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "aarch64" OR "${LABEL}" STREQUAL "aarch64")
    set(MAES_FLAG "")
    set(CRYPTOPP_AARCH64 ON CACHE BOOL FORCE "Tell CryptoPP that we are building for aarch64")
  elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "x86_64" AND NOT "${LABEL}" STREQUAL "aarch64")
    set(MAES_FLAG "-maes")
  endif()
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11 ${STATICASSERTC_FLAG} ${WARNINGS} ${C_WARNINGS} ${ARCH_FLAG} ${MAES_FLAG}")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 ${STATICASSERTCPP_FLAG} ${WARNINGS} ${CXX_WARNINGS} ${ARCH_FLAG} ${MAES_FLAG}")

  if(APPLE)
      if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
          # Need to build against libc++ instead of libstc++ on apple
          set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -nostdinc++ -I/usr/local/opt/llvm/include/c++/v1 -nodefaultlibs -lc++ -lc++abi -lm -lc -lgcc -lgcc_eh")

          # Need these flags so gcc OSX works on the cryptopp ASM - https://groups.google.com/forum/#!topic/cryptopp-users/po8yO-vYaac
          set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DCRYPTOPP_CLANG_INTEGRATED_ASSEMBLER=1")

      elseif(CMAKE_C_COMPILER_ID STREQUAL "Clang")
          # Need to link against the llvm libc++ library, default is too old for std::filesystem
          set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++ -I/usr/local/opt/llvm/include/c++/v1")
      endif()
  endif()

  if(NOT APPLE)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
  endif()

  ## Setting up DEBUG flags
  if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    set(DEBUG_FLAGS "-g3 -Og -gdwarf-4 -fvar-tracking -fvar-tracking-assignments -fno-inline -fno-omit-frame-pointer")
  else()
    set(DEBUG_FLAGS "-g3 -O0 -fno-omit-frame-pointer")
  endif()

  ## Setting up RELEASE flags
  set(RELEASE_FLAGS "-Ofast -DNDEBUG -Wno-unused-variable")

  if(NOT APPLE)
    # There is a clang bug that does not allow to compile code that uses AES-NI intrinsics if -flto is enabled
    if (CMAKE_C_COMPILER_ID STREQUAL "GNU" AND CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_BUILD_TYPE STREQUAL "Release")
      # On linux, to build in lto mode, check that ld.gold linker is used: 'update-alternatives --install /usr/bin/ld ld /usr/bin/ld.gold HIGHEST_PRIORITY'
      set(CMAKE_AR gcc-ar)
      set(CMAKE_RANLIB gcc-ranlib)
    endif()
  endif()

  ## Set up the normal CMake flags as we've built them
  set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} ${DEBUG_FLAGS}")
  set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} ${DEBUG_FLAGS}")
  set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} ${RELEASE_FLAGS}")
  set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} ${RELEASE_FLAGS}")

  ## Statically link our binaries
  if(NOT APPLE)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libgcc -static-libstdc++")
  endif()
endif()

include_directories(${CMAKE_SOURCE_DIR}/include)

set(BASE_CRYPTO
  src/aesb.c
  src/blake256.c
  src/chacha8.cpp
  src/crypto.cpp
  src/crypto-ops.c
  src/crypto-ops-data.c
  src/groestl.c
  src/hash.c
  src/hash-extra-blake.c
  src/hash-extra-groestl.c
  src/hash-extra-jh.c
  src/hash-extra-skein.c
  src/jh.c
  src/keccak.c
  src/oaes_lib.c
  src/random.cpp
  src/skein.c
  src/slow-hash.c
  src/StringTools.cpp
  src/tree-hash.c
)

add_subdirectory(external)
include_directories(external/argon2/include)
include_directories(external/cxxopts)

add_library(crypto STATIC ${BASE_CRYPTO})

set(SOURCES
  src/turtlecoin-crypto.cpp
)

add_library(turtlecoin-crypto-static STATIC ${SOURCES})
target_link_libraries(turtlecoin-crypto-static crypto argon2)

if(WIN32)
  add_library(turtlecoin-crypto-shared SHARED ${SOURCES})
  target_link_libraries(turtlecoin-crypto-shared crypto argon2)
  target_link_libraries(turtlecoin-crypto-static ws2_32)
  target_link_libraries(turtlecoin-crypto-shared ws2_32)
endif()

set(CRYPTOTEST_SOURCES
  tests/cryptotest.cpp
)

add_executable(cryptotest ${CRYPTOTEST_SOURCES})
target_link_libraries(cryptotest turtlecoin-crypto-static)
set_property(TARGET cryptotest PROPERTY OUTPUT_NAME "cryptotest")
