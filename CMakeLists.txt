cmake_minimum_required(VERSION 3.19)

project(rsrca VERSION 0.0.0 LANGUAGES C CXX)

include(CheckSymbolExists)
include(GNUInstallDirs)

add_compile_options(
	# For significant performance boost in PRNG.
	# Not a good idea if the project needs to be packaged. This is just a POC,
	# so...
	-mtune=native
	-march=native
	# -mavx2
	-Wall
	-Wextra
	-Wno-unused-parameter
	$<$<COMPILE_LANGUAGE:C>:-Werror=implicit-function-declaration>
	-D_GNU_SOURCE)

check_symbol_exists(_rdrand64_step immintrin.h HAVE_RDRAND64_STEP)

add_executable(rsrca
	src/rsrca.c
	src/dns-utils.c
	src/rnd_cpp.cpp
	src/inetchksm.c)
add_executable(rsrca-rnd
	src/rsrca-rnd.c
	src/rnd_well512.c
	# src/rnd_rdrnd.c
	src/rnd_cpp.cpp)
add_executable(rsrca-ns
	src/rsrca-ns.c
	src/dns-utils.c
	src/rnd_cpp.cpp)
add_executable(rsrca-echo src/rsrca-echo.c)
if (CMAKE_SYSTEM MATCHES Windows)
	target_link_libraries(rsrca-echo ws2_32)
endif()

install(TARGETS rsrca rsrca-rnd rsrca-ns rsrca-echo)
