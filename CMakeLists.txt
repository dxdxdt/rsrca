cmake_minimum_required(VERSION 3.19)

project(pmtu-attack VERSION 0.0.0 LANGUAGES C)

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
	-Werror=implicit-function-declaration
	-D_GNU_SOURCE)

add_executable(pmtu-attack src/pmtu-attack.c src/rnd_well512.c)

install(TARGETS pmtu-attack)
