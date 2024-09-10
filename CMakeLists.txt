cmake_minimum_required(VERSION 3.19)

project(pmtu-attack VERSION 0.0.0 LANGUAGES C)

include(GNUInstallDirs)

add_compile_options(
	-Wall
	-Wextra
	-Wno-unused-parameter
	-Werror=implicit-function-declaration
	-D_GNU_SOURCE)

add_executable(pmtu-attack src/pmtu-attack.c)

install(TARGETS pmtu-attack)
