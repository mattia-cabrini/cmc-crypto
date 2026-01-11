cmake_minimum_required(VERSION 3.10)

project(cmc-crypto)

if(NOT CMAKE_BUILD_TYPE)
	message("Setting BUILD_TYPE to Release")
	set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

find_program(CLANG_FORMAT_EXECUTABLE NAMES clang-format)
if (NOT CLANG_FORMAT_EXECUTABLE)
  message(FATAL_ERROR "clang-format not found.")
endif()

string(TOLOWER ${CMAKE_BUILD_TYPE} build_type)

set(CMAKE_C_FLAGS_RELEASE "")
set(CMAKE_C_FLAGS_DEBUG "")

set(SRC
	main.c random.c aes.c io.c bigint.c rsa.c
)

set(H
	random.h aes.h error.h block_cipher.h io.h bigint.h types.h rsa.h
)

set(FILES_FMT ${SRC} ${H})
set(FMT_CONFIG "clang-format")

add_executable(cmc-crypto ${SRC})

# This project is meant to be fun!
# The C standard is C89, strict ANSI.
# set_property(TARGET cmc-crypto PROPERTY C_STANDARD 90)
# set_property(TARGET cmc-crypto PROPERTY C_EXTENSIONS OFF)
target_compile_options(cmc-crypto PRIVATE -std=c89)

if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
	message("Compiler is supported.")
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
	message("Compiler is supported.")
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
	message(FATAL_ERROR "Your compiler is not supported.")
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(GPGME REQUIRED gpgme)

target_link_libraries(cmc-crypto PRIVATE ${GPGME_LIBRARIES})

target_compile_options(cmc-crypto PRIVATE 
	-pedantic -pedantic-errors -Werror
	-fno-common -fPIC -Wfatal-errors

	# Style
	# -Wdeclaration-after-statement -Werror=declaration-after-statement
)

# Basic Warnings
target_compile_options(cmc-crypto PRIVATE 
	-Wall
	-Wextra
	-Wabsolute-value
	-Waddress
	-Waddress-of-packed-member
	-Waggregate-return
	-Walloca
	-Wshadow
	-Wpointer-arith
	-Wcast-align
	-Wstrict-prototypes
	-Wmissing-prototypes
	-Wold-style-definition
	-Wformat=2
	-Wformat-truncation
	-Wundef
	-Wswitch-enum
	-Wbad-function-cast
	-Wconversion
	-Wsign-conversion
	-Wdouble-promotion
)

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
	# Basic Warnings
	target_compile_options(cmc-crypto PRIVATE 
		-Waggressive-loop-optimizations
		-Walloc-size-larger-than=1048576
		-Walloc-zero
		-Warith-conversion
		-Warray-bounds=2
		-Warray-compare
		-Wstringop-overflow
		-Walloca-larger-than=2048
	)

	# Analyzer
	target_compile_options(cmc-crypto PRIVATE 
		-fanalyzer 
		-Wanalyzer-allocation-size
		-Wanalyzer-deref-before-check
		-Wanalyzer-double-fclose
		-Wanalyzer-double-free
		-Wanalyzer-exposure-through-output-file
		-Wanalyzer-exposure-through-uninit-copy
		-Wanalyzer-fd-access-mode-mismatch
		-Wanalyzer-fd-double-close
		-Wanalyzer-fd-leak
		-Wanalyzer-fd-phase-mismatch
		-Wanalyzer-fd-type-mismatch
		-Wanalyzer-fd-use-after-close
		-Wanalyzer-fd-use-without-check
		-Wanalyzer-file-leak
		-Wanalyzer-free-of-non-heap
		-Wanalyzer-imprecise-fp-arithmetic
		-Wanalyzer-infinite-recursion
		-Wanalyzer-jump-through-null
		-Wanalyzer-malloc-leak
		-Wanalyzer-mismatching-deallocation
		-Wanalyzer-null-argument
		-Wanalyzer-null-dereference
		-Wanalyzer-out-of-bounds
		-Wanalyzer-possible-null-argument
		-Wanalyzer-possible-null-dereference
		-Wanalyzer-putenv-of-auto-var
		-Wanalyzer-shift-count-negative
		-Wanalyzer-shift-count-overflow
		-Wanalyzer-stale-setjmp-buffer
		-Wanalyzer-tainted-allocation-size
		-Wanalyzer-tainted-array-index
		-Wanalyzer-tainted-assertion
		-Wanalyzer-tainted-divisor
		-Wanalyzer-tainted-offset
		-Wanalyzer-tainted-size
		-Wno-analyzer-too-complex
		-Wanalyzer-unsafe-call-within-signal-handler
		-Wanalyzer-use-after-free
		-Wanalyzer-use-of-pointer-in-stale-stack-frame
		-Wanalyzer-use-of-uninitialized-value
		-Wanalyzer-va-arg-type-mismatch
		-Wanalyzer-va-list-exhausted
		-Wanalyzer-va-list-leak
		-Wanalyzer-va-list-use-after-va-end
		-Wanalyzer-write-to-const
		-Wanalyzer-write-to-string-literal
	)
endif()

if (build_type STREQUAL release)
	# Release Specific Flags
	target_compile_options(cmc-crypto PRIVATE -O2 -flto -DNDEBUG)
elseif (build_type STREQUAL debug)
	#Debug Specific Flags
	target_compile_options(cmc-crypto PRIVATE -O0 -g -DDEBUG)
endif()

set(FORMAT_STAMP ${CMAKE_CURRENT_BINARY_DIR}/.format-stamp)

add_custom_command(
	OUTPUT ${FORMAT_STAMP}
	COMMAND ${CMAKE_COMMAND} -E echo "==> clang-format on all .c and .h"
	COMMAND ${CLANG_FORMAT_EXECUTABLE} -i -style=file:${FMT_CONFIG} ${FILES_FMT}
	COMMAND ${CMAKE_COMMAND} -E touch ${FORMAT_STAMP}
	DEPENDS ${FILES_FMT}
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
	VERBATIM
)

add_custom_target(fmt DEPENDS ${FORMAT_STAMP})
add_dependencies(cmc-crypto fmt)

