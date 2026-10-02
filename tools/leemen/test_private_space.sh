#!/bin/sh
set -eu

repository_root=$(cd "$(dirname "$0")/../.." && pwd)
test_directory=$(mktemp -d "${TMPDIR:-/tmp}/leemen-private-space.XXXXXX")
trap 'rm -rf "$test_directory"' EXIT HUP INT TERM
task_cpp_compiler=${CXX:-c++}

"$task_cpp_compiler" \
	-std=c++20 -Wall -Wextra -Werror -pedantic -O0 -g \
	-I "$repository_root/Telegram/SourceFiles" \
	"$repository_root/Telegram/SourceFiles/leemen/private_space_state.cpp" \
	"$repository_root/Telegram/SourceFiles/test/leemen/private_space_state_tests.cpp" \
	-o "$test_directory/private_space_tests"

"$test_directory/private_space_tests"
