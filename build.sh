#!/bin/bash
set -e # Exit immediately if any command exits with a non-zero status

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$script_dir"

clean=0
sanitize=0
build_tests=0
build_examples=0

helpFunction()
{
  echo ""
  echo "Usage: $0 [-c] [-s] [-t] [-e] [-h]"
  echo -e "\t-c If present, starts the building phase from a clean state."
  echo -e "\t-s If present, instrument build with address sanitizer."
  echo -e "\t-t If present, build tests."
  echo -e "\t-e If present, build examples."
  echo -e "\t-h Print the script help message."
  exit 1
}

while getopts "chste" opt
do
   case "$opt" in
      c )
        clean=1       ;;
      s )
        sanitize=1     ;;
      t )
        build_tests=1  ;;
      e )
        build_examples=1 ;;
      h ) helpFunction ;;
      ? ) helpFunction ;;
   esac
done

if [[ "$clean" -eq 1 ]]; then
  cmake -E rm -rf build
fi

sanitize_opt=OFF
build_tests_opt=OFF
build_examples_opt=OFF

if [[ "$sanitize" -eq 1 ]]; then
  sanitize_opt=ON
fi

if [[ "$build_tests" -eq 1 ]]; then
  build_tests_opt=ON
fi

if [[ "$build_examples" -eq 1 ]]; then
  build_examples_opt=ON
fi

cmake_args=(
  -S .
  -B build
  -DVERBOSE=OFF
  -DENABLE_SANITIZERS="$sanitize_opt"
  -DHM_MPC_BUILD_TESTS="$build_tests_opt"
  -DHM_MPC_BUILD_EXAMPLES="$build_examples_opt"
)

cmake "${cmake_args[@]}"
cmake --build build
