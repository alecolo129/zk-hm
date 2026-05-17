#!/bin/bash
set -e # Exit immediately if any command exits with a non-zero status

set -x
n_processes=$(nproc)
set +x

helpFunction()
{
  echo ""
  echo "Usage: $0 -c -h"
  echo -e "\t-c If present, starts the building phase from a clean state."
  echo -e "\t-s If present, instrument build with address sanitizer."
  echo -e "\t-h Print the script help message."
  exit 1
}

while getopts "chs" opt
do
   case "$opt" in
      c )
        rm -rf build/* ;;
      s )
        sanitize=1     ;;
      h ) helpFunction ;;
      ? ) helpFunction ;;
   esac
done

if [[ -v sanitize ]]; then
  cmake -S . -B build -G Ninja -DENABLE_SANITIZERS=ON
else
  cmake -S . -B build -G Ninja
fi
cmake --build build
