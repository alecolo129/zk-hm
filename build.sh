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
  echo -e "\t-h Print the script help message."
  exit 1
}

while getopts "ch" opt
do
   case "$opt" in
      c )
        rm -rf build/* ;;
      h ) helpFunction ;;
      ? ) helpFunction ;;
   esac
done

cmake -S . -B build -G Ninja
cmake --build build
