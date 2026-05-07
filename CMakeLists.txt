cmake_minimum_required(VERSION 3.16)
project(HM_MPC C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Options
add_compile_options(-O3)

option(ENABLE_SANITIZERS "Enable ASan/UBSan" OFF)

if(ENABLE_SANITIZERS)
  add_library(sanitizers INTERFACE)
  target_compile_options(sanitizers INTERFACE
    -fsanitize=address,undefined
    -fno-omit-frame-pointer
    -g
  )
  target_link_options(sanitizers INTERFACE
    -fsanitize=address,undefined
  )
endif()



# Dependencies
find_package(OpenMP REQUIRED)
find_package(OpenSSL REQUIRED)

# Add subdirectories
add_subdirectory(src)

enable_testing()
add_subdirectory(tests)
