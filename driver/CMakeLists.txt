cmake_minimum_required(VERSION 3.16)
project(driver_touchframe CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

add_library(driver_touchframe SHARED src/driver.cpp src/udp_source.cpp)
target_include_directories(driver_touchframe PRIVATE src vendor)
target_compile_options(driver_touchframe PRIVATE -Wall -Wextra -Wno-unused-parameter)
target_link_libraries(driver_touchframe PRIVATE pthread)
# Static libstdc++ so the driver doesn't depend on the system's version matching SteamVR's runtime.
target_link_options(driver_touchframe PRIVATE -static-libstdc++ -static-libgcc -Wl,--no-undefined)
set_target_properties(driver_touchframe PROPERTIES PREFIX ""
  LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/touchframe/bin/linuxarm64)

# Stage the driver folder (manifest + resources) next to the binary.
add_custom_command(TARGET driver_touchframe POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_SOURCE_DIR}/touchframe ${CMAKE_BINARY_DIR}/touchframe)
