cmake_minimum_required(VERSION 3.16)
project(driver_touchframe CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

add_library(driver_touchframe SHARED src/driver.cpp src/udp_source.cpp src/skeleton.cpp
  src/cv_tracker.cpp src/cv_clone.cpp src/cv_source.cpp)
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

# Calibration tool (an OpenVR client) links SteamVR's own libopenvr_api.so on the Frame.
add_executable(tf_calibrate src/calibrate.cpp)
target_include_directories(tf_calibrate PRIVATE vendor)
target_link_directories(tf_calibrate PRIVATE /opt/steamvr/bin/linuxarm64)
target_link_libraries(tf_calibrate PRIVATE openvr_api)
set_target_properties(tf_calibrate PROPERTIES
  BUILD_RPATH /opt/steamvr/bin/linuxarm64
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/touchframe/bin/linuxarm64)

# Skeleton check tool: compares the driver's hand poses with SteamVR's reference poses.
add_executable(tf_skeldump src/skeldump.cpp src/skeleton.cpp)
target_include_directories(tf_skeldump PRIVATE src vendor)
target_link_directories(tf_skeldump PRIVATE /opt/steamvr/bin/linuxarm64)
target_link_libraries(tf_skeldump PRIVATE openvr_api)
set_target_properties(tf_skeldump PROPERTIES
  BUILD_RPATH /opt/steamvr/bin/linuxarm64
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/touchframe/bin/linuxarm64)
