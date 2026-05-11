cmake_minimum_required(VERSION 3.10)

project(NativeLib LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(MONERO_CPP_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../submodules/monero-cpp)
set(MONERO_CPP_BUILD_DIR ${MONERO_CPP_DIR}/build)

# import shared monero-cpp library
add_library(monero-cpp SHARED IMPORTED)

set_target_properties(monero-cpp PROPERTIES
        IMPORTED_LOCATION ${MONERO_CPP_BUILD_DIR}/libmonero-cpp.so
)

# import our library
add_library(NativeLib SHARED src/monero_abi_bridge.cpp)

# headers
target_include_directories(NativeLib PRIVATE
        ${MONERO_CPP_DIR}/src
        ${MONERO_CPP_DIR}/external/monero-project/src
        ${MONERO_CPP_DIR}/external/monero-project/contrib/epee/include
        ${MONERO_CPP_DIR}/external/monero-project/external
        ${MONERO_CPP_DIR}/external/monero-project/external/easylogging++
        ${MONERO_CPP_DIR}/external/monero-project/external/rapidjson/include
)

# link monero-cpp
target_link_libraries(NativeLib PRIVATE
        monero-cpp
)