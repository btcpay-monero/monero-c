cmake_minimum_required(VERSION 3.10)

project(monero-c LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(MONERO_CPP_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../submodules/monero-cpp)
set(MONERO_CPP_BUILD_DIR ${MONERO_CPP_DIR}/build)

set(Boost_NO_BOOST_CMAKE 1)
set(Boost_USE_MULTITHREADED ON)
find_package(Boost REQUIRED COMPONENTS system thread serialization filesystem)
find_package(OpenSSL REQUIRED)

# import shared monero-cpp library
add_library(monero-cpp SHARED IMPORTED)

if (APPLE)
    set(MONERO_CPP_LIB ${MONERO_CPP_BUILD_DIR}/libmonero-cpp.dylib)
elseif (UNIX)
    set(MONERO_CPP_LIB ${MONERO_CPP_BUILD_DIR}/libmonero-cpp.so)
elseif (WIN32)
    set(MONERO_CPP_LIB ${MONERO_CPP_BUILD_DIR}/libmonero-cpp.dll)
endif()

if (WIN32)
    set_target_properties(monero-cpp PROPERTIES
            IMPORTED_LOCATION ${MONERO_CPP_LIB}
            IMPORTED_IMPLIB ${MONERO_CPP_BUILD_DIR}/libmonero-cpp.dll.a
    )
else()
    set_target_properties(monero-cpp PROPERTIES
            IMPORTED_LOCATION ${MONERO_CPP_LIB}
    )
endif()

# import our library
add_library(monero-c SHARED src/monero_abi_bridge.cpp)

# headers
target_include_directories(monero-c PRIVATE
        ${MONERO_CPP_DIR}/src
        ${MONERO_CPP_DIR}/external/monero-project/src
        ${MONERO_CPP_DIR}/external/monero-project/contrib/epee/include
        ${MONERO_CPP_DIR}/external/monero-project/external
        ${MONERO_CPP_DIR}/external/monero-project/external/easylogging++
        ${MONERO_CPP_DIR}/external/monero-project/external/rapidjson/include
)

# link monero-cpp
target_link_libraries(monero-c PRIVATE
        monero-cpp

        Boost::system
        Boost::thread
        Boost::serialization
        Boost::filesystem

        OpenSSL::SSL
        OpenSSL::Crypto
)

if(WIN32)
    target_link_libraries(monero-c PRIVATE Ws2_32)
endif()
