cmake_minimum_required(VERSION 3.5)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED 1)

# Set extension name here
set(TARGET_NAME crypto)

set(EXTENSION_NAME ${TARGET_NAME}_extension)
set(LOADABLE_EXTENSION_NAME ${TARGET_NAME}_loadable_extension)

project(${TARGET_NAME})

include_directories(src/include)

# Find OpenSSL
find_package(OpenSSL REQUIRED)
find_package(blake3 CONFIG REQUIRED)

set(EXTENSION_SOURCES
    src/crypto_extension.cpp
    src/crypto_hash.cpp
    src/query_farm_telemetry.cpp
)

build_static_extension(${TARGET_NAME} ${EXTENSION_SOURCES})
build_loadable_extension(${TARGET_NAME} " " ${EXTENSION_SOURCES})

# Link OpenSSL to both static and loadable extensions
target_link_libraries(${EXTENSION_NAME} OpenSSL::SSL OpenSSL::Crypto BLAKE3::blake3)
target_link_libraries(${LOADABLE_EXTENSION_NAME} OpenSSL::SSL OpenSSL::Crypto BLAKE3::blake3)

install(
  TARGETS ${EXTENSION_NAME}
  EXPORT "${DUCKDB_EXPORT_SET}"
  LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
  ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")
