cmake_minimum_required (VERSION 3.5...3.31)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

find_package(Sodium 1.0.14 REQUIRED)

file(GLOB HEADERS "include/*.h")
file(GLOB SRC "src/*.cpp")

add_library(EmbeddedJSONSignature STATIC ${HEADERS} ${SRC})
target_link_libraries(EmbeddedJSONSignature PRIVATE unofficial-sodium::sodium)
target_include_directories(EmbeddedJSONSignature PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
