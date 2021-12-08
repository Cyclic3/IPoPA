project(ipopa)

set(CMAKE_CXX_STANDARD 20)

add_executable(ipopad src/main.cpp)
target_link_libraries(ipopad pthread -static)
