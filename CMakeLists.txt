cmake_minimum_required(VERSION 3.5)
project(vpnp2p LANGUAGES C)
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-stack-protector ")

add_subdirectory(libuv)

add_executable(vpnp2p main.c)
#add_executable(vpnp2p_mini main_mini.c)
target_link_libraries(vpnp2p uv)
#target_link_libraries(vpnp2p_mini uv)
