cmake_minimum_required(VERSION 3.15)
project(gnome-keyring-cli  C)

set(CMAKE_C_STANDARD 99)

add_executable(gnome-keyring-cli gnome-keyring-cli.c)

find_package(PkgConfig REQUIRED)
pkg_search_module(GLIB REQUIRED glib-2.0)
#pkg_search_module(GKEYRING REQUIRED gnome-keyring-1)
target_include_directories(gnome-keyring-cli PRIVATE ${GLIB_INCLUDE_DIRS} PRIVATE ${GKEYRING_INCLUDE_DIRS})
target_link_libraries(gnome-keyring-cli ${GLIB_LDFLAGS} ${GKEYRING_LDFLAGS})
