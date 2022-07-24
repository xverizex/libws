cmake_minimum_required (VERSION 3.22)

project (ws)

include (FindPkgConfig)

add_library (ws SHARED ws.c)

pkg_check_modules (ZLIB "zlib")
pkg_check_modules (OPENSSL "openssl")

target_include_directories (ws PUBLIC
	${ZLIB_INCLUDE_DIRS}
	${OPENSSL_INCLUDE_DIRS}
	)

target_link_libraries (ws PUBLIC
	${ZLIB_LIBRARIES}
	${OPENSSL_LIBRARIES}
	)
