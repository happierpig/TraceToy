cmake_minimum_required(VERSION 2.6)
set(DynamoRIO_DIR "/home/dreamer/Desktop/Mycode/dynamorio/build/cmake")
set(CMAKE_CXX_STANDARD 11)

if (NOT "${DynamoRIO_DIR}" STREQUAL "")
	project(threadTracer)

	set(output_dir "${PROJECT_BINARY_DIR}/bin")
	set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${output_dir}")
	set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}")
	set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${output_dir}")

	find_package(DynamoRIO)
	if (NOT DynamoRIO_FOUND)
		message(FATAL_ERROR  "DynamoRIO package required to build")
	endif (NOT DynamoRIO_FOUND)

    include_directories("/home/dreamer/Desktop/Mycode/dynamorio/build/clients/include/drmemtrace/")
    add_executable(threadTracer main.cpp)
    use_DynamoRIO_drmemtrace(threadTracer)
    target_link_libraries(threadTracer drmemtrace_analyzer drmemtrace_reuse_distance)
endif ()
