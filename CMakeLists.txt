cmake_minimum_required(VERSION 3.22.1)

project(secureapi LANGUAGES CXX)

# Use C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Enable hidden visibility for symbols (security and size optimization)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN ON)

# Define the shared library
add_library(${PROJECT_NAME} SHARED
        native-lib.cpp
        security_utils.cpp
        whitelist_utils.cpp
)

# Android log library
find_library(LOG_LIB log REQUIRED)

# Link libraries
target_link_libraries(${PROJECT_NAME}
        PRIVATE
        ${LOG_LIB}
)

# Optional: include directories if needed
# target_include_directories(${PROJECT_NAME} PRIVATE include)
