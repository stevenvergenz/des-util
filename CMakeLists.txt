cmake_minimum_required (VERSION 2.6)
project (des)

# add the des algorithm code to be compiled
add_library (algorithms des.cpp)

# build and link the final binary
add_executable (des main.cpp)
target_link_libraries(des algorithms)
