cmake_minimum_required(VERSION 3.20)
set(CMAKE_CXX_STANDARD 20)
project(pwsf_font_hook)

include_directories(${CMAKE_SOURCE_DIR} .)
include_directories(${CMAKE_SOURCE_DIR}/detours/include)
link_libraries(${CMAKE_SOURCE_DIR}/detours/lib/detours.lib)

# 注入 DLL：字体路线 A（sigscan + detour on font_load_xpr）
add_library(dllmain SHARED dllmain.cpp)
target_compile_options(dllmain PUBLIC /GR- /GS-)

# 默认产出 winmm.dll（伪装 winmm 导出，ASI loader 也能扫到）。
# cmake -DPWSF_ASI=ON 改为产出 pwsf.asi（给扫描游戏根目录的 ASI loader）。
option(PWSF_ASI "Emit pwsf.asi instead of winmm.dll" OFF)
if(PWSF_ASI)
  set_target_properties(dllmain PROPERTIES OUTPUT_NAME "pwsf" SUFFIX ".asi")
else()
  set_target_properties(dllmain PROPERTIES OUTPUT_NAME "winmm")
endif()

# 顺手把产物丢到工程根目录，方便部署
add_custom_command(TARGET dllmain POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy
          $<TARGET_FILE:dllmain>
          ${CMAKE_SOURCE_DIR}/$<TARGET_FILE_NAME:dllmain>
  COMMENT "Artifact -> ${CMAKE_SOURCE_DIR}/$<TARGET_FILE_NAME:dllmain>")
