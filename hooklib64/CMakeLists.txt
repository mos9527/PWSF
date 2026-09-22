cmake_minimum_required(VERSION 3.20)
set(CMAKE_CXX_STANDARD 20)
project(pwsf_font_hook)

include_directories(${CMAKE_SOURCE_DIR} .)
include_directories(${CMAKE_SOURCE_DIR}/detours/include)
link_libraries(${CMAKE_SOURCE_DIR}/detours/lib/detours.lib)

# 注入 DLL：字体路线 A（sigscan + detour on font_load_xpr）
add_library(dllmain SHARED dllmain.cpp)
target_compile_options(dllmain PUBLIC /GR- /GS-)

# 诊断：AllocConsole + printf。默认关 —— 发布包不该弹控制台；
# 排查时 cmake -DPWSF_DEBUG=ON 重编。
option(PWSF_DEBUG "Alloc a console and print hook diagnostics" OFF)
if(PWSF_DEBUG)
  target_compile_definitions(dllmain PRIVATE PWSF_DEBUG=1)
endif()

# 产物恒为 pwsf.dll。装进游戏时它叫 winmm.dll 还是 pwsf.asi，是安装侧的事
# （pwsf.install --hook winmm|asi|none / install.bat 问用户），构建不掺和。
set_target_properties(dllmain PROPERTIES OUTPUT_NAME "pwsf")

# 顺手把产物丢到工程根目录，方便部署
add_custom_command(TARGET dllmain POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy
          $<TARGET_FILE:dllmain>
          ${CMAKE_SOURCE_DIR}/$<TARGET_FILE_NAME:dllmain>
  COMMENT "Artifact -> ${CMAKE_SOURCE_DIR}/$<TARGET_FILE_NAME:dllmain>")
