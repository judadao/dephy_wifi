if(CONFIG_DEPHY_WIFI)
  zephyr_library_named(dephy_wifi)
  zephyr_library_sources(../src/wifi.c)
  zephyr_library_include_directories(../include)
  zephyr_include_directories(../include)
endif()

