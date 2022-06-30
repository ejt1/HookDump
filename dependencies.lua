Dependency = {
    spdlog = {
        include = "%{wks.location}/vendor/spdlog/include",
        lib = ""
    },
    zycore = {
        include = "%{wks.location}/vendor/zydis/dependencies/zycore/include",
        lib = "zycore"
    },
    zydis = {
        include = "%{wks.location}/vendor/zydis/include",
        lib = "zydis"
    }
}
