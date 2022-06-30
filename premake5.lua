require('dependencies')

workspace "HookDump"
    architecture "x86_64"
    startproject "HookDump"

    language "C++"
    cppdialect "C++latest"
    staticruntime "off"
    characterset "MBCS"
    warnings "Extra"

    configurations {
        "Debug",
        "Release",
    }

    filter "system:windows"
        systemversion "latest"

    filter "configurations:Debug"
        defines { "DEBUG" }
        runtime "Debug"
        symbols "on"

    filter "configurations:Release"
        runtime "Release"
        optimize "on"

    -- reset filter
    filter ""

    flags {
        "MultiProcessorCompile"
    }

outputdir = "%{cfg.buildcfg}-%{cfg.system}-%{cfg.architecture}"

-- dependencies
include "vendor"
include "HookDump"
