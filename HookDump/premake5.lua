project "HookDump"
    kind "SharedLib"

    targetdir("%{wks.location}/out/" .. outputdir .. "/bin/")
    debugdir("%{wks.location}/out/" .. outputdir .. "/bin/")
    objdir("%{wks.location}/out/" .. outputdir .. "/obj/%{prj.name}")
    implibdir("%{wks.location}/out/" .. outputdir .. "/obj/%{prj.name}")
    symbolspath("%{wks.location}/out/" .. outputdir .. "/obj/%{prj.name}/%{prj.name}.pdb")

    files {
        "src/**.h",
        "src/**.cpp"
    }

    includedirs {
        "src",

        Dependency.spdlog.include,
        Dependency.zycore.include,
        Dependency.zydis.include
    }

    links {
        Dependency.zycore.lib,
        Dependency.zydis.lib
    }

    defines {
        "ZYCORE_STATIC_BUILD",
        "ZYDIS_STATIC_BUILD"
    }
