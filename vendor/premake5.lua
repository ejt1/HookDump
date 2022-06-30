group "External Dependencies"
    project "zycore"
        kind "StaticLib"

        targetdir("%{wks.location}/out/" .. outputdir .. "/lib/")
        debugdir("%{wks.location}/out/" .. outputdir .. "/lib/")
        objdir("%{wks.location}/out/" .. outputdir .. "/obj/%{prj.name}")
        implibdir("%{wks.location}/out/" .. outputdir .. "/obj/%{prj.name}")
        symbolspath("%{wks.location}/out/" .. outputdir .. "/obj/%{prj.name}/%{prj.name}.pdb")

        files {
            "zydis/dependencies/zycore/src/**.h",
            "zydis/dependencies/zycore/src/**.c"
        }

        includedirs {
            "zydis/dependencies/zycore/include"
        }

        defines {
            "ZYCORE_STATIC_BUILD"
        }

    project "zydis"
        kind "StaticLib"

        targetdir("%{wks.location}/out/" .. outputdir .. "/lib/")
        debugdir("%{wks.location}/out/" .. outputdir .. "/lib/")
        objdir("%{wks.location}/out/" .. outputdir .. "/obj/%{prj.name}")
        implibdir("%{wks.location}/out/" .. outputdir .. "/obj/%{prj.name}")
        symbolspath("%{wks.location}/out/" .. outputdir .. "/obj/%{prj.name}/%{prj.name}.pdb")

        files {
            "zydis/src/**.h",
            "zydis/src/**.c"
        }

        includedirs {
            "zydis/include",
            "zydis/src",

            Dependency.zycore.include
        }

        links {
            Dependency.zycore.lib
        }

        defines {
            "ZYDIS_STATIC_BUILD"
        }
group ""
