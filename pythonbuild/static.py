#!/usr/bin/env python3
# PYSTANDALONE: re-added support for static compilation
import pathlib
import re
import sys

from pythonbuild.cpython import meets_python_minimum_version
from pythonbuild.logging import log
from pythonbuild.utils import NoSearchStringError, static_replace_in_file


def add_to_config_c(source_path: pathlib.Path, extension: str, init_fn: str):
    """Add an extension to PC/config.c"""

    config_c_path = source_path / "PC" / "config.c"

    lines = []

    with config_c_path.open("r", encoding="utf8") as fh:
        for line in fh:
            line = line.rstrip()

            # Insert the init function declaration before the _inittab struct.
            if line.startswith("struct _inittab"):
                log("adding %s declaration to config.c" % init_fn)
                lines.append("extern PyObject* %s(void);" % init_fn)

            # Insert the extension in the _inittab struct.
            if line.lstrip().startswith("/* Sentinel */"):
                log("marking %s as a built-in extension module" % extension)
                lines.append('{"%s", %s},' % (extension, init_fn))

            lines.append(line)

    with config_c_path.open("w", encoding="utf8") as fh:
        fh.write("\n".join(lines))


def remove_from_config_c(source_path: pathlib.Path, extension: str):
    """Remove an extension from PC/config.c"""

    config_c_path = source_path / "PC" / "config.c"

    lines: list[str] = []

    with config_c_path.open("r", encoding="utf8") as fh:
        for line in fh:
            line = line.rstrip()

            if ('{"%s",' % extension) in line:
                log("removing %s as a built-in extension module" % extension)
                init_fn = line.strip().strip("{},").partition(", ")[2]
                log("removing %s declaration from config.c" % init_fn)
                lines = list(filter(lambda line: init_fn not in line, lines))
                continue

            lines.append(line)

    with config_c_path.open("w", encoding="utf8") as fh:
        fh.write("\n".join(lines))


def remove_from_extension_modules(source_path: pathlib.Path, extension: str):
    """Remove an extension from the set of extension/external modules.

    Call this when an extension will be compiled into libpython instead of
    compiled as a standalone extension.
    """

    RE_EXTENSION_MODULES = re.compile('<(Extension|External)Modules Include="([^"]+)"')

    pcbuild_proj_path = source_path / "PCbuild" / "pcbuild.proj"

    lines = []

    with pcbuild_proj_path.open("r", encoding="utf8") as fh:
        for line in fh:
            line = line.rstrip()

            m = RE_EXTENSION_MODULES.search(line)

            if m:
                modules = [m for m in m.group(2).split(";") if m != extension]

                # Ignore line if new value is empty.
                if not modules:
                    continue

                line = line.replace(m.group(2), ";".join(modules))

            lines.append(line)

    with pcbuild_proj_path.open("w", encoding="utf8") as fh:
        fh.write("\n".join(lines))


def make_project_static_library(source_path: pathlib.Path, project: str):
    """Turn a project file into a static library."""

    proj_path = source_path / "PCbuild" / ("%s.vcxproj" % project)
    lines = []

    found_config_type = False
    found_target_ext = False

    with proj_path.open("r", encoding="utf8") as fh:
        for line in fh:
            line = line.rstrip()

            # Change the project configuration to a static library.
            if "<ConfigurationType>DynamicLibrary</ConfigurationType>" in line:
                log("changing %s to a static library" % project)
                found_config_type = True
                line = line.replace("DynamicLibrary", "StaticLibrary")

            elif "<ConfigurationType>StaticLibrary</ConfigurationType>" in line:
                log("%s is already a static library" % project)
                return

            # Change the output file name from .pyd to .lib because it is no
            # longer an extension.
            if "<TargetExt>.pyd</TargetExt>" in line:
                log("changing output of %s to a .lib" % project)
                found_target_ext = True
                line = line.replace(".pyd", ".lib")
            # Python 3.13+ uses $(PyStdlibPydExt) instead of literal .pyd.
            elif "<TargetExt>$(PyStdlibPydExt)</TargetExt>" in line:
                log("changing output of %s to a .lib (3.13+ style)" % project)
                found_target_ext = True
                line = line.replace("$(PyStdlibPydExt)", ".lib")

            lines.append(line)

    if not found_config_type:
        log("failed to adjust config type for %s" % project)
        sys.exit(1)

    if not found_target_ext:
        log("failed to adjust target extension for %s" % project)
        sys.exit(1)

    with proj_path.open("w", encoding="utf8") as fh:
        fh.write("\n".join(lines))


def convert_to_static_library(
    source_path: pathlib.Path,
    extension: str,
    entry: dict,
    honor_allow_missing_preprocessor: bool,
):
    """Converts an extension to a static library."""

    proj_path = source_path / "PCbuild" / ("%s.vcxproj" % extension)

    if not proj_path.exists() and entry.get("ignore_missing"):
        return False

    # Make the extension's project emit a static library so we can link
    # against libpython.
    make_project_static_library(source_path, extension)

    # And do the same thing for its dependencies.
    for project in entry.get("static_depends", []):
        make_project_static_library(source_path, project)

    copy_link_to_lib(proj_path)

    lines: list[str] = []

    RE_PREPROCESSOR_DEFINITIONS = re.compile(
        "<PreprocessorDefinitions[^>]*>([^<]+)</PreprocessorDefinitions>"
    )

    found_preprocessor = False
    itemgroup_line = None
    itemdefinitiongroup_line = None

    with proj_path.open("r", encoding="utf8") as fh:
        for i, line in enumerate(fh):
            line = line.rstrip()

            # Add Py_BUILD_CORE_BUILTIN to preprocessor definitions so linkage
            # data is correct.
            m = RE_PREPROCESSOR_DEFINITIONS.search(line)

            # But don't do it if it is an annotation for an individual source file.
            if m and "<ClCompile Include=" not in lines[i - 1]:
                log("adding Py_BUILD_CORE_BUILTIN to %s" % extension)
                found_preprocessor = True
                line = line.replace(m.group(1), "Py_BUILD_CORE_BUILTIN;%s" % m.group(1))

            # Find the first <ItemGroup> entry.
            if "<ItemGroup>" in line and not itemgroup_line:
                itemgroup_line = i

            # Find the first <ItemDefinitionGroup> entry.
            if "<ItemDefinitionGroup>" in line and not itemdefinitiongroup_line:
                itemdefinitiongroup_line = i

            lines.append(line)

    if not found_preprocessor:
        if honor_allow_missing_preprocessor and entry.get("allow_missing_preprocessor"):
            log("not adjusting preprocessor definitions for %s" % extension)
        elif itemgroup_line is not None:
            log("introducing <PreprocessorDefinitions> to %s" % extension)
            lines[itemgroup_line:itemgroup_line] = [
                "  <ItemDefinitionGroup>",
                "    <ClCompile>",
                "      <PreprocessorDefinitions>Py_BUILD_CORE_BUILTIN;%(PreprocessorDefinitions)</PreprocessorDefinitions>",
                "    </ClCompile>",
                "  </ItemDefinitionGroup>",
            ]

            itemdefinitiongroup_line = itemgroup_line + 1

    if "static_depends" in entry:
        if not itemdefinitiongroup_line:
            log("unable to find <ItemDefinitionGroup> for %s" % extension)
            sys.exit(1)

        log("changing %s to automatically link library dependencies" % extension)
        lines[itemdefinitiongroup_line + 1 : itemdefinitiongroup_line + 1] = [
            "    <ProjectReference>",
            "      <LinkLibraryDependencies>true</LinkLibraryDependencies>",
            "    </ProjectReference>",
        ]

    # Preserve the natural dependency graph: extensions depend on
    # pythoncore.  This ensures pythoncore's _UpdatePyconfig target runs
    # before any extension compiles, so pyconfig.h exists in pythoncore's
    # IntDir and extensions see a consistent, correctly-substituted copy
    # via GeneratedPyConfigDir on /I.
    #
    # pythoncore.lib therefore does not contain extension objs; the final
    # executables (python.exe, pythonw.exe) link each extension's .lib
    # directly to resolve the PyInit_* symbols referenced by PC/config.c.
    # See `link_builtin_extensions_into_executables` below.
    with proj_path.open("w", encoding="utf8") as fh:
        fh.write("\n".join(lines))

    return True


def link_builtin_extensions_into_executables(
    source_path: pathlib.Path, extensions: list[str]
):
    """Make python.exe / pythonw.exe link against each built-in extension's
    static library.

    python.vcxproj / pythonw.vcxproj inherit their link settings from
    pyproject.props and do not declare an `<AdditionalDependencies>`
    element.  Inject one just before the closing `</Link>` listing
    `$(OutDir)<ext>.lib` for every converted extension so the linker
    resolves the `PyInit_*` symbols referenced by PC/config.c.
    """

    if not extensions:
        return

    additional = ";".join("$(OutDir)%s.lib" % ext for ext in extensions)
    injected_line = (
        "      <AdditionalDependencies>"
        "%s;%%(AdditionalDependencies)"
        "</AdditionalDependencies>"
    ) % additional

    for exe_proj_name in ("python", "pythonw", "_freeze_importlib"):
        exe_path = source_path / "PCbuild" / ("%s.vcxproj" % exe_proj_name)
        if not exe_path.exists():
            log("skipping %s.vcxproj: not present" % exe_proj_name)
            continue

        with exe_path.open("r", encoding="utf8") as fh:
            data = fh.read()

        # Detect likely newline style so we can preserve it.
        newline = "\r\n" if "\r\n" in data else "\n"

        closing = newline + "    </Link>"
        if closing not in data:
            log(
                "warning: no </Link> tag found in %s.vcxproj; "
                "built-in extensions will not link into %s.exe"
                % (exe_proj_name, exe_proj_name)
            )
            continue

        # Insert only once (idempotent).
        if "<!-- PYSTANDALONE_BUILTIN_EXT_LIBS -->" in data:
            log("skipping %s.vcxproj: already patched" % exe_proj_name)
            continue

        replacement = (
            newline
            + injected_line
            + newline
            + "      <!-- PYSTANDALONE_BUILTIN_EXT_LIBS -->"
            + newline
            + "    </Link>"
        )
        data = data.replace(closing, replacement, 1)

        log(
            "linking %d built-in extension lib(s) into %s.exe"
            % (len(extensions), exe_proj_name)
        )
        with exe_path.open("w", encoding="utf8") as fh:
            fh.write(data)


def copy_link_to_lib(p: pathlib.Path):
    """Copy the contents of a <Link> section to a <Lib> section."""

    lines = []
    copy_lines: list[str] = []
    copy_active = False

    with p.open("r", encoding="utf8") as fh:
        for line in fh:
            line = line.rstrip()

            lines.append(line)

            if "<Link>" in line:
                copy_active = True
                continue

            elif "</Link>" in line:
                copy_active = False

                log("duplicating <Link> section in %s" % p)
                lines.append("    <Lib>")
                lines.extend(copy_lines)
                # Ensure the output directory is in the library path for
                # lib.exe.  The <Link> section inherits $(OutDir) from
                # property sheets, but <Lib> does not.  Without this,
                # dependency libraries referenced by filename only (e.g.
                # zlib-ng.lib on 3.14+) cannot be found.
                if not any("<AdditionalLibraryDirectories>" in l for l in copy_lines):
                    lines.append(
                        "      <AdditionalLibraryDirectories>"
                        "$(OutDir);%(AdditionalLibraryDirectories)"
                        "</AdditionalLibraryDirectories>"
                    )
                lines.append("    </Lib>")

            if copy_active:
                copy_lines.append(line)

    with p.open("w", encoding="utf8") as fh:
        fh.write("\n".join(lines))


PYPORT_EXPORT_SEARCH_39 = b"""
#if defined(__CYGWIN__)
#       define HAVE_DECLSPEC_DLL
#endif

#include "exports.h"

/* only get special linkage if built as shared or platform is Cygwin */
#if defined(Py_ENABLE_SHARED) || defined(__CYGWIN__)
#       if defined(HAVE_DECLSPEC_DLL)
#               if defined(Py_BUILD_CORE) && !defined(Py_BUILD_CORE_MODULE)
#                       define PyAPI_FUNC(RTYPE) Py_EXPORTED_SYMBOL RTYPE
#                       define PyAPI_DATA(RTYPE) extern Py_EXPORTED_SYMBOL RTYPE
        /* module init functions inside the core need no external linkage */
        /* except for Cygwin to handle embedding */
#                       if defined(__CYGWIN__)
#                               define PyMODINIT_FUNC Py_EXPORTED_SYMBOL PyObject*
#                       else /* __CYGWIN__ */
#                               define PyMODINIT_FUNC PyObject*
#                       endif /* __CYGWIN__ */
#               else /* Py_BUILD_CORE */
        /* Building an extension module, or an embedded situation */
        /* public Python functions and data are imported */
        /* Under Cygwin, auto-import functions to prevent compilation */
        /* failures similar to those described at the bottom of 4.1: */
        /* http://docs.python.org/extending/windows.html#a-cookbook-approach */
#                       if !defined(__CYGWIN__)
#                               define PyAPI_FUNC(RTYPE) Py_IMPORTED_SYMBOL RTYPE
#                       endif /* !__CYGWIN__ */
#                       define PyAPI_DATA(RTYPE) extern Py_IMPORTED_SYMBOL RTYPE
        /* module init functions outside the core must be exported */
#                       if defined(__cplusplus)
#                               define PyMODINIT_FUNC extern "C" Py_EXPORTED_SYMBOL PyObject*
#                       else /* __cplusplus */
#                               define PyMODINIT_FUNC Py_EXPORTED_SYMBOL PyObject*
#                       endif /* __cplusplus */
#               endif /* Py_BUILD_CORE */
#       endif /* HAVE_DECLSPEC_DLL */
#endif /* Py_ENABLE_SHARED */

/* If no external linkage macros defined by now, create defaults */
#ifndef PyAPI_FUNC
#       define PyAPI_FUNC(RTYPE) Py_EXPORTED_SYMBOL RTYPE
#endif
#ifndef PyAPI_DATA
#       define PyAPI_DATA(RTYPE) extern Py_EXPORTED_SYMBOL RTYPE
#endif
#ifndef PyMODINIT_FUNC
#       if defined(__cplusplus)
#               define PyMODINIT_FUNC extern "C" Py_EXPORTED_SYMBOL PyObject*
#       else /* __cplusplus */
#               define PyMODINIT_FUNC Py_EXPORTED_SYMBOL PyObject*
#       endif /* __cplusplus */
#endif
"""

PYPORT_EXPORT_SEARCH_38 = b"""
#if defined(__CYGWIN__)
#       define HAVE_DECLSPEC_DLL
#endif

/* only get special linkage if built as shared or platform is Cygwin */
#if defined(Py_ENABLE_SHARED) || defined(__CYGWIN__)
#       if defined(HAVE_DECLSPEC_DLL)
#               if defined(Py_BUILD_CORE) && !defined(Py_BUILD_CORE_MODULE)
#                       define PyAPI_FUNC(RTYPE) __declspec(dllexport) RTYPE
#                       define PyAPI_DATA(RTYPE) extern __declspec(dllexport) RTYPE
        /* module init functions inside the core need no external linkage */
        /* except for Cygwin to handle embedding */
#                       if defined(__CYGWIN__)
#                               define PyMODINIT_FUNC __declspec(dllexport) PyObject*
#                       else /* __CYGWIN__ */
#                               define PyMODINIT_FUNC PyObject*
#                       endif /* __CYGWIN__ */
#               else /* Py_BUILD_CORE */
        /* Building an extension module, or an embedded situation */
        /* public Python functions and data are imported */
        /* Under Cygwin, auto-import functions to prevent compilation */
        /* failures similar to those described at the bottom of 4.1: */
        /* http://docs.python.org/extending/windows.html#a-cookbook-approach */
#                       if !defined(__CYGWIN__)
#                               define PyAPI_FUNC(RTYPE) __declspec(dllimport) RTYPE
#                       endif /* !__CYGWIN__ */
#                       define PyAPI_DATA(RTYPE) extern __declspec(dllimport) RTYPE
        /* module init functions outside the core must be exported */
#                       if defined(__cplusplus)
#                               define PyMODINIT_FUNC extern "C" __declspec(dllexport) PyObject*
#                       else /* __cplusplus */
#                               define PyMODINIT_FUNC __declspec(dllexport) PyObject*
#                       endif /* __cplusplus */
#               endif /* Py_BUILD_CORE */
#       endif /* HAVE_DECLSPEC_DLL */
#endif /* Py_ENABLE_SHARED */

/* If no external linkage macros defined by now, create defaults */
#ifndef PyAPI_FUNC
#       define PyAPI_FUNC(RTYPE) RTYPE
#endif
#ifndef PyAPI_DATA
#       define PyAPI_DATA(RTYPE) extern RTYPE
#endif
#ifndef PyMODINIT_FUNC
#       if defined(__cplusplus)
#               define PyMODINIT_FUNC extern "C" PyObject*
#       else /* __cplusplus */
#               define PyMODINIT_FUNC PyObject*
#       endif /* __cplusplus */
#endif
"""

PYPORT_EXPORT_SEARCH_37 = b"""
#if defined(__CYGWIN__)
#       define HAVE_DECLSPEC_DLL
#endif

/* only get special linkage if built as shared or platform is Cygwin */
#if defined(Py_ENABLE_SHARED) || defined(__CYGWIN__)
#       if defined(HAVE_DECLSPEC_DLL)
#               if defined(Py_BUILD_CORE) || defined(Py_BUILD_CORE_BUILTIN)
#                       define PyAPI_FUNC(RTYPE) __declspec(dllexport) RTYPE
#                       define PyAPI_DATA(RTYPE) extern __declspec(dllexport) RTYPE
        /* module init functions inside the core need no external linkage */
        /* except for Cygwin to handle embedding */
#                       if defined(__CYGWIN__)
#                               define PyMODINIT_FUNC __declspec(dllexport) PyObject*
#                       else /* __CYGWIN__ */
#                               define PyMODINIT_FUNC PyObject*
#                       endif /* __CYGWIN__ */
#               else /* Py_BUILD_CORE */
        /* Building an extension module, or an embedded situation */
        /* public Python functions and data are imported */
        /* Under Cygwin, auto-import functions to prevent compilation */
        /* failures similar to those described at the bottom of 4.1: */
        /* http://docs.python.org/extending/windows.html#a-cookbook-approach */
#                       if !defined(__CYGWIN__)
#                               define PyAPI_FUNC(RTYPE) __declspec(dllimport) RTYPE
#                       endif /* !__CYGWIN__ */
#                       define PyAPI_DATA(RTYPE) extern __declspec(dllimport) RTYPE
        /* module init functions outside the core must be exported */
#                       if defined(__cplusplus)
#                               define PyMODINIT_FUNC extern "C" __declspec(dllexport) PyObject*
#                       else /* __cplusplus */
#                               define PyMODINIT_FUNC __declspec(dllexport) PyObject*
#                       endif /* __cplusplus */
#               endif /* Py_BUILD_CORE */
#       endif /* HAVE_DECLSPEC_DLL */
#endif /* Py_ENABLE_SHARED */

/* If no external linkage macros defined by now, create defaults */
#ifndef PyAPI_FUNC
#       define PyAPI_FUNC(RTYPE) RTYPE
#endif
#ifndef PyAPI_DATA
#       define PyAPI_DATA(RTYPE) extern RTYPE
#endif
#ifndef PyMODINIT_FUNC
#       if defined(__cplusplus)
#               define PyMODINIT_FUNC extern "C" PyObject*
#       else /* __cplusplus */
#               define PyMODINIT_FUNC PyObject*
#       endif /* __cplusplus */
#endif
"""

PYPORT_EXPORT_REPLACE_NEW = b"""
#include "exports.h"
#define PyAPI_FUNC(RTYPE) __declspec(dllexport) RTYPE
#define PyAPI_DATA(RTYPE) extern __declspec(dllexport) RTYPE
#define PyMODINIT_FUNC __declspec(dllexport) PyObject*
"""

PYPORT_EXPORT_REPLACE_OLD = b"""
#define PyAPI_FUNC(RTYPE) __declspec(dllexport) RTYPE
#define PyAPI_DATA(RTYPE) extern __declspec(dllexport) RTYPE
#define PyMODINIT_FUNC __declspec(dllexport) PyObject*
"""

SYSMODULE_WINVER_SEARCH = b"""
#ifdef MS_COREDLL
    SET_SYS("dllhandle", PyLong_FromVoidPtr(PyWin_DLLhModule));
    SET_SYS_FROM_STRING("winver", PyWin_DLLVersionString);
#endif
"""

SYSMODULE_WINVER_REPLACE = b"""
#ifdef MS_COREDLL
    SET_SYS("dllhandle", PyLong_FromVoidPtr(PyWin_DLLhModule));
    SET_SYS_FROM_STRING("winver", PyWin_DLLVersionString);
#else
    SET_SYS_FROM_STRING("winver", "%s");
#endif
"""

SYSMODULE_WINVER_SEARCH_38 = b"""
#ifdef MS_COREDLL
    SET_SYS_FROM_STRING("dllhandle",
                        PyLong_FromVoidPtr(PyWin_DLLhModule));
    SET_SYS_FROM_STRING("winver",
                        PyUnicode_FromString(PyWin_DLLVersionString));
#endif
"""

SYSMODULE_WINVER_REPLACE_38 = b"""
#ifdef MS_COREDLL
    SET_SYS_FROM_STRING("dllhandle",
                        PyLong_FromVoidPtr(PyWin_DLLhModule));
    SET_SYS_FROM_STRING("winver",
                        PyUnicode_FromString(PyWin_DLLVersionString));
#else
    SET_SYS_FROM_STRING("winver", PyUnicode_FromString("%s"));
#endif
"""

# In CPython 3.13+, the export macros were moved from pyport.h to exports.h.
# We add Py_NO_ENABLE_SHARED to the conditions so that our static builds
# (which define Py_NO_ENABLE_SHARED) get proper dllexport on BOTH
# Py_EXPORTED_SYMBOL and Py_IMPORTED_SYMBOL.  Using dllexport for BOTH
# (instead of dllimport for Py_IMPORTED_SYMBOL) is critical because static
# libraries don't have __imp_ prefixed symbols that dllimport requires.
# This matches the 3.11/3.12 approach where PyAPI_FUNC is unconditionally
# __declspec(dllexport) for all code.
# We also add Py_NO_ENABLE_SHARED to the PyAPI_FUNC/PyMODINIT_FUNC block
# which activates the Py_BUILD_CORE branch for core code.  That branch
# defines PyMODINIT_FUNC as plain PyObject* (no dllexport), matching the
# plain "extern" declarations in internal headers like pycore_warnings.h
# (which changed from PyAPI_FUNC() to plain extern in 3.13).
# Without this, _freeze_module gets C2375 "different linkage" errors.
EXPORTS_H_SEARCH_313 = b"""#if defined(_WIN32) || defined(__CYGWIN__)
    #if defined(Py_ENABLE_SHARED)
        #define Py_IMPORTED_SYMBOL __declspec(dllimport)
        #define Py_EXPORTED_SYMBOL __declspec(dllexport)
        #define Py_LOCAL_SYMBOL
    #else
        #define Py_IMPORTED_SYMBOL
        #define Py_EXPORTED_SYMBOL
        #define Py_LOCAL_SYMBOL
    #endif"""

EXPORTS_H_REPLACE_313 = b"""#if defined(_WIN32) || defined(__CYGWIN__)
    #if defined(Py_ENABLE_SHARED) || defined(Py_NO_ENABLE_SHARED)
        #define Py_IMPORTED_SYMBOL __declspec(dllexport)
        #define Py_EXPORTED_SYMBOL __declspec(dllexport)
        #define Py_LOCAL_SYMBOL
    #else
        #define Py_IMPORTED_SYMBOL
        #define Py_EXPORTED_SYMBOL
        #define Py_LOCAL_SYMBOL
    #endif"""

# The second block in exports.h: the PyAPI_FUNC/PyMODINIT_FUNC conditional.
EXPORTS_H_LINKAGE_SEARCH_313 = b"/* only get special linkage if built as shared or platform is Cygwin */\n#if defined(Py_ENABLE_SHARED) || defined(__CYGWIN__)"

EXPORTS_H_LINKAGE_REPLACE_313 = b"/* only get special linkage if built as shared or platform is Cygwin */\n#if defined(Py_ENABLE_SHARED) || defined(Py_NO_ENABLE_SHARED) || defined(__CYGWIN__)"


def hack_source_files(source_path: pathlib.Path, python_version: str):
    """Apply source modifications to make things work for static builds."""

    # The PyAPI_FUNC, PyAPI_DATA, and PyMODINIT_FUNC macros define symbol
    # visibility. By default, pyport.h looks at Py_ENABLE_SHARED, __CYGWIN__,
    # Py_BUILD_CORE, Py_BUILD_CORE_BUILTIN, etc to determine what the macros
    # should be. The logic assumes that Python is being built in a certain
    # manner - notably that extensions are standalone dynamic libraries.
    #
    # We force the use of __declspec(dllexport) in all cases to ensure that
    # API symbols are exported. This annotation becomes embedded within the
    # object file. When that object file is linked, the symbol is exported
    # from the final binary. For statically linked binaries, this behavior
    # may not be needed. However, by exporting the symbols we allow downstream
    # consumers of the object files to produce a binary that can be
    # dynamically linked. This is a useful property to have.

    # In CPython 3.13+, exports moved from pyport.h to exports.h.
    exports_h = source_path / "Include" / "exports.h"
    pyport_h = source_path / "Include" / "pyport.h"

    if meets_python_minimum_version(python_version, "3.13") and exports_h.exists():
        static_replace_in_file(exports_h, EXPORTS_H_SEARCH_313, EXPORTS_H_REPLACE_313)
        # Also patch the PyAPI_FUNC/PyMODINIT_FUNC conditional block.
        static_replace_in_file(
            exports_h, EXPORTS_H_LINKAGE_SEARCH_313, EXPORTS_H_LINKAGE_REPLACE_313
        )
    else:
        try:
            static_replace_in_file(
                pyport_h, PYPORT_EXPORT_SEARCH_39, PYPORT_EXPORT_REPLACE_NEW
            )
        except NoSearchStringError:
            try:
                static_replace_in_file(
                    pyport_h, PYPORT_EXPORT_SEARCH_38, PYPORT_EXPORT_REPLACE_OLD
                )
            except NoSearchStringError:
                static_replace_in_file(
                    pyport_h, PYPORT_EXPORT_SEARCH_37, PYPORT_EXPORT_REPLACE_OLD
                )

    # Modules/getpath.c unconditionally refers to PyWin_DLLhModule, which is
    # conditionally defined behind Py_ENABLE_SHARED. Change its usage
    # accordingly. This regressed as part of upstream commit
    # 99fcf1505218464c489d419d4500f126b6d6dc28. But it was fixed
    # in 3.12 by c6858d1e7f4cd3184d5ddea4025ad5dfc7596546.
    if meets_python_minimum_version(
        python_version, "3.11"
    ) and not meets_python_minimum_version(python_version, "3.12"):
        try:
            static_replace_in_file(
                source_path / "Modules" / "getpath.c",
                b"#ifdef MS_WINDOWS\n    extern HMODULE PyWin_DLLhModule;",
                b"#if defined MS_WINDOWS && defined Py_ENABLE_SHARED\n    extern HMODULE PyWin_DLLhModule;",
            )
        except NoSearchStringError:
            pass

    # Similar deal as above. Regression also introduced in upstream commit
    # 99fcf1505218464c489d419d4500f126b6d6dc28.
    if meets_python_minimum_version(python_version, "3.11"):
        try:
            static_replace_in_file(
                source_path / "Python" / "dynload_win.c",
                b"extern HMODULE PyWin_DLLhModule;\n",
                b"#ifdef Py_ENABLE_SHARED\nextern HMODULE PyWin_DLLhModule;\n#else\n#define PyWin_DLLhModule NULL\n#endif\n",
            )
        except NoSearchStringError:
            pass

    # Modules/_winapi.c and Modules/overlapped.c both define an
    # ``OverlappedType`` symbol. We rename one to make the symbol conflict
    # go away.
    try:
        overlapped_c = source_path / "Modules" / "overlapped.c"
        static_replace_in_file(overlapped_c, b"OverlappedType", b"OOverlappedType")
    except NoSearchStringError:
        pass

    # Modules/ctypes/callbacks.c has lines like the following:
    # #ifndef Py_NO_ENABLE_SHARED
    # BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvRes)
    # We currently define Py_ENABLE_SHARED. And I /think/ this check should
    # also check against Py_BUILD_CORE_BUILTIN because Py_BUILD_CORE_BUILTIN
    # with Py_ENABLE_SHARED is theoretically a valid configuration.
    try:
        callbacks_c = source_path / "Modules" / "_ctypes" / "callbacks.c"
        static_replace_in_file(
            callbacks_c,
            b"#ifndef Py_NO_ENABLE_SHARED\nBOOL WINAPI DllMain(",
            b"#if !defined(Py_NO_ENABLE_SHARED) && !defined(Py_BUILD_CORE_BUILTIN)\nBOOL WINAPI DllMain(",
        )
    except NoSearchStringError:
        pass

    # Lib/ctypes/__init__.py needs to populate the Python API version. On
    # Windows, it assumes a ``pythonXY`` is available. On Cygwin, a
    # ``libpythonXY`` DLL. The former assumes that ``sys.dllhandle`` is
    # available. And ``sys.dllhandle`` is only populated if ``MS_COREDLL``
    # (a deprecated symbol) is defined. And ``MS_COREDLL`` is not defined
    # if ``Py_NO_ENABLE_SHARED`` is defined. The gist of it is that ctypes
    # assumes that Python on Windows will use a Python DLL.
    #
    # The ``pythonapi`` handle obtained in ``ctypes/__init__.py`` needs to
    # expose a handle on the Python API. If we have a static library, that
    # handle should be the current binary. So all the fancy logic to find
    # the DLL can be simplified.
    #
    # But, ``PyDLL(None)`` doesn't work out of the box because this is
    # translated into a call to ``LoadLibrary(NULL)``. Unlike ``dlopen()``,
    # ``LoadLibrary()`` won't accept a NULL value. So, we need a way to
    # get an ``HMODULE`` for the current executable. Arguably the best way
    # to do this is with ``GetModuleHandleEx()`` using the following C code:
    #
    #   HMODULE hModule = NULL;
    #   GetModuleHandleEx(
    #     GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
    #     (LPCSTR)SYMBOL_IN_CURRENT_MODULE,
    #     &hModule);
    #
    # The ``ctypes`` module has handles on function pointers in the current
    # binary. One would think we'd be able to use ``ctypes.cast()`` +
    # ``ctypes.addressof()`` to get a pointer to a symbol in the current
    # executable. But the addresses appear to be to heap allocated PyObject
    # instances, which won't work.
    #
    # An ideal solution would be to expose the ``HMODULE`` of the current
    # module. We /should/ be able to change the behavior of ``sys.dllhandle``
    # to facilitate this. But this is a bit more work. Our hack is to instead
    # use ``sys.executable`` with ``LoadLibrary()``. This should hopefully be
    # "good enough."
    try:
        ctypes_init = source_path / "Lib" / "ctypes" / "__init__.py"
        static_replace_in_file(
            ctypes_init,
            b'pythonapi = PyDLL("python dll", None, _sys.dllhandle)',
            b"pythonapi = PyDLL(_sys.executable)",
        )
    except NoSearchStringError:
        pass

    # Python 3.11 made _Py_IDENTIFIER hidden by default. Source files need to
    # opt in to unmasking it. Our static build tickles this into not working.
    try:
        static_replace_in_file(
            source_path / "PC" / "_msi.c",
            b"#include <Python.h>\n",
            b"#define NEEDS_PY_IDENTIFIER\n#include <Python.h>\n",
        )
    except (NoSearchStringError, FileNotFoundError):
        pass

    # The `sys` module only populates `sys.winver` if MS_COREDLL is defined,
    # which it isn't in static builds. We know what the version should be, so
    # we go ahead and set it.
    majmin = ".".join(python_version.split(".")[0:2])
    # Source changed in 3.10.
    try:
        static_replace_in_file(
            source_path / "Python" / "sysmodule.c",
            SYSMODULE_WINVER_SEARCH,
            SYSMODULE_WINVER_REPLACE % majmin.encode("ascii"),
        )
    except NoSearchStringError:
        try:
            static_replace_in_file(
                source_path / "Python" / "sysmodule.c",
                SYSMODULE_WINVER_SEARCH_38,
                SYSMODULE_WINVER_REPLACE_38 % majmin.encode("ascii"),
            )
        except NoSearchStringError:
            pass

    # Producing statically linked binaries invalidates assumptions in the
    # layout tool. Update the tool accordingly.
    try:
        layout_main = source_path / "PC" / "layout" / "main.py"

        # We no longer have a pythonXX.dll file.
        try:
            # 3.13+ has an if/else block for freethreaded DLL name.
            static_replace_in_file(
                layout_main,
                b"    if ns.include_freethreaded:\n        yield from in_build(FREETHREADED_PYTHON_DLL_NAME)\n    else:\n        yield from in_build(PYTHON_DLL_NAME)\n",
                b"",
            )
        except NoSearchStringError:
            static_replace_in_file(
                layout_main, b"    yield from in_build(PYTHON_DLL_NAME)\n", b""
            )
    except NoSearchStringError:
        pass
