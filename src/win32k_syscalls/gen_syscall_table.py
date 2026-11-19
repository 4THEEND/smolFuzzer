#!/usr/bin/env python3
"""Turn win32k_syscalls_updated.json into win32k_syscall_table.hpp.

    python3 gen_syscall_table.py win32k_syscalls_updated.json win32k_syscall_table.hpp

The header holds only what the syscall mutator needs to build a call: SSN,
argument types/kinds/directions, pointee layout (fields the kernel reads,
nested pointers), array/count links, string forms and observed literals.
Re-run it whenever the JSON changes (new build, refined types).
"""
import json
import sys

# Syscalls the mutator must never emit. They stay in the table (so seeds that
# contain them can be recognised and dropped) but are flagged disabled.
# This is a starting point: extend it with whatever stalls or kills your VM.
DENYLIST = {
    # Block until a message/event arrives: every exec would run into the timeout.
    "NtUserGetMessage", "NtUserWaitMessage", "NtUserRealInternalGetMessage",
    "NtUserRealWaitMessageEx", "NtUserWaitAvailableMessageEx",
    "NtUserMsgWaitForMultipleObjectsEx", "NtUserWaitForInputIdle",
    "NtUserWaitForRedirectionStartComplete", "NtDCompositionSyncWait",
    "NtDCompositionWaitForChannel", "NtDCompositionWaitForCompositorClock",
    "NtGdiDdDDIWaitForVerticalBlankEvent", "NtGdiDdDDIWaitForVerticalBlankEvent2",
    "NtGdiDdDDIWaitForIdle", "NtGdiDdDDIWaitForSynchronizationObject",
    "NtGdiDdDDIWaitForSynchronizationObjectFromCpu",
    "NtGdiDdDDIWaitForSynchronizationObjectFromGpu", "NtGdiWaitForTextReady",
    "NtKSTWait",
    # Modal loops.
    "NtUserTrackPopupMenuEx", "NtUserDragDetect", "NtUserDragObject",
    # Change session state in ways that end the run instead of finding bugs.
    "NtUserLockWorkStation", "NtUserBlockInput", "NtUserSetThreadInputBlocked",
    "NtUserSwitchDesktop", "NtUserHardErrorControl", "NtUserDwmKernelShutdown",
    "NtUserPrepareForLogoff", "NtUserWakeRITForShutdown", "NtUserRemoteDisconnect",
    "NtUserLockWindowStation",
}

MAX_MEM = 4096  # must match win32k::prog::kMaxMem in syscall_program.hpp

KIND = {"handle": "Handle", "scalar": "Scalar", "pointer": "Pointer", "buffer": "Buffer",
        "array": "Array", "string": "String", "unknown": "Unknown"}
DIR = {"in": "In", "out": "Out", "inout": "InOut"}
TEXT = {"nul_terminated": "NulTerminated", "counted_array": "CountedArray",
        "unicode_string_struct": "UnicodeString", "ansi_string_struct": "AnsiString"}
RET = {"status": "Status", "scalar": "Scalar", "handle": "Handle", "pointer": "Pointer", "void": "Void"}
WIDE_PTR = {"LPWSTR", "LPCWSTR", "PWSTR", "PCWSTR"}
NARROW_PTR = {"LPSTR", "LPCSTR", "PSTR", "PCSTR"}


def cstr(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    with open(sys.argv[1], encoding="utf-8") as f:
        doc = json.load(f)

    syscalls = sorted(doc["syscalls"], key=lambda s: s["ssn"])
    names = {s["name"] for s in syscalls}
    for missing in sorted(DENYLIST - names):
        print(f"note: denylisted {missing} is not in this build", file=sys.stderr)

    args, fields, nested, values, rows = [], [], [], [], []
    for sc in syscalls:
        assert sc["nargs"] == len(sc["args"]) and sc["ssn"] <= 0xFFFF
        first_arg = len(args)
        for a in sc["args"]:
            cd = a.get("character_data")
            arr = a.get("array")
            pointee = a.get("pointee") or {}

            text = TEXT[cd["form"]] if cd else "None"
            if a["c_type"] == "PLARGE_STRING":
                text = "LargeString"

            elem = (arr or {}).get("element_size") or (cd or {}).get("element_size") or 0
            if not elem and a["kind"] != "scalar":
                elem = 2 if a["c_type"] in WIDE_PTR else 1 if a["c_type"] in NARROW_PTR else 0
            if text in ("UnicodeString", "AnsiString", "LargeString"):
                elem = 2 if text != "AnsiString" else 1   # element size of the characters

            count = (arr or {}).get("count_arg")
            if count is None:
                count = (cd or {}).get("count_arg")
            if count is not None and (count == a["index"] or count >= sc["nargs"]
                                      or sc["args"][count]["kind"] != "scalar"):
                count = None    # the JSON sometimes points the count at a non-scalar

            f0 = len(fields)
            for fld in pointee.get("fields", []):
                if "r" not in fld["access"] or fld["offset"] + fld["size"] > MAX_MEM:
                    continue    # fields the kernel only writes do not shape the input
                const = fld.get("caller_const")
                fields.append((fld["offset"], fld["size"], const))
            n0 = len(nested)
            for n in pointee.get("nested_pointers", []):
                if n["at_offset"] + 8 <= MAX_MEM:
                    nested.append((n["at_offset"], min(n["size"], MAX_MEM)))
            v0 = len(values)
            values.extend((a.get("observed_values") or {}).get("literals", []))

            args.append(
                f'{{{cstr(a["c_type"])}, Kind::{KIND[a["kind"]]}, Dir::{DIR[a["direction"]]}, '
                f'Text::{text}, {a["size"]}, {min(elem, 255)}, {-1 if count is None else count}, '
                f'{min(pointee.get("size") or 0, MAX_MEM)}, '
                f'{f0}, {len(fields) - f0}, {n0}, {len(nested) - n0}, {v0}, {len(values) - v0}}},'
                f'  // {sc["name"]} a{a["index"]}')
        ret = sc["return"]
        rows.append(
            f'{{{cstr(sc["name"])}, {cstr(ret["c_type"])}, 0x{sc["ssn"]:04X}, {first_arg}, '
            f'{sc["nargs"]}, Ret::{RET[ret["kind"]]}, {"false" if sc["name"] in DENYLIST else "true"}}},')

    assert len(args) <= 0xFFFF and len(fields) <= 0xFFFF and len(nested) <= 0xFFFF and len(values) <= 0xFFFF

    build = doc["build"]
    out = []
    w = out.append
    w("// win32k_syscall_table.hpp - GENERATED by gen_syscall_table.py, do not edit.")
    w(f'// Source: {build["os"]} {build["build"]} ({build["arch"]}), {len(rows)} syscalls, {len(args)} arguments.')
    w("#pragma once")
    w("")
    w("#include <cstddef>")
    w("#include <cstdint>")
    w("#include <string_view>")
    w("")
    w("namespace win32k {")
    w("")
    w("enum class Kind : std::uint8_t { Handle, Scalar, Pointer, Buffer, Array, String, Unknown };")
    w("enum class Dir : std::uint8_t { In, Out, InOut };")
    w("enum class Ret : std::uint8_t { Status, Scalar, Handle, Pointer, Void };")
    w("// How character data is passed. UnicodeString/AnsiString/LargeString are 16-byte")
    w("// structs with the character pointer at offset 8.")
    w("enum class Text : std::uint8_t { None, NulTerminated, CountedArray, UnicodeString, AnsiString, LargeString };")
    w("")
    w("// A field of a pointed-to struct that the kernel reads.")
    w("struct FieldDesc {")
    w("    std::uint16_t offset;")
    w("    std::uint16_t size;")
    w("    bool          hasConst;   // user-mode callers always store `constValue` here")
    w("    std::uint64_t constValue;")
    w("};")
    w("")
    w("// A pointer stored inside a pointed-to struct, and the size of what it points to.")
    w("struct NestedDesc {")
    w("    std::uint16_t atOffset;")
    w("    std::uint16_t size;")
    w("};")
    w("")
    w("struct ArgDesc {")
    w("    std::string_view type;         // C type; also the key into sysmon::ArgPool")
    w("    Kind             kind;")
    w("    Dir              dir;")
    w("    Text             text;")
    w("    std::uint8_t     size;         // width of the argument itself: 1, 2, 4 or 8")
    w("    std::uint8_t     elemSize;     // element size for arrays/character data, 0 = not an array")
    w("    std::int8_t      countArg;     // argument holding the element count, -1 = none/unknown")
    w("    std::uint16_t    pointeeSize;  // 0 = unknown")
    w("    std::uint16_t    firstField, numFields;     // into kFields")
    w("    std::uint16_t    firstNested, numNested;    // into kNested")
    w("    std::uint16_t    firstValue, numValues;     // into kValues (literals seen at call sites)")
    w("};")
    w("")
    w("struct SyscallDesc {")
    w("    std::string_view name;")
    w("    std::string_view retType;")
    w("    std::uint16_t    ssn;")
    w("    std::uint16_t    firstArg;     // into kArgs")
    w("    std::uint8_t     numArgs;")
    w("    Ret              ret;")
    w("    bool             enabled;      // false = denylisted, never emitted")
    w("};")
    w("")
    w(f"inline constexpr FieldDesc kFields[] = {{")
    for off, size, const in fields:
        if const is None:
            w(f"    {{{off}, {size}, false, 0}},")
        else:
            w(f"    {{{off}, {size}, true, 0x{const & 0xFFFFFFFFFFFFFFFF:X}ull}},")
    w("};")
    w("")
    w("inline constexpr NestedDesc kNested[] = {")
    for off, size in nested:
        w(f"    {{{off}, {size}}},")
    w("};")
    w("")
    w("inline constexpr std::int64_t kValues[] = {")
    for i in range(0, len(values), 12):
        w("    " + " ".join(f"{v}," for v in values[i:i + 12]))
    w("};")
    w("")
    w("inline constexpr ArgDesc kArgs[] = {")
    out.extend("    " + a for a in args)
    w("};")
    w("")
    w("// Sorted by SSN.")
    w("inline constexpr SyscallDesc kSyscalls[] = {")
    out.extend("    " + r for r in rows)
    w("};")
    w("")
    w("inline constexpr std::size_t kNumSyscalls = sizeof(kSyscalls) / sizeof(kSyscalls[0]);")
    w("")
    w("}  // namespace win32k")
    with open(sys.argv[2], "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")
    disabled = sum(1 for s in syscalls if s["name"] in DENYLIST)
    print(f"{sys.argv[2]}: {len(rows)} syscalls ({disabled} disabled), {len(args)} args, "
          f"{len(fields)} read fields, {len(nested)} nested pointers, {len(values)} literals")


if __name__ == "__main__":
    main()
