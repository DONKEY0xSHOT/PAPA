#pragma once

#include <iostream>
#include <vector>
#include <string>
#include <cstdint>
#include <algorithm>
#include <exception>
#include <memory>
#include <map>

// Disable warnings from LIEF headers (MSVC only)
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4267 4244)
#endif
#include <LIEF/PE.hpp>
#ifdef _MSC_VER
#pragma warning(pop)
#endif

#include <capstone/capstone.h>

// Structure to hold function information extracted from the PE file.
struct FunctionInfo {
    std::string name;             // Function name (from the export table)
    uint64_t address;             // Virtual address where the function starts
    std::vector<uint8_t> code;    // Raw bytes of the function (extracted from the .text section)
};

// Structure to represent a disassembled instruction.
struct Instruction {
    uint64_t address;             // Address of the instruction
    std::string mnemonic;         // Mnemonic (e.g. "mov", "jmp")
    std::string op_str;           // Operand string (e.g. "eax, ebx")
};

// New structure for representing string references found in the binary.
struct StringInfo {
    uint64_t address; // Virtual address of the string in the binary.
    std::string value; // The extracted string value.
};

// Disassemble a function's code and annotate instructions with Windows API calls and string references.
// The implementation is provided in disassembly.cpp.
std::vector<std::vector<Instruction>> disassembleFunction(
    const FunctionInfo& funcInfo,
    const std::map<uint64_t, std::string>& imports,
    const std::vector<StringInfo>& strings);
