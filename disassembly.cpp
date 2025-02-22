#include "disassembly.h"
#include <sstream>
#include <cctype>
#include <cstdlib>

// Helper function to annotate an instruction’s operand string using Capstone detail information.
std::string annotateInstruction(cs_insn* insn,
    const std::map<uint64_t, std::string>& imports,
    const std::vector<StringInfo>& strings) {

    // Start with the default operand string provided by Capstone.
    std::string annotated = std::string(insn->op_str);

    // Make sure that detail information is available.
    if (insn->detail == nullptr) {
        return annotated;
    }

    cs_x86* x86 = &(insn->detail->x86);

    // For each operand, try to compute an effective address.
    for (size_t i = 0; i < x86->op_count; i++) {
        cs_x86_op op = x86->operands[i];
        uint64_t effective_addr = 0;
        bool computed = false;

        // For memory operands using RIP-relative addressing.
        if (op.type == X86_OP_MEM && op.mem.base == X86_REG_RIP) {
            effective_addr = insn->address + insn->size + op.mem.disp;
            computed = true;
        }
        // For immediate operands.
        else if (op.type == X86_OP_IMM) {
            effective_addr = op.imm;
            computed = true;
        }

        if (computed) {
            std::ostringstream oss;
            bool annotatedFlag = false;
            // If the effective address matches an imported API, annotate it.
            auto it = imports.find(effective_addr);
            if (it != imports.end()) {
                oss << " ; " << it->second;
                annotatedFlag = true;
            }
            // If the effective address points to a string, annotate it.
            for (const auto& s : strings) {
                if (s.address == effective_addr) {
                    oss << " ; \"" << s.value << "\"";
                    annotatedFlag = true;
                    break;
                }
            }
            if (annotatedFlag) {
                // Append the annotations (for each operand, the annotation is appended to the end).
                annotated += oss.str();
            }
        }
    }
    return annotated;
}

std::vector<std::vector<Instruction>> disassembleFunction(
    const FunctionInfo& funcInfo,
    const std::map<uint64_t, std::string>& imports,
    const std::vector<StringInfo>& strings)
{
    std::vector<std::vector<Instruction>> blocks;
    csh handle;
    cs_insn* insn = nullptr;
    size_t count = 0;

    // Initialize Capstone for x86 64-bit disassembly.
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        std::cerr << "Failed to initialize Capstone." << std::endl;
        return blocks;
    }

    // Enable detail mode to get operand information.
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    // Disassemble the function’s code.
    count = cs_disasm(handle, funcInfo.code.data(), funcInfo.code.size(), funcInfo.address, 0, &insn);
    if (count == 0) {
        std::cerr << "Failed to disassemble function: " << funcInfo.name << std::endl;
        cs_close(&handle);
        return blocks;
    }

    std::vector<Instruction> instructions;
    for (size_t i = 0; i < count; i++) {
        Instruction inst;
        inst.address = insn[i].address;
        inst.mnemonic = insn[i].mnemonic;
        // Use our helper to annotate the instruction using detail mode.
        inst.op_str = annotateInstruction(&insn[i], imports, strings);
        instructions.push_back(inst);
    }
    cs_free(insn, count);
    cs_close(&handle);

    // Group instructions into basic blocks using a branch heuristic.
    std::vector<Instruction> currentBlock;
    auto isBranchInstruction = [](const Instruction& inst) -> bool {
        const std::vector<std::string> branchMnemonics = {
            "jmp", "je", "jne", "jg", "jge", "jl", "jle", "ja", "jae", "call", "ret"
        };
        for (const auto& mnemonic : branchMnemonics) {
            if (inst.mnemonic == mnemonic) {
                return true;
            }
        }
        return false;
        };

    for (const auto& inst : instructions) {
        currentBlock.push_back(inst);
        if (isBranchInstruction(inst)) {
            blocks.push_back(currentBlock);
            currentBlock.clear();
        }
    }
    if (!currentBlock.empty()) {
        blocks.push_back(currentBlock);
    }

    // --- Heuristic Filtering ---
    // Filter out blocks that contain no "meaningful" instructions.
    // Here we consider an instruction meaningful if its mnemonic is not "int3" or "nop".
    std::vector<std::vector<Instruction>> filteredBlocks;
    for (const auto& block : blocks) {
        int meaningfulCount = 0;
        for (const auto& inst : block) {
            if (inst.mnemonic != "int3" && inst.mnemonic != "nop")
                meaningfulCount++;
        }
        // Only add blocks that have at least one meaningful instruction.
        if (meaningfulCount > 0)
            filteredBlocks.push_back(block);
    }

    return filteredBlocks;
}