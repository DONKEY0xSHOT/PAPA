#include "disassembly.h"
#include "pe.h"
#include "rule_parser.h"
#include <map>
#include <vector>
#include <sstream>
#include <iostream>

/// Helper functions to convert disassembly blocks into strings.
std::string basicBlockToString(const std::vector<Instruction>& block) {
    std::ostringstream oss;
    for (const auto& inst : block) {
        oss << "0x" << std::hex << inst.address << ": "
            << inst.mnemonic << " " << inst.op_str << "\n";
    }
    return oss.str();
}

std::string functionToString(const std::vector<std::vector<Instruction>>& blocks) {
    std::ostringstream oss;
    for (const auto& block : blocks) {
        oss << basicBlockToString(block);
    }
    return oss.str();
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <PE file path> <rule directory> [--scan-only]" << std::endl;
        return 1;
    }
    std::string filePath = argv[1];
    std::string ruleDir = argv[2];

    // If the optional third parameter "--scan-only" is provided, then disable printing of disassembly.
    bool printDisassembly = true;
    if (argc >= 4) {
        std::string mode(argv[3]);
        if (mode == "--scan-only") {
            printDisassembly = false;
        }
    }

    std::vector<FunctionInfo> functions;
    std::vector<uint8_t> textSection;
    uint64_t textSectionAddress = 0;
    size_t textSectionSize = 0;
    std::vector<StringInfo> strings;
    std::map<uint64_t, std::string> imports;

    if (!loadPEFile(filePath, functions, textSection, textSectionAddress, textSectionSize, strings, imports)) {
        std::cerr << "Error loading PE file." << std::endl;
        return 1;
    }

    // If no export info found, disassemble entire .text section.
    if (functions.empty()) {
        std::cout << "No export information found. Disassembling entire .text section." << std::endl;
        FunctionInfo fi;
        fi.name = "EntireTextSection";
        fi.address = textSectionAddress;
        fi.code = textSection;
        functions.push_back(fi);
    }

    // Disassemble each function.
    std::vector<std::pair<FunctionInfo, std::vector<std::vector<Instruction>>>> disassembled;
    for (const auto& func : functions) {
        auto blocks = disassembleFunction(func, imports, strings);
        disassembled.push_back({ func, blocks });
    }

    // Load all rules from the rule directory.
    std::vector<Rule> rules = parseRuleDirectory(ruleDir);

    // For each rule, evaluate it against the disassembly.
    // A rule is matched if any instance in the specified scope contains the condition.
    std::vector<std::string> matchedRuleNames;
    for (const auto& rule : rules) {
        bool matched = false;
        if (rule.scope == RuleScope::FILE) {
            std::ostringstream oss;
            for (const auto& p : disassembled) {
                oss << functionToString(p.second);
            }
            std::string fileText = oss.str();
            matched = evaluateCondition(rule.condition.get(), fileText);
        }
        else if (rule.scope == RuleScope::FUNCTION) {
            for (const auto& p : disassembled) {
                std::string funcText = functionToString(p.second);
                if (evaluateCondition(rule.condition.get(), funcText)) {
                    matched = true;
                    break;
                }
            }
        }
        else if (rule.scope == RuleScope::BASIC_BLOCK) {
            for (const auto& p : disassembled) {
                for (const auto& block : p.second) {
                    std::string bbText = basicBlockToString(block);
                    if (evaluateCondition(rule.condition.get(), bbText)) {
                        matched = true;
                        break;
                    }
                }
                if (matched)
                    break;
            }
        }
        if (matched) {
            matchedRuleNames.push_back(rule.name);
        }
    }

    // Only print disassembled code if not in scan-only mode.
    if (printDisassembly) {
        for (const auto& p : disassembled) {
            std::cout << "Function: " << p.first.name << " at 0x"
                << std::hex << p.first.address << std::dec << std::endl;
            int blockCount = 1;
            for (const auto& block : p.second) {
                std::cout << "  Basic Block " << blockCount++ << ":\n";
                for (const auto& inst : block) {
                    std::cout << "    0x" << std::hex << inst.address << ": "
                        << inst.mnemonic << " " << inst.op_str << std::dec << std::endl;
                }
            }
            std::cout << std::endl;
        }
    }

    // Output the names of each rule that was matched.
    std::cout << "Matched Rules:" << std::endl;
    for (const auto& name : matchedRuleNames) {
        std::cout << "  " << name << std::endl;
    }

    return 0;
}
