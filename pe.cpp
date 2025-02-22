#include "disassembly.h"
#include <cctype>
#include <sstream>
#include <cstdlib>

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4267 4244)
#endif
#include <LIEF/PE.hpp>
#ifdef _MSC_VER
#pragma warning(pop)
#endif

bool loadPEFile(const std::string& filePath,
    std::vector<FunctionInfo>& functions,
    std::vector<uint8_t>& textSection,
    uint64_t& textSectionAddress,
    size_t& textSectionSize,
    std::vector<StringInfo>& strings,
    std::map<uint64_t, std::string>& imports)
{
    try {
        std::unique_ptr<LIEF::PE::Binary> binary = LIEF::PE::Parser::parse(filePath);
        if (!binary) {
            std::cerr << "Failed to parse the PE file: " << filePath << std::endl;
            return false;
        }

        const LIEF::PE::Section* text_sec = binary->get_section(".text");
        if (!text_sec) {
            std::cerr << "Failed to find .text section." << std::endl;
            return false;
        }
        textSection.assign(text_sec->content().begin(), text_sec->content().end());
        textSectionAddress = text_sec->virtual_address();
        textSectionSize = text_sec->size();

        const LIEF::PE::Export* exp = binary->get_export();
        if (exp) {
            auto entries = exp->entries();
            std::sort(entries.begin(), entries.end(), [](const LIEF::PE::ExportEntry& a, const LIEF::PE::ExportEntry& b) {
                return a.address() < b.address();
                });

            for (size_t i = 0; i < entries.size(); ++i) {
                uint64_t func_addr = entries[i].address();
                std::string func_name = entries[i].name();
                size_t func_size = 0;
                if (i < entries.size() - 1) {
                    func_size = entries[i + 1].address() - func_addr;
                }
                else {
                    func_size = textSectionSize - (func_addr - textSectionAddress);
                }
                if (func_addr < textSectionAddress || (func_addr - textSectionAddress + func_size) > textSectionSize) {
                    continue;
                }
                std::vector<uint8_t> func_code(textSection.begin() + (func_addr - textSectionAddress),
                    textSection.begin() + (func_addr - textSectionAddress + func_size));
                FunctionInfo fi;
                fi.name = func_name;
                fi.address = func_addr;
                fi.code = func_code;
                functions.push_back(fi);
            }
        }

        // Fallback: if no export info is found, disassemble the entire .text section.
        if (functions.empty()) {
            std::cout << "No export information found. Disassembling entire .text section." << std::endl;
            FunctionInfo fi;
            fi.name = "EntireTextSection";
            fi.address = textSectionAddress;
            // Use the entire .text section.
            fi.code = textSection;
            functions.push_back(fi);
        }

        // Extract imported functions.
        auto importsList = binary->imports();
        for (const auto& imp : importsList) {
            for (const auto& entry : imp.entries()) {
                // Use iat_address() as the correct accessor.
                uint64_t imp_addr = entry.iat_address();
                std::string imp_name = entry.name();
                if (!imp_name.empty()) {
                    imports[imp_addr] = imp_name;
                }
            }
        }

        // Extract strings from the .rdata section.
        const LIEF::PE::Section* rdata_sec = binary->get_section(".rdata");
        if (rdata_sec) {
            std::vector<uint8_t> rdata(rdata_sec->content().begin(), rdata_sec->content().end());
            uint64_t rdataAddress = rdata_sec->virtual_address();
            size_t i = 0;
            while (i < rdata.size()) {
                if (std::isprint(rdata[i]) && rdata[i] != 0) {
                    std::string s;
                    size_t j = i;
                    while (j < rdata.size() && std::isprint(rdata[j]) && rdata[j] != 0) {
                        s.push_back(rdata[j]);
                        j++;
                    }
                    if (s.size() >= 4) {
                        StringInfo strInfo;
                        strInfo.address = rdataAddress + i;
                        strInfo.value = s;
                        strings.push_back(strInfo);
                    }
                    i = j;
                }
                else {
                    i++;
                }
            }
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Exception while parsing PE file: " << e.what() << std::endl;
        return false;
    }
    return true;
}
