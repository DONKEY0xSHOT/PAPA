#include "disassembly.h"

// Parses a Windows PE file, extracts the .text section, and retrieves exported functions.
// Also extracts string references from the .rdata section and imported functions.
// Parameters:
//   filePath           - Path to the PE file.
//   functions          - Output vector to store exported function details.
//   textSection        - Output vector to store the .text section bytes.
//   textSectionAddress - Output parameter for the .text section base address.
//   textSectionSize    - Output parameter for the .text section size.
//   strings            - Output vector to store extracted string references from the binary.
//   imports            - Output map to store imported functions (address -> function name).
// Returns true on success; false otherwise.
bool loadPEFile(const std::string& filePath,
    std::vector<FunctionInfo>& functions,
    std::vector<uint8_t>& textSection,
    uint64_t& textSectionAddress,
    size_t& textSectionSize,
    std::vector<StringInfo>& strings,
    std::map<uint64_t, std::string>& imports);

// (Other declarations remain unchanged.)
