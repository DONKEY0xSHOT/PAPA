# PAPA: a CAPA-like PE Analysis Tool

## Overview

PAPA is a simple CAPA-like tool implemented in C++ that analyzes Windows Portable Executable (PE) files for specific capabilities. By disassembling the binary and scanning for strings, Windows API calls, and opcode patterns, the tool identifies indicators of various capabilities. It leverages a custom rule engine that uses a simple domain-specific language (DSL) to query disassembled code, making it an effective and lightweight alternative to more heavyweight analysis frameworks.

## Implementation

PAPA uses LIEF to parse Windows PE files and extract important sections, and Capstone to disassemble code into functions and basic blocks. A custom rule engine is integrated, which:
- Loads rule files from a specified directory.
- Parses rules written in a simple DSL supporting logical expressions (using AND/OR operators), regex with wildcards, case-insensitivity, and even base64 searches.
- Evaluates each rule against the disassembled code at three different scopes: the entire file, individual functions, or individual basic blocks.

This design allows the tool to quickly and efficiently identify areas of interest in the binary.

## Advantages

- **Speed:** By focusing on disassembled code and leveraging efficient in-memory string and regex matching, this tool is much faster than the original CAPA tool.
- **Lightweight:** The project avoids heavy dependencies for rule parsing by using a custom DSL and only relies on well-established libraries (LIEF and Capstone) for PE parsing and disassembly.
- **Flexibility:** Users can write custom rules to search at different scopes (file, function, basic block) and employ advanced matching techniques (regex with wildcards, case-insensitivity, and base64 decoding).
- **Ease of Use:** The rule engine is designed to be user-friendly. New rules can be added simply by dropping text files into the rules directory without needing to recompile the tool.

## Usage

### Building

Ensure you have a C++17-compliant compiler installed along with the following dependencies:
- **LIEF:** For parsing and analyzing PE files.
- **Capstone:** For disassembling binary code.

### Basic Use

The tool is run from the command line with the following syntax:
PAPA.exe {PE file path} {rule directory} [--scan-only]

- `PE file path`: Path to the Windows PE file you want to analyze.
- `rule directory`: Directory containing rule files.
- `--scan-only`: Optional flag to run in scan-only mode (only outputs the names of matched rules without printing the full disassembly).

### Rule File Format and Writing Rules

Each rule file uses a simple DSL with the following format:
name: <Rule Name> scope: <Scope> condition: (<Condition Expression>)


#### Fields

- **name:** A descriptive identifier for the rule.
- **scope:** Defines the level at which the rule is applied. Valid values are:
  - `file`: The rule is evaluated against the entire disassembled output.
  - `function`: The rule is evaluated per function.
  - `basicblock`: The rule is evaluated on each basic block.
- **condition:** A logical expression that combines conditions with the operators `AND` and `OR`. Conditions can target:
  - **API calls:** e.g., `api:"<pattern>"`  
  - **Strings:** e.g., `string:"<pattern>"`  
  - **Opcodes:** e.g., `opcode:"<pattern>"`  

#### Advanced Matching Features

- **Regex and Wildcards:**  
  Enclose the pattern in forward slashes to enable regex matching. For instance,  
  `api:"/MessageBoxA/i"`  
  will match the API call `MessageBoxA` in a case-insensitive manner. Wildcards can be used via standard regex constructs (e.g., `/Hello.*/`).

- **Base64 Search:**  
  Prefix the pattern with `b64:` to enable base64 matching. For example,  
  `string:"b64:/Hello World/i"`  
  instructs the tool to scan for base64-encoded substrings, decode them, and then perform a case-insensitive regex search for "Hello World".

#### Example Rules

1. **Detect MessageBoxA with Hello World in the same basic block:**

    ```
    name: Detect MessageBoxA with Hello world
    scope: basicblock
    condition: (api:"/MessageBoxA/i" AND string:"/Hello World/i")
    ```

2. **Detect a function-level capability to capture screenshots:**

    ```
    name: capture screenshot
    scope: function
    condition: ((api:"GetWindowDC" OR api:"GetDC" OR api:"CreateDC") AND (api:"BitBlt" OR api:"GetDIBits")) OR (api:"System.Drawing.Graphics::CopyFromScreen")

    ```

### Official rules
PAPA has over 600 official rules, which are official CAPA rules that were modified to support PAPA's DSL syntax.
We currently only support rules that don't use the "match", "section", "offset" & "number" features of CAPA - hopefully these would be supported in the future. 


### TODO

- [ ] **Support NOT Operator for Logics:**  
  Implement the NOT logical operator in our rule DSL to allow users to exclude specific conditions from matching.

- [ ] **Extend Encoding Support:**  
  Expand the current base64 matching feature to include additional encoding formats (e.g. base32, hex) for more robust detection.

- [ ] **Export Results to JSON:**  
  Add an option to output scan results in JSON format.

- [ ] **Support CAPA Rules Syntax:**  
  Prase CAPA-compatible rule syntax, making it possible to use existing CAPA rules.
