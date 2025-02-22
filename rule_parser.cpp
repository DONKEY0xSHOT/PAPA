#include "rule_parser.h"
#include <fstream>
#include <sstream>
#include <cctype>
#include <stdexcept>
#include <iostream>
#include <filesystem>
#include <regex>
namespace fs = std::filesystem;

// ---------- Helper functions for string trimming ----------
static inline std::string trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    size_t end = s.find_last_not_of(" \t\r\n");
    return (start == std::string::npos) ? "" : s.substr(start, end - start + 1);
}

// ---------- Tokenizer for condition expressions ----------

enum class TokenType { LPAREN, RPAREN, AND, OR, COLON, IDENTIFIER, QUOTED_STRING, END };

struct Token {
    TokenType type;
    std::string value;
};

class ConditionLexer {
public:
    ConditionLexer(const std::string& input) : input_(input), pos_(0) { }

    Token getNextToken() {
        skipWhitespace();
        if (pos_ >= input_.size())
            return { TokenType::END, "" };

        char current = input_[pos_];
        if (current == '(') {
            pos_++;
            return { TokenType::LPAREN, "(" };
        }
        else if (current == ')') {
            pos_++;
            return { TokenType::RPAREN, ")" };
        }
        else if (current == ':') {
            pos_++;
            return { TokenType::COLON, ":" };
        }
        else if (current == '"') {
            // parse quoted string
            pos_++; // skip opening quote
            std::string result;
            while (pos_ < input_.size() && input_[pos_] != '"') {
                result.push_back(input_[pos_++]);
            }
            if (pos_ < input_.size() && input_[pos_] == '"')
                pos_++; // skip closing quote
            return { TokenType::QUOTED_STRING, result };
        }
        else if (std::isalpha(current)) {
            // parse identifier or keyword (AND, OR, api, string, opcode)
            std::string result;
            while (pos_ < input_.size() && (std::isalnum(input_[pos_]) || input_[pos_] == '_')) {
                result.push_back(input_[pos_++]);
            }
            if (result == "AND")
                return { TokenType::AND, result };
            else if (result == "OR")
                return { TokenType::OR, result };
            else
                return { TokenType::IDENTIFIER, result };
        }
        throw std::runtime_error("Unknown token in condition: " + std::string(1, current));
    }
private:
    void skipWhitespace() {
        while (pos_ < input_.size() && std::isspace(input_[pos_])) {
            pos_++;
        }
    }
    std::string input_;
    size_t pos_;
};

// ---------- Parser for condition expressions ----------

class ConditionParser {
public:
    ConditionParser(const std::string& input) : lexer_(input) {
        currentToken_ = lexer_.getNextToken();
    }

    std::unique_ptr<ConditionNode> parseExpression() {
        auto node = parseTerm();
        while (currentToken_.type == TokenType::OR) {
            consume(TokenType::OR);
            auto right = parseTerm();
            auto parent = std::make_unique<ConditionNode>();
            parent->type = NodeType::OR;
            parent->left = std::move(node);
            parent->right = std::move(right);
            node = std::move(parent);
        }
        return node;
    }
private:
    std::unique_ptr<ConditionNode> parseTerm() {
        auto node = parseFactor();
        while (currentToken_.type == TokenType::AND) {
            consume(TokenType::AND);
            auto right = parseFactor();
            auto parent = std::make_unique<ConditionNode>();
            parent->type = NodeType::AND;
            parent->left = std::move(node);
            parent->right = std::move(right);
            node = std::move(parent);
        }
        return node;
    }

    std::unique_ptr<ConditionNode> parseFactor() {
        if (currentToken_.type == TokenType::LPAREN) {
            consume(TokenType::LPAREN);
            auto node = parseExpression();
            consume(TokenType::RPAREN);
            return node;
        }
        else if (currentToken_.type == TokenType::IDENTIFIER) {
            // expect a leaf condition: identifier ":" quoted_string
            std::string id = currentToken_.value;
            consume(TokenType::IDENTIFIER);
            consume(TokenType::COLON);
            if (currentToken_.type != TokenType::QUOTED_STRING) {
                throw std::runtime_error("Expected quoted string after ':'");
            }
            std::string val = currentToken_.value;
            consume(TokenType::QUOTED_STRING);
            auto node = std::make_unique<ConditionNode>();
            node->type = NodeType::LEAF;
            if (id == "string")
                node->leafType = LeafType::STRING;
            else if (id == "api")
                node->leafType = LeafType::API;
            else if (id == "opcode")
                node->leafType = LeafType::OPCODE;
            else
                throw std::runtime_error("Unknown condition type: " + id);
            node->value = val;
            return node;
        }
        throw std::runtime_error("Unexpected token in condition parser: " + currentToken_.value);
    }

    void consume(TokenType expected) {
        if (currentToken_.type != expected) {
            throw std::runtime_error("Unexpected token: " + currentToken_.value);
        }
        currentToken_ = lexer_.getNextToken();
    }

    ConditionLexer lexer_;
    Token currentToken_;
};

// Public function to parse a condition string into an AST.
static std::unique_ptr<ConditionNode> parseConditionString(const std::string& condStr) {
    ConditionParser parser(condStr);
    return parser.parseExpression();
}

// ---------- Rule file parsing ----------

bool parseRuleFile(const std::string& filepath, Rule& rule) {
    std::ifstream infile(filepath);
    if (!infile) {
        std::cerr << "Failed to open rule file: " << filepath << std::endl;
        return false;
    }
    std::string line;
    std::string name, scopeStr, conditionStr;
    while (std::getline(infile, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue; // skip comments/empty lines
        auto pos = line.find(':');
        if (pos == std::string::npos) continue;
        std::string key = trim(line.substr(0, pos));
        std::string value = trim(line.substr(pos + 1));
        if (key == "name")
            name = value;
        else if (key == "scope")
            scopeStr = value;
        else if (key == "condition")
            conditionStr = value;
    }
    if (name.empty() || scopeStr.empty() || conditionStr.empty()) {
        std::cerr << "Incomplete rule file: " << filepath << std::endl;
        return false;
    }
    rule.name = name;
    if (scopeStr == "file")
        rule.scope = RuleScope::FILE;
    else if (scopeStr == "function")
        rule.scope = RuleScope::FUNCTION;
    else if (scopeStr == "basicblock")
        rule.scope = RuleScope::BASIC_BLOCK;
    else {
        std::cerr << "Unknown scope in rule file: " << scopeStr << std::endl;
        return false;
    }
    try {
        rule.condition = parseConditionString(conditionStr);
    }
    catch (const std::exception& e) {
        std::cerr << "Error parsing condition in rule file " << filepath << ": " << e.what() << std::endl;
        return false;
    }
    return true;
}

std::vector<Rule> parseRuleDirectory(const std::string& directoryPath) {
    std::vector<Rule> rules;
    for (const auto& entry : fs::directory_iterator(directoryPath)) {
        if (entry.is_regular_file()) {
            Rule rule;
            if (parseRuleFile(entry.path().string(), rule)) {
                rules.push_back(std::move(rule));
            }
        }
    }
    return rules;
}

#include "rule_parser.h"
#include <regex>
#include <stdexcept>
#include <cctype>

// Simple base64 decoder (without external libraries)
static unsigned char decodeBase64Char(char c) {
    if ('A' <= c && c <= 'Z') return c - 'A';
    if ('a' <= c && c <= 'z') return c - 'a' + 26;
    if ('0' <= c && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    throw std::runtime_error("Invalid base64 character");
}

static std::string decodeBase64(const std::string& in) {
    std::string out;
    int val = 0, valb = -8;
    for (unsigned char c : in) {
        if (std::isspace(c))
            continue;
        if (c == '=')
            break;
        val = (val << 6) + decodeBase64Char(c);
        valb += 6;
        if (valb >= 0) {
            out.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

bool evaluateCondition(const ConditionNode* node, const std::string& text) {
    if (!node)
        return false;
    if (node->type == NodeType::LEAF) {
        std::string pattern = node->value;
        bool isBase64 = false;
        bool isRegex = false;
        bool isCaseInsensitive = false;

        // Check for base64 modifier.
        if (pattern.rfind("b64:", 0) == 0) {
            isBase64 = true;
            pattern = pattern.substr(4);
        }
        // Check if pattern is enclosed in slashes (e.g. /.../ or /.../i).
        if (pattern.size() >= 2 && pattern.front() == '/' && pattern.find_last_of('/') != 0) {
            size_t lastSlash = pattern.find_last_of('/');
            if (lastSlash < pattern.size() - 1 && pattern[lastSlash + 1] == 'i') {
                isCaseInsensitive = true;
            }
            pattern = pattern.substr(1, lastSlash - 1);
            isRegex = true;
        }
        // If not explicitly marked as regex, treat the literal as a regex that matches exactly.
        if (!isRegex) {
            std::string escaped;
            for (char c : pattern) {
                if (std::strchr(".*+?^${}()|[]\\", c))
                    escaped.push_back('\\');
                escaped.push_back(c);
            }
            pattern = escaped;
            isRegex = true;
        }
        std::regex::flag_type flags = std::regex::ECMAScript;
        if (isCaseInsensitive)
            flags |= std::regex::icase;

        try {
            std::regex re(pattern, flags);
            if (isBase64) {
                // Use a regex that optionally strips quotes from the candidate.
                std::regex b64Regex("\"?([A-Za-z0-9+/]{4,}={0,2})\"?");
                auto begin = std::sregex_iterator(text.begin(), text.end(), b64Regex);
                auto end = std::sregex_iterator();
                for (auto i = begin; i != end; ++i) {
                    // Use the captured group (without surrounding quotes).
                    std::string candidate = (*i)[1].str();
                    try {
                        std::string decoded = decodeBase64(candidate);
                        if (std::regex_search(decoded, re))
                            return true;
                    }
                    catch (const std::exception&) {
                        continue;
                    }
                }
                return false;
            }
            else {
                return std::regex_search(text, re);
            }
        }
        catch (const std::regex_error& e) {
            std::cerr << "Regex error: " << e.what() << std::endl;
            return false;
        }
    }
    else if (node->type == NodeType::AND) {
        return evaluateCondition(node->left.get(), text) && evaluateCondition(node->right.get(), text);
    }
    else if (node->type == NodeType::OR) {
        return evaluateCondition(node->left.get(), text) || evaluateCondition(node->right.get(), text);
    }
    return false;
}
