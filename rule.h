#pragma once
#include <string>
#include <memory>

enum class RuleScope { FILE, FUNCTION, BASIC_BLOCK };

enum class NodeType { LEAF, AND, OR };
enum class LeafType { STRING, API, OPCODE };

struct ConditionNode {
    NodeType type;
    // Valid if type == LEAF.
    LeafType leafType;
    std::string value; // The text to search for.
    // Valid if type is AND/OR.
    std::unique_ptr<ConditionNode> left;
    std::unique_ptr<ConditionNode> right;
};

struct Rule {
    std::string name;
    RuleScope scope;
    std::unique_ptr<ConditionNode> condition;
};
