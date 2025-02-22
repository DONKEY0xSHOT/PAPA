#pragma once
#include "rule.h"
#include <string>
#include <vector>

// Parses a single rule file and returns true if successful.
bool parseRuleFile(const std::string& filepath, Rule& rule);

// Given a directory path, loads and parses all rule files in that directory.
std::vector<Rule> parseRuleDirectory(const std::string& directoryPath);

// Evaluates a parsed rule’s condition against a given text.
bool evaluateCondition(const ConditionNode* node, const std::string& text);
