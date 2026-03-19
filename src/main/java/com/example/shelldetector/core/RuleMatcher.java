package com.example.shelldetector.core;

import com.example.shelldetector.model.Rule;
import com.example.shelldetector.model.RuleType;

import java.util.ArrayList;
import java.util.List;

public class RuleMatcher {

    public List<Rule> matchWhitelist(String command, List<Rule> rules) {
        List<Rule> matched = new ArrayList<>();
        for (Rule rule : rules) {
            if (rule.getType() == RuleType.WHITELIST && rule.matches(command)) {
                matched.add(rule);
            }
        }
        return matched;
    }

    public List<Rule> matchBlacklist(String command, List<Rule> rules) {
        List<Rule> matched = new ArrayList<>();
        for (Rule rule : rules) {
            if (rule.getType() == RuleType.BLACKLIST && rule.matches(command)) {
                matched.add(rule);
            }
        }
        return matched;
    }

    public boolean isEntireCommandWhitelisted(String entireCommand, List<Rule> rules) {
        // 只有当整条命令不包含命令分隔符时，才用子命令级白名单规则匹配
        // 或者有专门的整条命令白名单规则
        boolean hasCommandSeparators = entireCommand.contains(";") || entireCommand.contains("|") || entireCommand.contains("&");

        for (Rule rule : rules) {
            if (rule.getType() == com.example.shelldetector.model.RuleType.WHITELIST && rule.matches(entireCommand)) {
                // 如果包含命令分隔符，只有"整条命令专用"的白名单规则才生效
                // 判断：如果规则pattern包含命令分隔符，认为是整条命令规则
                if (hasCommandSeparators) {
                    String pattern = rule.getPattern();
                    if (pattern.contains(";") || pattern.contains("|") || pattern.contains("&")) {
                        return true;
                    }
                } else {
                    // 单一命令，可以直接用子命令级白名单规则
                    return true;
                }
            }
        }
        return false;
    }

    public boolean areAllCommandsWhitelisted(List<String> commands, List<Rule> rules) {
        if (commands.isEmpty()) {
            return false;
        }
        for (String cmd : commands) {
            if (matchWhitelist(cmd, rules).isEmpty()) {
                return false;
            }
        }
        return true;
    }
}
