package com.example.shelldetector.core;

import com.example.shelldetector.model.Rule;
import com.example.shelldetector.model.RuleType;

import java.util.ArrayList;
import java.util.List;

/**
 * 规则匹配器 - 提供黑白名单规则的匹配能力
 * <p>
 * 设计原则：所有匹配逻辑完全依赖规则定义，无任何硬编码的特殊字符检查。
 * 重定向操作符、命令分隔符等都通过黑白名单规则来控制。
 * </p>
 */
public class RuleMatcher {

    /**
     * 匹配白名单规则
     *
     * @param command 待检测的命令
     * @param rules 规则列表
     * @return 匹配成功的白名单规则列表
     */
    public List<Rule> matchWhitelist(String command, List<Rule> rules) {
        List<Rule> matched = new ArrayList<>();
        if (command == null || rules == null) {
            return matched;
        }
        for (Rule rule : rules) {
            if (rule != null && rule.getType() == RuleType.WHITELIST && rule.matches(command)) {
                matched.add(rule);
            }
        }
        return matched;
    }

    /**
     * 匹配黑名单规则
     *
     * @param command 待检测的命令
     * @param rules 规则列表
     * @return 匹配成功的黑名单规则列表
     */
    public List<Rule> matchBlacklist(String command, List<Rule> rules) {
        List<Rule> matched = new ArrayList<>();
        if (command == null || rules == null) {
            return matched;
        }
        for (Rule rule : rules) {
            if (rule != null && rule.getType() == RuleType.BLACKLIST && rule.matches(command)) {
                matched.add(rule);
            }
        }
        return matched;
    }

    /**
     * 检查整条命令是否匹配白名单
     * <p>
     * 完全依赖白名单规则匹配，无硬编码逻辑。
     * 特殊字符（如 ; | & > <）的处理完全由规则决定。
     * </p>
     *
     * @param entireCommand 完整的命令字符串
     * @param rules 规则列表
     * @return true 表示整条命令匹配白名单
     */
    public boolean isEntireCommandWhitelisted(String entireCommand, List<Rule> rules) {
        if (entireCommand == null || rules == null) {
            return false;
        }
        // 完全依赖白名单规则匹配，无硬编码逻辑
        for (Rule rule : rules) {
            if (rule != null && rule.getType() == com.example.shelldetector.model.RuleType.WHITELIST && rule.matches(entireCommand)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 检查所有子命令是否都匹配白名单
     * <p>
     * 完全依赖白名单规则匹配，无硬编码逻辑。
     * 只有当所有子命令都匹配白名单时才返回 true。
     * </p>
     *
     * @param commands 子命令列表
     * @param rules 规则列表
     * @return true 表示所有子命令都匹配白名单
     */
    public boolean areAllCommandsWhitelisted(List<String> commands, List<Rule> rules) {
        if (commands == null || commands.isEmpty() || rules == null) {
            return false;
        }
        // 完全依赖白名单规则匹配，无硬编码逻辑
        for (String cmd : commands) {
            if (cmd == null) {
                return false;
            }
            if (matchWhitelist(cmd, rules).isEmpty()) {
                return false;
            }
        }
        return true;
    }
}
