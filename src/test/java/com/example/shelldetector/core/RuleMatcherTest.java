package com.example.shelldetector.core;

import com.example.shelldetector.model.Rule;
import com.example.shelldetector.model.RuleType;
import com.example.shelldetector.model.RiskLevel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * RuleMatcher 测试类
 * <p>
 * 测试规则匹配器的功能，包括：
 * - 白名单规则匹配
 * - 黑名单规则匹配
 * - 整条命令白名单检查
 * - 所有子命令白名单检查
 * </p>
 */
class RuleMatcherTest {

    private RuleMatcher matcher;
    private List<Rule> rules;

    @BeforeEach
    void setUp() {
        matcher = new RuleMatcher();
        rules = new ArrayList<>();

        rules.add(Rule.builder()
                .id("whitelist-ls")
                .name("ls")
                .type(RuleType.WHITELIST)
                .pattern("^\\s*ls\\b")
                .riskLevel(RiskLevel.SAFE)
                .build());
        rules.add(Rule.builder()
                .id("whitelist-echo")
                .name("echo")
                .type(RuleType.WHITELIST)
                .pattern("^\\s*echo\\b")
                .riskLevel(RiskLevel.SAFE)
                .build());
        rules.add(Rule.builder()
                .id("blacklist-rm")
                .name("rm")
                .type(RuleType.BLACKLIST)
                .pattern("rm\\s+.*-rf")
                .riskLevel(RiskLevel.RISK)
                .build());
        rules.add(Rule.builder()
                .id("blacklist-danger")
                .name("danger")
                .type(RuleType.BLACKLIST)
                .pattern("danger")
                .riskLevel(RiskLevel.DANGER)
                .build());
    }

    @Test
    void testMatchWhitelistWithNullCommand() {
        List<Rule> result = matcher.matchWhitelist(null, rules);
        assertTrue(result.isEmpty());
    }

    @Test
    void testMatchWhitelistWithNullRules() {
        List<Rule> result = matcher.matchWhitelist("ls", null);
        assertTrue(result.isEmpty());
    }

    @Test
    void testMatchWhitelistSuccess() {
        List<Rule> result = matcher.matchWhitelist("ls -la", rules);
        assertEquals(1, result.size());
        assertEquals("whitelist-ls", result.get(0).getId());
    }

    @Test
    void testMatchWhitelistNoMatch() {
        List<Rule> result = matcher.matchWhitelist("unknown", rules);
        assertTrue(result.isEmpty());
    }

    @Test
    void testMatchWhitelistSkipsBlacklistRules() {
        List<Rule> result = matcher.matchWhitelist("rm -rf /", rules);
        assertTrue(result.isEmpty());
    }

    @Test
    void testMatchWhitelistSkipsDisabledRules() {
        Rule disabledRule = Rule.builder()
                .id("disabled")
                .whitelist()
                .pattern("disabled")
                .enabled(false)
                .build();
        rules.add(disabledRule);

        List<Rule> result = matcher.matchWhitelist("disabled", rules);
        assertTrue(result.isEmpty());
    }

    @Test
    void testMatchWhitelistSkipsNullRules() {
        rules.add(null);
        List<Rule> result = matcher.matchWhitelist("ls -la", rules);
        assertEquals(1, result.size());
    }

    @Test
    void testMatchBlacklistWithNullCommand() {
        List<Rule> result = matcher.matchBlacklist(null, rules);
        assertTrue(result.isEmpty());
    }

    @Test
    void testMatchBlacklistWithNullRules() {
        List<Rule> result = matcher.matchBlacklist("rm -rf", null);
        assertTrue(result.isEmpty());
    }

    @Test
    void testMatchBlacklistSuccess() {
        List<Rule> result = matcher.matchBlacklist("rm -rf /tmp", rules);
        assertEquals(1, result.size());
        assertEquals("blacklist-rm", result.get(0).getId());
    }

    @Test
    void testMatchBlacklistNoMatch() {
        List<Rule> result = matcher.matchBlacklist("ls -la", rules);
        assertTrue(result.isEmpty());
    }

    @Test
    void testMatchBlacklistSkipsWhitelistRules() {
        List<Rule> result = matcher.matchBlacklist("ls -la", rules);
        assertTrue(result.isEmpty());
    }

    @Test
    void testMatchBlacklistMultipleMatches() {
        List<Rule> result = matcher.matchBlacklist("rm -rf danger", rules);
        assertEquals(2, result.size());
    }

    @Test
    void testIsEntireCommandWhitelistedWithNullCommand() {
        assertFalse(matcher.isEntireCommandWhitelisted(null, rules));
    }

    @Test
    void testIsEntireCommandWhitelistedWithNullRules() {
        assertFalse(matcher.isEntireCommandWhitelisted("ls", null));
    }

    @Test
    void testIsEntireCommandWhitelistedSuccess() {
        assertTrue(matcher.isEntireCommandWhitelisted("ls -la", rules));
    }

    @Test
    void testIsEntireCommandWhitelistedNoMatch() {
        assertFalse(matcher.isEntireCommandWhitelisted("rm -rf", rules));
    }

    @Test
    void testIsEntireCommandWhitelistedSkipsNullRules() {
        rules.add(null);
        assertTrue(matcher.isEntireCommandWhitelisted("ls -la", rules));
    }

    @Test
    void testAreAllCommandsWhitelistedWithNullCommands() {
        assertFalse(matcher.areAllCommandsWhitelisted(null, rules));
    }

    @Test
    void testAreAllCommandsWhitelistedWithEmptyCommands() {
        assertFalse(matcher.areAllCommandsWhitelisted(new ArrayList<>(), rules));
    }

    @Test
    void testAreAllCommandsWhitelistedWithNullRules() {
        List<String> commands = new ArrayList<>();
        commands.add("ls");
        assertFalse(matcher.areAllCommandsWhitelisted(commands, null));
    }

    @Test
    void testAreAllCommandsWhitelistedSuccess() {
        List<String> commands = new ArrayList<>();
        commands.add("ls -la");
        commands.add("echo hello");
        assertTrue(matcher.areAllCommandsWhitelisted(commands, rules));
    }

    @Test
    void testAreAllCommandsWhitelistedSomeNotWhitelisted() {
        List<String> commands = new ArrayList<>();
        commands.add("ls -la");
        commands.add("unknown");
        assertFalse(matcher.areAllCommandsWhitelisted(commands, rules));
    }

    @Test
    void testAreAllCommandsWhitelistedWithNullCommand() {
        List<String> commands = new ArrayList<>();
        commands.add("ls -la");
        commands.add(null);
        assertFalse(matcher.areAllCommandsWhitelisted(commands, rules));
    }

    @Test
    void testMatchWhitelistFindsAllMatchingRules() {
        rules.add(Rule.builder()
                .id("whitelist-ls-2")
                .whitelist()
                .pattern("ls")
                .build());

        List<Rule> result = matcher.matchWhitelist("ls -la", rules);
        assertEquals(2, result.size());
    }

    @Test
    void testMatchBlacklistFindsAllMatchingRules() {
        rules.add(Rule.builder()
                .id("blacklist-rm-2")
                .blacklist()
                .pattern("rm")
                .riskLevel(RiskLevel.RISK)
                .build());

        List<Rule> result = matcher.matchBlacklist("rm -rf", rules);
        assertEquals(2, result.size());
    }
}
