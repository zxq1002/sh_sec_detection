package com.example.shelldetector.core;

import com.example.shelldetector.model.RiskLevel;
import com.example.shelldetector.model.Rule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * RuleConflictChecker 测试类
 * <p>
 * 测试规则冲突检测功能，包括：
 * - 白名单与黑名单冲突检测
 * - 相同类型规则重叠检测
 * - 重复规则ID检测
 * </p>
 */
class RuleConflictCheckerTest {

    private RuleConflictChecker checker;

    @BeforeEach
    void setUp() {
        checker = new RuleConflictChecker();
    }

    @Test
    void testEmptyRulesShouldHaveNoConflicts() {
        List<RuleConflictChecker.Conflict> conflicts = checker.checkConflicts(new ArrayList<>());
        assertTrue(conflicts.isEmpty());
    }

    @Test
    void testSingleRuleShouldHaveNoConflicts() {
        List<Rule> rules = new ArrayList<>();
        rules.add(Rule.builder()
                .id("test1")
                .pattern("remove.*")
                .blacklist()
                .build());

        List<RuleConflictChecker.Conflict> conflicts = checker.checkConflicts(rules);
        assertTrue(conflicts.isEmpty());
    }

    @Test
    void testWhitelistAndBlacklistOverlapShouldDetectConflict() {
        List<Rule> rules = new ArrayList<>();
        rules.add(Rule.builder()
                .id("white-list")
                .name("list whitelist")
                .pattern("^list\\b")
                .whitelist()
                .build());
        rules.add(Rule.builder()
                .id("black-list")
                .name("list blacklist")
                .pattern("list.*")
                .blacklist()
                .riskLevel(RiskLevel.RISK)
                .build());

        List<RuleConflictChecker.Conflict> conflicts = checker.checkConflicts(rules);
        assertFalse(conflicts.isEmpty(), "Should detect overlap for 3+ char words");
        assertEquals(1, conflicts.size());
        assertTrue(conflicts.get(0).getDescription().contains("Whitelist and blacklist"));
    }

    @Test
    void testDuplicateIdShouldDetectConflict() {
        List<Rule> rules = new ArrayList<>();
        rules.add(Rule.builder()
                .id("duplicate-id")
                .pattern("remove.*")
                .blacklist()
                .build());
        rules.add(Rule.builder()
                .id("duplicate-id")
                .pattern("list.*")
                .whitelist()
                .build());

        List<RuleConflictChecker.Conflict> conflicts = checker.checkConflicts(rules);
        assertFalse(conflicts.isEmpty());
        assertTrue(conflicts.get(0).getDescription().contains("Duplicate rule ID"));
    }

    @Test
    void testTwoBlacklistOverlapShouldDetectConflict() {
        List<Rule> rules = new ArrayList<>();
        rules.add(Rule.builder()
                .id("black1")
                .name("remove all")
                .pattern("remove.*")
                .blacklist()
                .riskLevel(RiskLevel.RISK)
                .build());
        rules.add(Rule.builder()
                .id("black2")
                .name("remove rf")
                .pattern("remove\\s+-rf")
                .blacklist()
                .riskLevel(RiskLevel.DANGER)
                .build());

        List<RuleConflictChecker.Conflict> conflicts = checker.checkConflicts(rules);
        assertFalse(conflicts.isEmpty(), "Should detect overlap for 3+ char words");
        assertTrue(conflicts.get(0).getDescription().contains("Blacklist rules"));
    }

    @Test
    void testTwoWhitelistOverlapShouldDetectConflict() {
        List<Rule> rules = new ArrayList<>();
        rules.add(Rule.builder()
                .id("white1")
                .name("list commands")
                .pattern("list.*")
                .whitelist()
                .build());
        rules.add(Rule.builder()
                .id("white2")
                .name("list la")
                .pattern("list\\s+-la")
                .whitelist()
                .build());

        List<RuleConflictChecker.Conflict> conflicts = checker.checkConflicts(rules);
        assertFalse(conflicts.isEmpty(), "Should detect overlap for 3+ char words");
        assertTrue(conflicts.get(0).getDescription().contains("Whitelist rules"));
    }

    @Test
    void testDisabledRulesShouldBeIgnored() {
        List<Rule> rules = new ArrayList<>();
        rules.add(Rule.builder()
                .id("white-list")
                .pattern("^list\\b")
                .whitelist()
                .enabled(false)
                .build());
        rules.add(Rule.builder()
                .id("black-list")
                .pattern("list.*")
                .blacklist()
                .enabled(false)
                .build());

        List<RuleConflictChecker.Conflict> conflicts = checker.checkConflicts(rules);
        assertTrue(conflicts.isEmpty());
    }

    @Test
    void testUnrelatedRulesShouldHaveNoConflicts() {
        List<Rule> rules = new ArrayList<>();
        rules.add(Rule.builder()
                .id("white-list")
                .pattern("^list\\b")
                .whitelist()
                .build());
        rules.add(Rule.builder()
                .id("black-remove")
                .pattern("remove.*")
                .blacklist()
                .riskLevel(RiskLevel.RISK)
                .build());

        List<RuleConflictChecker.Conflict> conflicts = checker.checkConflicts(rules);
        assertTrue(conflicts.isEmpty());
    }

    @Test
    void testConflictToStringFormat() {
        Rule rule1 = Rule.builder()
                .id("rule1")
                .name("Test Rule 1")
                .pattern("test1")
                .whitelist()
                .build();
        Rule rule2 = Rule.builder()
                .id("rule2")
                .name("Test Rule 2")
                .pattern("test2")
                .blacklist()
                .riskLevel(RiskLevel.RISK)
                .build();

        RuleConflictChecker.Conflict conflict = new RuleConflictChecker.Conflict(
                rule1, rule2, "Test conflict description");

        String str = conflict.toString();
        assertTrue(str.contains("Test Rule 1"));
        assertTrue(str.contains("Test Rule 2"));
        assertTrue(str.contains("Test conflict description"));
        assertEquals(rule1, conflict.getRule1());
        assertEquals(rule2, conflict.getRule2());
        assertEquals("Test conflict description", conflict.getDescription());
    }
}
