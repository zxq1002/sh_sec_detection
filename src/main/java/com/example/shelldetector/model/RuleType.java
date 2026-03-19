package com.example.shelldetector.model;

/**
 * 规则类型枚举 - 定义白名单和黑名单两种规则类型
 * <p>
 * 白名单优先：先检查白名单，通过则直接放行；不匹配才检查黑名单。
 * </p>
 */
public enum RuleType {
    /** 白名单 - 匹配则直接通过检测 */
    WHITELIST,
    /** 黑名单 - 匹配则根据风险等级决定是否拦截 */
    BLACKLIST
}
