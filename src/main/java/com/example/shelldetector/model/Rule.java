package com.example.shelldetector.model;

import com.example.shelldetector.exception.InvalidPatternException;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public class Rule implements Serializable {
    @JsonProperty("id")
    private String id;

    @JsonProperty("name")
    private String name;

    @JsonProperty("type")
    private RuleType type;

    @JsonProperty("pattern")
    private String pattern;

    @JsonIgnore
    private transient Pattern compiledPattern;

    @JsonProperty("riskLevel")
    private RiskLevel riskLevel;

    @JsonProperty("description")
    private String description;

    @JsonProperty("enabled")
    private boolean enabled;

    private Rule() {
    }

    public String getId() { return id; }
    public String getName() { return name; }
    public RuleType getType() { return type; }
    public String getPattern() { return pattern; }
    public RiskLevel getRiskLevel() { return riskLevel; }
    public String getDescription() { return description; }
    public boolean isEnabled() { return enabled; }

    @JsonIgnore
    public Pattern getCompiledPattern() {
        if (compiledPattern == null && pattern != null) {
            try {
                compiledPattern = Pattern.compile(pattern);
            } catch (PatternSyntaxException e) {
                throw new InvalidPatternException("Invalid regex pattern: " + pattern, e);
            }
        }
        return compiledPattern;
    }

    public boolean matches(String command) {
        if (!enabled || pattern == null) {
            return false;
        }
        return getCompiledPattern().matcher(command).find();
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String id;
        private String name;
        private RuleType type = RuleType.BLACKLIST;
        private String pattern;
        private RiskLevel riskLevel = RiskLevel.RISK;
        private String description;
        private boolean enabled = true;

        public Builder id(String id) {
            this.id = id;
            return this;
        }

        public Builder name(String name) {
            this.name = name;
            return this;
        }

        public Builder type(RuleType type) {
            this.type = type;
            return this;
        }

        public Builder whitelist() {
            this.type = RuleType.WHITELIST;
            return this;
        }

        public Builder blacklist() {
            this.type = RuleType.BLACKLIST;
            return this;
        }

        public Builder pattern(String pattern) {
            this.pattern = pattern;
            return this;
        }

        public Builder riskLevel(RiskLevel riskLevel) {
            this.riskLevel = riskLevel;
            return this;
        }

        public Builder description(String description) {
            this.description = description;
            return this;
        }

        public Builder enabled(boolean enabled) {
            this.enabled = enabled;
            return this;
        }

        public Rule build() {
            Rule rule = new Rule();
            rule.id = this.id;
            rule.name = this.name;
            rule.type = this.type;
            rule.pattern = this.pattern;
            rule.riskLevel = this.riskLevel;
            rule.description = this.description;
            rule.enabled = this.enabled;
            return rule;
        }
    }
}
