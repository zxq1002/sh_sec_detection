package com.example.shelldetector;

import com.example.shelldetector.builtin.BuiltinRules;
import com.example.shelldetector.config.DetectionConfig;
import com.example.shelldetector.core.DetectionEngine;
import com.example.shelldetector.model.DetectionResult;
import com.example.shelldetector.model.RiskLevel;
import com.example.shelldetector.model.Rule;
import com.example.shelldetector.persistence.RuleLoader;
import com.example.shelldetector.persistence.RuleSaver;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class ShellDetector {
    private final DetectionConfig config;
    private final DetectionEngine engine;
    private final Map<String, Rule> rules;

    private ShellDetector(Builder builder) {
        this.config = builder.config;
        this.engine = new DetectionEngine(config);
        this.rules = new ConcurrentHashMap<>();
        for (Rule rule : builder.rules) {
            this.rules.put(rule.getId(), rule);
        }
    }

    public DetectionResult detect(String command) {
        return engine.detect(command, new ArrayList<>(rules.values()));
    }

    public void addRule(Rule rule) {
        if (rule == null || rule.getId() == null) {
            throw new IllegalArgumentException("Rule and rule id cannot be null");
        }
        rules.put(rule.getId(), rule);
    }

    public void removeRule(String ruleId) {
        if (ruleId != null) {
            rules.remove(ruleId);
        }
    }

    public void updateRule(Rule rule) {
        if (rule == null || rule.getId() == null) {
            throw new IllegalArgumentException("Rule and rule id cannot be null");
        }
        rules.put(rule.getId(), rule);
    }

    public Rule getRule(String ruleId) {
        if (ruleId == null) {
            return null;
        }
        return rules.get(ruleId);
    }

    public List<Rule> getRules() {
        return new ArrayList<>(rules.values());
    }

    public void saveRulesToJson(String path) {
        if (path == null || path.trim().isEmpty()) {
            throw new IllegalArgumentException("Path cannot be null or empty");
        }
        RuleSaver.saveToJson(getRules(), path);
    }

    public void saveRulesToJson(File file) {
        if (file == null) {
            throw new IllegalArgumentException("File cannot be null");
        }
        RuleSaver.saveToJson(getRules(), file);
    }

    public static ShellDetector createDefault() {
        return builder().withDefaultRules().build();
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private DetectionConfig config = DetectionConfig.builder().build();
        private List<Rule> rules = new ArrayList<>();

        public Builder withConfig(DetectionConfig config) {
            if (config == null) {
                throw new IllegalArgumentException("Config cannot be null");
            }
            this.config = config;
            return this;
        }

        public Builder withThreshold(RiskLevel threshold) {
            if (threshold == null) {
                throw new IllegalArgumentException("Threshold cannot be null");
            }
            this.config = DetectionConfig.builder().threshold(threshold).build();
            return this;
        }

        public Builder withDefaultRules() {
            this.rules.addAll(BuiltinRules.getRules());
            return this;
        }

        public Builder withRules(List<Rule> rules) {
            if (rules != null) {
                this.rules.addAll(rules);
            }
            return this;
        }

        public Builder withRule(Rule rule) {
            if (rule == null) {
                throw new IllegalArgumentException("Rule cannot be null");
            }
            this.rules.add(rule);
            return this;
        }

        public Builder withRulesFromJson(String path) {
            if (path == null || path.trim().isEmpty()) {
                throw new IllegalArgumentException("Path cannot be null or empty");
            }
            this.rules.addAll(RuleLoader.loadFromJson(path));
            return this;
        }

        public Builder withRulesFromJson(File file) {
            if (file == null) {
                throw new IllegalArgumentException("File cannot be null");
            }
            this.rules.addAll(RuleLoader.loadFromJson(file));
            return this;
        }

        public ShellDetector build() {
            return new ShellDetector(this);
        }
    }
}
