package com.example.shelldetector.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class DetectionResult implements Serializable {
    @JsonProperty("passed")
    private final boolean passed;

    @JsonProperty("matchedRules")
    private final List<Rule> matchedRules;

    @JsonProperty("highestRiskLevel")
    private final RiskLevel highestRiskLevel;

    @JsonProperty("blockReason")
    private final String blockReason;

    private DetectionResult(Builder builder) {
        this.passed = builder.passed;
        this.matchedRules = Collections.unmodifiableList(new ArrayList<>(builder.matchedRules));
        this.highestRiskLevel = builder.highestRiskLevel;
        this.blockReason = builder.blockReason;
    }

    public boolean isPassed() { return passed; }
    public List<Rule> getMatchedRules() { return matchedRules; }
    public RiskLevel getHighestRiskLevel() { return highestRiskLevel; }
    public String getBlockReason() { return blockReason; }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private boolean passed = true;
        private List<Rule> matchedRules = new ArrayList<>();
        private RiskLevel highestRiskLevel = RiskLevel.SAFE;
        private String blockReason;

        public Builder passed(boolean passed) {
            this.passed = passed;
            return this;
        }

        public Builder addMatchedRule(Rule rule) {
            this.matchedRules.add(rule);
            if (rule.getRiskLevel().isHigherOrEqualTo(this.highestRiskLevel)) {
                this.highestRiskLevel = rule.getRiskLevel();
            }
            return this;
        }

        public Builder highestRiskLevel(RiskLevel level) {
            this.highestRiskLevel = level;
            return this;
        }

        public Builder blockReason(String reason) {
            this.blockReason = reason;
            return this;
        }

        public DetectionResult build() {
            return new DetectionResult(this);
        }
    }
}
