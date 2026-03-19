package com.example.shelldetector.core;

import com.example.shelldetector.model.RiskLevel;
import com.example.shelldetector.model.Rule;

import java.util.List;

public class RiskEvaluator {

    public RiskLevel evaluateHighestRisk(List<Rule> matchedRules) {
        RiskLevel highest = RiskLevel.SAFE;
        if (matchedRules == null) {
            return highest;
        }
        for (Rule rule : matchedRules) {
            if (rule != null && rule.getRiskLevel() != null && rule.getRiskLevel().isHigherOrEqualTo(highest)) {
                highest = rule.getRiskLevel();
            }
        }
        return highest;
    }

    public boolean shouldBlock(RiskLevel riskLevel, RiskLevel threshold) {
        if (riskLevel == null || threshold == null) {
            return false;
        }
        return riskLevel.isHigherOrEqualTo(threshold);
    }
}
