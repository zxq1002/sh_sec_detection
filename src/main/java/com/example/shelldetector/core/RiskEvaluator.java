package com.example.shelldetector.core;

import com.example.shelldetector.model.RiskLevel;
import com.example.shelldetector.model.Rule;

import java.util.List;

public class RiskEvaluator {

    public RiskLevel evaluateHighestRisk(List<Rule> matchedRules) {
        RiskLevel highest = RiskLevel.SAFE;
        for (Rule rule : matchedRules) {
            if (rule.getRiskLevel().isHigherOrEqualTo(highest)) {
                highest = rule.getRiskLevel();
            }
        }
        return highest;
    }

    public boolean shouldBlock(RiskLevel riskLevel, RiskLevel threshold) {
        return riskLevel.isHigherOrEqualTo(threshold);
    }
}
