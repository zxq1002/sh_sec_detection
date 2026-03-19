package com.example.shelldetector.core;

import com.example.shelldetector.config.DetectionConfig;
import com.example.shelldetector.exception.ShellParseException;
import com.example.shelldetector.model.DetectionResult;
import com.example.shelldetector.model.RiskLevel;
import com.example.shelldetector.model.Rule;
import com.example.shelldetector.parser.ShellCommandExtractor;

import java.util.ArrayList;
import java.util.List;

public class DetectionEngine {
    private final DetectionConfig config;
    private final RuleMatcher ruleMatcher;
    private final RiskEvaluator riskEvaluator;
    private final ShellCommandExtractor commandExtractor;

    public DetectionEngine(DetectionConfig config) {
        this.config = config;
        this.ruleMatcher = new RuleMatcher();
        this.riskEvaluator = new RiskEvaluator();
        this.commandExtractor = new ShellCommandExtractor();
    }

    public DetectionResult detect(String entireCommand, List<Rule> rules) {
        DetectionResult.Builder resultBuilder = DetectionResult.builder();

        try {
            List<String> commands = commandExtractor.extractCommands(entireCommand);

            if (commands.isEmpty()) {
                return resultBuilder.passed(true).build();
            }

            if (ruleMatcher.isEntireCommandWhitelisted(entireCommand, rules)) {
                return resultBuilder.passed(true).build();
            }

            if (ruleMatcher.areAllCommandsWhitelisted(commands, rules)) {
                return resultBuilder.passed(true).build();
            }

            List<Rule> allMatchedRules = new ArrayList<>();
            for (String cmd : commands) {
                List<Rule> matched = ruleMatcher.matchBlacklist(cmd, rules);
                allMatchedRules.addAll(matched);
                for (Rule rule : matched) {
                    resultBuilder.addMatchedRule(rule);
                }
            }

            RiskLevel highestRisk = riskEvaluator.evaluateHighestRisk(allMatchedRules);
            boolean shouldBlock = riskEvaluator.shouldBlock(highestRisk, config.getThreshold());

            if (shouldBlock) {
                resultBuilder.passed(false)
                        .highestRiskLevel(highestRisk)
                        .blockReason("Command exceeded risk threshold: " + highestRisk.getDescription());
            }

        } catch (ShellParseException e) {
            if (config.isFailOnParseError()) {
                throw e;
            }
            resultBuilder.passed(true);
        }

        return resultBuilder.build();
    }
}
