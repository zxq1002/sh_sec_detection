package com.example.shelldetector.model;

public enum RiskLevel {
    SAFE(0, "安全"),
    RISK(1, "风险"),
    DANGER(2, "高危");

    private final int level;
    private final String description;

    RiskLevel(int level, String description) {
        this.level = level;
        this.description = description;
    }

    public int getLevel() {
        return level;
    }

    public String getDescription() {
        return description;
    }

    public boolean isHigherOrEqualTo(RiskLevel other) {
        return this.level >= other.level;
    }
}
