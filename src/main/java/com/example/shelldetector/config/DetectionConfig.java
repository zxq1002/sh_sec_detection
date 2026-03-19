package com.example.shelldetector.config;

import com.example.shelldetector.model.RiskLevel;

import java.io.Serializable;

public class DetectionConfig implements Serializable {
    private RiskLevel threshold = RiskLevel.RISK;
    private boolean failOnParseError = true;

    public DetectionConfig() {
    }

    public RiskLevel getThreshold() {
        return threshold;
    }

    public void setThreshold(RiskLevel threshold) {
        if (threshold == null) {
            throw new IllegalArgumentException("Threshold cannot be null");
        }
        this.threshold = threshold;
    }

    public boolean isFailOnParseError() {
        return failOnParseError;
    }

    public void setFailOnParseError(boolean failOnParseError) {
        this.failOnParseError = failOnParseError;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private DetectionConfig config = new DetectionConfig();

        public Builder threshold(RiskLevel threshold) {
            if (threshold == null) {
                throw new IllegalArgumentException("Threshold cannot be null");
            }
            config.threshold = threshold;
            return this;
        }

        public Builder failOnParseError(boolean failOnParseError) {
            config.failOnParseError = failOnParseError;
            return this;
        }

        public DetectionConfig build() {
            return config;
        }
    }
}
