package com.example.shelldetector.builtin;

import com.example.shelldetector.model.Rule;
import com.example.shelldetector.persistence.RuleLoader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class BuiltinRules {
    private static final Logger logger = LoggerFactory.getLogger(BuiltinRules.class);
    private static final String BUILTIN_RESOURCES = "/builtin-rules.json";
    private static volatile List<Rule> cachedRules;

    public static List<Rule> getRules() {
        if (cachedRules == null) {
            synchronized (BuiltinRules.class) {
                if (cachedRules == null) {
                    cachedRules = loadRules();
                }
            }
        }
        return Collections.unmodifiableList(cachedRules);
    }

    private static List<Rule> loadRules() {
        try (InputStream is = BuiltinRules.class.getResourceAsStream(BUILTIN_RESOURCES)) {
            if (is == null) {
                logger.warn("Built-in rules file not found: {}", BUILTIN_RESOURCES);
                return new ArrayList<>();
            }
            List<Rule> rules = RuleLoader.loadFromJson(is);
            logger.info("Loaded {} built-in rules", rules.size());
            return rules;
        } catch (IOException e) {
            logger.error("Failed to load built-in rules: {}", e.getMessage(), e);
            return new ArrayList<>();
        }
    }
}
