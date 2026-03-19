package com.example.shelldetector.builtin;

import com.example.shelldetector.model.Rule;
import com.example.shelldetector.persistence.RuleLoader;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class BuiltinRules {
    private static final String BUILTIN_RESOURCES = "/builtin-rules.json";
    private static List<Rule> cachedRules;

    public static List<Rule> getRules() {
        if (cachedRules == null) {
            cachedRules = loadRules();
        }
        return Collections.unmodifiableList(cachedRules);
    }

    private static List<Rule> loadRules() {
        try (InputStream is = BuiltinRules.class.getResourceAsStream(BUILTIN_RESOURCES)) {
            if (is == null) {
                return new ArrayList<>();
            }
            return RuleLoader.loadFromJson(is);
        } catch (IOException e) {
            return new ArrayList<>();
        }
    }
}
