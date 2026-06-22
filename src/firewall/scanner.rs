use regex::RegexSet;
use crate::firewall::rules::RuleSet;

pub struct Scanner {
    pub regex_set: RegexSet,
    pub rule_id_map: Vec<u32>,
    pub rules: RuleSet,
}

impl Scanner {
    pub fn new(rules_path: &str) -> Self {
        let rule_set = RuleSet::load_from_file(rules_path);

        let patterns: Vec<&str> = rule_set.signatures
            .iter()
            .map(|r| r.pattern.as_str())
            .collect();

        let regex_set = RegexSet::new(&patterns)
            .expect("Failed to compile regex rules");

        let rule_id_map: Vec<u32> = rule_set.signatures
            .iter()
            .map(|r| r.id)
            .collect();

        Scanner { regex_set, rule_id_map, rules: rule_set }
    }

    pub fn matches(&self, input: &str) -> Option<u32> {
        self.regex_set
            .matches(input)
            .into_iter()
            .next()
            .map(|idx| self.rule_id_map[idx])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sqli_detection() {
        let scanner = Scanner::new("rules.yaml");
        let result = scanner.matches("union select * from users");
        assert!(result.is_some());
        assert_eq!(result.unwrap(), 1001);
    }

    #[test]
    fn test_clean_pass() {
        let scanner = Scanner::new("rules.yaml");
        assert!(scanner.matches("hello world this is clean").is_none());
    }

    #[test]
    fn test_xss_detection() {
        let scanner = Scanner::new("rules.yaml");
        let result = scanner.matches("<script>alert('xss')</script>");
        assert!(result.is_some());
        assert_eq!(result.unwrap(), 2001);
    }

    #[test]
    fn test_path_traversal() {
        let scanner = Scanner::new("rules.yaml");
        let result = scanner.matches("/etc/passwd");
        assert!(result.is_some());
        assert_eq!(result.unwrap(), 3001);
    }

    #[test]
    fn test_rce_detection() {
        let scanner = Scanner::new("rules.yaml");
        let result = scanner.matches("bin/bash -c 'exploit'");
        assert!(result.is_some());
        assert_eq!(result.unwrap(), 4001);
    }
}
