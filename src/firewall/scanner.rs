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