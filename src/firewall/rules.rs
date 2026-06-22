use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Rule {
    pub id: u32,
    pub name: String,
    pub pattern: String,
    pub severity: String,
    pub category: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RuleSet {
    pub signatures: Vec<Rule>,
}

impl RuleSet {
    /// Loads rules from a YAML file
    pub fn load_from_file(path: &str) -> Self {
        let content = fs::read_to_string(path)
            .expect("Failed to read rules.yaml");
        serde_yaml::from_str(&content)
            .expect("Failed to parse rules.yaml")
    }
}