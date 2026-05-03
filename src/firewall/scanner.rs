use hyperscan::prelude::*;
use crate::firewall::rules::RuleSet;

pub struct Scanner {
    pub db: BlockDatabase,
    pub scratch: Scratch,
    pub rules: RuleSet, 
}

impl Scanner {
    pub fn new(rules_path: &str) -> Self {
        let rule_set = RuleSet::load_from_file(rules_path);
        
        // Patterns is hyperscan's own Vec wrapper that implements DatabaseBuilder
        let patterns: Patterns = rule_set.signatures
            .iter()
            .map(|r| {
                let mut p = pattern! { &r.pattern; CASELESS | DOTALL };
                p.id = Some(r.id as usize);
                p
            })
            .collect();

        let db: BlockDatabase = patterns
            .build()
            .expect("Failed to compile Hyperscan database");
            
        let scratch = db.alloc_scratch().expect("Failed to allocate scratch space");

        Scanner { db, scratch, rules: rule_set }
    }

    pub fn matches(&mut self, input: &str) -> Option<u32> {
        let mut matched_id: Option<u32> = None;
        
        let _ = self.db.scan(input, &self.scratch, |id, _from, _to, _flags| {
            matched_id = Some(id as u32);
            Matching::Terminate 
        });
        
        matched_id
    }
}