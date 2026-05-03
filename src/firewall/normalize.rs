use percent_encoding::percent_decode_str;
use html_escape::decode_html_entities;

pub struct RequestNormalizer;

impl RequestNormalizer {
    /// Normalizes a string by decoding URLs, HTML entities, and cleaning whitespace.
    pub fn normalize(input: &str) -> String {
        // 1. URL Decoding (%27 -> ')
        let url_decoded = percent_decode_str(input).decode_utf8_lossy();
        
        // 2. HTML Entity Decoding (&lt; -> <)
        let html_decoded = decode_html_entities(&url_decoded);
        
        // 3. Final cleaning: Lowercase and collapse whitespace
        html_decoded
            .to_lowercase()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }
}