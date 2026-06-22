use percent_encoding::percent_decode_str;
use html_escape::decode_html_entities;

pub struct RequestNormalizer;

impl RequestNormalizer {
    pub fn normalize(input: &str) -> String {
        let url_decoded = percent_decode_str(input).decode_utf8_lossy();
        let html_decoded = decode_html_entities(&url_decoded);
        html_decoded
            .to_lowercase()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_decode() {
        assert_eq!(RequestNormalizer::normalize("%27"), "'");
    }

    #[test]
    fn test_html_decode() {
        assert_eq!(RequestNormalizer::normalize("&lt;"), "<");
    }

    #[test]
    fn test_lowercase() {
        assert_eq!(RequestNormalizer::normalize("HELLO"), "hello");
    }

    #[test]
    fn test_whitespace_collapse() {
        assert_eq!(RequestNormalizer::normalize("a   b"), "a b");
    }

    #[test]
    fn test_sql_injection_encoding() {
        let result = RequestNormalizer::normalize("%27%20UNION%20SELECT%20%2A");
        assert_eq!(result, "' union select *");
    }

    #[test]
    fn test_xss_encoding() {
        let result = RequestNormalizer::normalize("&lt;script&gt;alert(1)&lt;/script&gt;");
        assert_eq!(result, "<script>alert(1)</script>");
    }

    #[test]
    fn test_empty_string() {
        assert_eq!(RequestNormalizer::normalize(""), "");
    }
}
