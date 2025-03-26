use url::Url;

/// Parse a string URL & returns it as [Url].
pub fn parse_url(s: &str) -> Result<Url, url::ParseError> {
    s.parse()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("https://www.example.com/", true)]
    #[case("https://example.com/path?query=value", true)]
    #[case("http://localhost:8080/", true)]
    #[case("ftp://ftp.example.com/", true)]
    #[case("not_a_url", false)]
    #[case("http://", false)]
    #[case("://invalid.com", false)]
    fn test_parse_url(#[case] url: &str, #[case] should_pass: bool) {
        let result = parse_url(url);
        assert_eq!(result.is_ok(), should_pass, "URL: {}", url);

        if should_pass {
            let parsed_url = result.unwrap();
            assert_eq!(parsed_url.as_str(), url, "URL parsing changed the format");
        }
    }
}
