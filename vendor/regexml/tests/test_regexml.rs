use regexml::{Error, Regex};
use std::time::{Duration, Instant};

#[test]
fn test_is_match_simple() {
    let regex = Regex::xpath("hello", "").unwrap();
    assert!(regex.is_match("hello"));
    assert!(!regex.is_match("world"));
}

#[test]
fn test_is_match_question_mark() {
    let regex = Regex::xpath("a?", "").unwrap();
    assert!(regex.is_match(""));
    assert!(regex.is_match("a"));
    assert!(regex.is_match("aa"));
}

#[test]
fn test_is_match_question_mark_complete() {
    let regex = Regex::xpath("^a?$", "").unwrap();
    assert!(regex.is_match(""));
    assert!(regex.is_match("a"));
    assert!(!regex.is_match("aa"));
    assert!(!regex.is_match("b"));
}

#[test]
fn test_is_match_star() {
    let regex = Regex::xpath("a*", "").unwrap();
    assert!(regex.is_match(""));
    assert!(regex.is_match("a"));
    assert!(regex.is_match("aa"));
    assert!(regex.is_match("aaa"));
}

#[test]
fn test_is_match_star_complete() {
    let regex = Regex::xpath("^a*$", "").unwrap();
    assert!(!regex.is_match("b"));
    assert!(regex.is_match(""));
    assert!(regex.is_match("a"));
    assert!(regex.is_match("aa"));
    assert!(regex.is_match("aaa"));
}

#[test]
fn test_is_match_plus() {
    let regex = Regex::xpath("a+", "").unwrap();
    assert!(!regex.is_match(""));
    assert!(regex.is_match("a"));
    assert!(regex.is_match("aa"));
    assert!(regex.is_match("aaa"));
}

#[test]
fn test_mixed() {
    let regex = Regex::xpath("^a?b+c*$", "").unwrap();
    assert!(regex.is_match("bc"));
    assert!(regex.is_match("abc"));
    assert!(regex.is_match("abbc"));
    assert!(regex.is_match("abbbcc"));
    assert!(regex.is_match("abbb"));
    assert!(regex.is_match("ab"));
    assert!(regex.is_match("b"));
    assert!(!regex.is_match("a"));
    assert!(!regex.is_match("c"));
    assert!(!regex.is_match("ac"));
}

#[test]
fn test_mixed_problem() {
    let regex = Regex::xpath("^a?b+c*$", "").unwrap();
    assert!(regex.is_match("ab"));
}

// these tests are a sampling from qt3/fn/matches.xml to ensure
// that at least some basics work, and to help debug it when not.

#[test]
fn test_matches_1() {
    let regex = Regex::xpath("bra", "").unwrap();
    assert!(regex.is_match("abracadabra"));
}

#[test]
fn test_matches_2() {
    let regex = Regex::xpath("^a.*a$", "").unwrap();
    assert!(regex.is_match("abracadabra"));
}

#[test]
fn test_matches_3() {
    let regex = Regex::xpath("^bra", "").unwrap();
    assert!(!regex.is_match("abracadabra"));
}

#[test]
fn test_matches_6() {
    let regex = Regex::xpath("\\^", "").unwrap();
    assert!(regex.is_match("abracadabra^abracadabra"));
}

#[test]
fn test_matches_20() {
    let regex = Regex::xpath("\t", "").unwrap();
    assert!(regex.is_match("abracadbra\tabracadabra"));
}

#[test]
fn test_matches_22() {
    let regex = Regex::xpath("aa{1}", "").unwrap();
    assert!(regex.is_match("abracadabraabracadabra"));
}

#[test]
fn test_matches_23() {
    let regex = Regex::xpath("aa{1,}", "").unwrap();
    assert!(regex.is_match("abracadabraabracadabraabracadabra"));
}

#[test]
fn test_matches_30() {
    let regex = Regex::xpath("(?:abra(?:cad)?)*", "").unwrap();
    assert!(regex.is_match("abracadabra"));
}

#[test]
fn test_matches_52() {
    let regex = Regex::xpath("^(a*b?a*){3,3}$", "").unwrap();
    assert!(regex.is_match("aaababaaabaa"))
}

#[test]
fn test_matches_character_range() {
    let regex = Regex::xpath("[A-Z]", "").unwrap();
    assert!(regex.is_match("A"))
}

#[test]
fn test_matches_53() {
    let regex = Regex::xpath("([A-Z])\\1*", "").unwrap();
    assert!(regex.is_match("A"))
}

#[test]
fn test_simple_replace() {
    let regex = Regex::xpath("hello", "").unwrap();

    assert_eq!(
        regex.replace_all("hello world", "bye").unwrap(),
        "bye world"
    )
}

#[test]
fn test_replace_48() {
    let regex = Regex::xpath("^a(.).$|^a...$", "").unwrap();

    assert_eq!(regex.replace_all("abcd", "$1").unwrap(), "")
}

#[test]
fn test_tokenize_9() {
    let regex = Regex::xpath("(ab)|(a)", "").unwrap();
    assert_eq!(
        regex.tokenize("abracadabra").unwrap().collect::<Vec<_>>(),
        vec![
            "".to_string(),
            "r".to_string(),
            "c".to_string(),
            "d".to_string(),
            "r".to_string(),
            "".to_string(),
        ]
    );
}

#[test]
fn test_tokenize_10() {
    let regex = Regex::xpath("ww", "").unwrap();
    assert_eq!(
        regex.tokenize("abracadabra").unwrap().collect::<Vec<_>>(),
        vec!["abracadabra".to_string(),]
    );
}

#[test]
fn test_tokenize_11() {
    let regex = Regex::xpath("^a", "").unwrap();
    assert_eq!(
        regex.tokenize("abracadabra").unwrap().collect::<Vec<_>>(),
        vec!["".to_string(), "bracadabra".to_string()]
    );
}

#[test]
fn test_caselessmatch01() {
    let regex = Regex::xpath("ABC", "i").unwrap();
    assert!(regex.is_match("abc"));
}

#[test]
fn test_caselessmatch01_inverted() {
    let regex = Regex::xpath("abc", "i").unwrap();
    assert!(regex.is_match("ABC"));
}

#[test]
fn test_caseless_match_character_classes() {
    let regex = Regex::xpath("[A-Z]", "i").unwrap();
    assert!(regex.is_match("a"));
}

#[test]
fn test_matches_multiline() {
    let regex = Regex::xpath("^$", "m").unwrap();
    assert!(!regex.is_match("abcd\ndefg\n"));
}

#[test]
fn test_position_assumption() {
    let a = [0, 1, 2, 3, 4, 5];
    // find the index of first matching element while skipping the first two
    a.iter().enumerate().skip(2).find(|(_, &x)| x == 3);
}

#[test]
fn test_matches_31() {
    let regex = Regex::xpath("(?:abra(?:cad)?)*", "").unwrap();
    assert!(regex.is_match("abracadabra"));
}

#[test]
fn test_is_full_match_whole_string() {
    let regex = Regex::xsd("a", "").unwrap();
    assert!(regex.is_full_match("a"));
    assert!(!regex.is_full_match("ab"));
    assert!(!regex.is_full_match("ba"));
    assert!(regex.is_match("ab"));
}

#[test]
fn test_is_full_match_leftmost_alternative_backtracks() {
    // A leftmost-first engine finds the short branch first; full matching
    // must still accept through the longer one.
    let regex = Regex::xsd("a|ab", "").unwrap();
    assert!(regex.is_full_match("a"));
    assert!(regex.is_full_match("ab"));
    assert!(!regex.is_full_match("abc"));
}

#[test]
fn test_is_full_match_xpath_anchors_still_work() {
    let regex = Regex::xpath("^a$", "").unwrap();
    assert!(regex.is_full_match("a"));
    assert!(!regex.is_full_match("aa"));
}

#[test]
fn test_is_full_match_empty() {
    let regex = Regex::xsd("a?", "").unwrap();
    assert!(regex.is_full_match(""));
    assert!(regex.is_full_match("a"));
    assert!(!regex.is_full_match("aa"));
}

// The number of operations a match takes, found by bisecting the budget: the
// smallest budget the match completes within is what it costs. Matching is
// deterministic, so a budget that is enough once is enough always.
fn ops_used(regex: &Regex, haystack: &str, ceiling: usize) -> usize {
    assert!(regex.is_full_match_bounded(haystack, ceiling).is_ok());
    let mut low = 0;
    let mut high = ceiling;
    while low < high {
        let mid = low + (high - low) / 2;
        if regex.is_full_match_bounded(haystack, mid).is_ok() {
            high = mid;
        } else {
            low = mid + 1;
        }
    }
    low
}

// A label-shaped pattern, of the kind that appears in XML Schema pattern
// facets, against a subject of the length such a facet sees.
const LABEL_PATTERN: &str = r"[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+";
const LABEL_SUBJECT: &str = "abc-def.ghi-jkl.mno-pqr.stu-vwx.yz0-123.456-789.abcdefgh";

#[test]
fn test_is_full_match_bounded_ordinary_patterns() {
    // measured: 6 operations for the literal, 253 for the label
    let regex = Regex::xsd("application/json", "").unwrap();
    assert_eq!(
        regex.is_full_match_bounded("application/json", 1000),
        Ok(true)
    );
    assert_eq!(
        regex.is_full_match_bounded("application/jsom", 1000),
        Ok(false)
    );

    let regex = Regex::xsd(LABEL_PATTERN, "").unwrap();
    assert_eq!(regex.is_full_match_bounded(LABEL_SUBJECT, 10_000), Ok(true));
    assert!(ops_used(&regex, LABEL_SUBJECT, 10_000) < 1000);

    // rejecting costs more than accepting: every way of splitting the subject
    // has to be tried before the pattern can be ruled out (measured: 1017)
    let rejected = "abc-def.ghi-jkl.mno-pqr.stu-vwx.yz0-123.456-789.abcdefg!";
    assert_eq!(regex.is_full_match_bounded(rejected, 10_000), Ok(false));
    assert!(ops_used(&regex, rejected, 10_000) < 10_000);
}

#[test]
fn test_is_full_match_bounded_refuses_catastrophic_backtracking() {
    // (a+)+ against a subject with no b takes exponential time unbounded: the
    // engine tries every way of splitting the a's between the two repeats
    let regex = Regex::xsd("(a+)+b", "").unwrap();
    let haystack = "a".repeat(30);

    let start = Instant::now();
    assert_eq!(
        regex.is_full_match_bounded(&haystack, 10_000),
        Err(Error::BudgetExceeded)
    );
    assert!(start.elapsed() < Duration::from_millis(100));

    // a budget a hundred times larger buys no answer either, it only takes
    // longer to give up
    assert_eq!(
        regex.is_full_match_bounded(&haystack, 1_000_000),
        Err(Error::BudgetExceeded)
    );
}

#[test]
fn test_is_full_match_bounded_never_answers_from_an_exhausted_budget() {
    // "a|ab" needs to backtrack into the second branch to match "ab" (14
    // operations); cut off halfway it must refuse, not report "no match"
    let regex = Regex::xsd("a|ab", "").unwrap();
    assert_eq!(regex.is_full_match_bounded("ab", 100), Ok(true));
    assert_eq!(
        regex.is_full_match_bounded("ab", 7),
        Err(Error::BudgetExceeded)
    );
    assert_eq!(
        regex.is_full_match_bounded("ab", 0),
        Err(Error::BudgetExceeded)
    );
}

#[test]
fn test_is_full_match_bounded_is_deterministic() {
    // the budget counts operations, not time, so repeating a call repeats its
    // outcome and its cost exactly
    let regex = Regex::xsd(LABEL_PATTERN, "").unwrap();
    assert_eq!(
        ops_used(&regex, LABEL_SUBJECT, 10_000),
        ops_used(&regex, LABEL_SUBJECT, 10_000)
    );

    let regex = Regex::xsd("(a+)+b", "").unwrap();
    let haystack = "a".repeat(30);
    assert_eq!(
        regex.is_full_match_bounded(&haystack, 10_000),
        regex.is_full_match_bounded(&haystack, 10_000)
    );
}

#[test]
fn test_is_full_match_bounded_matches_the_unbounded_answer() {
    for (pattern, haystack) in [
        ("a", "a"),
        ("a", "ab"),
        ("a|ab", "ab"),
        ("a?", ""),
        ("(a+)+b", "aaaab"),
        ("(a+)+b", "aaaac"),
        (LABEL_PATTERN, LABEL_SUBJECT),
    ] {
        let regex = Regex::xsd(pattern, "").unwrap();
        assert_eq!(
            regex.is_full_match_bounded(haystack, 100_000),
            Ok(regex.is_full_match(haystack)),
            "{pattern} against {haystack}"
        );
    }
}
