use crate::{
    character_class::CharacterClass,
    operation::{
        ForceProgressIterator, Operation, OperationControl, RepeatOperation, MATCHES_ZLS_ANYWHERE,
    },
    re_flags::{Language, ReFlags},
    re_matcher::ReMatcher,
};

// Handle a repetition (with possible min and max) where the
// size of the repeated unit is variable.
#[derive(Debug, Clone)]
pub(crate) struct Repeat {
    pub(crate) operation: Box<Operation>,
    pub(crate) min: usize,
    pub(crate) max: usize,
    pub(crate) greedy: bool,
    xsd: bool,
    nullable: bool,
}

impl Repeat {
    pub(crate) fn new(operation: Operation, min: usize, max: usize, greedy: bool) -> Self {
        Self {
            operation: Box::new(operation),
            min,
            max,
            greedy,
            xsd: false,
            nullable: false,
        }
    }
}

impl OperationControl for Repeat {
    fn get_match_length(&self) -> Option<usize> {
        self.operation.get_match_length().and_then(|match_length| {
            if self.min == self.max {
                Some(self.min * match_length)
            } else {
                None
            }
        })
    }

    fn get_minimum_match_length(&self) -> usize {
        self.min * self.operation.get_minimum_match_length()
    }

    fn get_initial_character_class(&self, case_blind: bool) -> CharacterClass {
        self.operation.get_initial_character_class(case_blind)
    }

    fn optimize(self, flags: &ReFlags) -> Operation {
        let operation = self.operation.optimize(flags);
        let xsd = flags.language() == Language::XSD;
        let nullable = operation.matches_empty_string() == MATCHES_ZLS_ANYWHERE;
        let min = if !xsd && self.min == 0 && nullable {
            // turns (a?)* into (a?)+
            1
        } else {
            self.min
        };
        Operation::from(Repeat {
            operation: Box::new(operation),
            min,
            max: self.max,
            greedy: self.greedy,
            xsd,
            nullable,
        })
    }

    fn matches_empty_string(&self) -> u32 {
        if self.min == 0 {
            MATCHES_ZLS_ANYWHERE
        } else {
            self.operation.matches_empty_string()
        }
    }

    fn contains_capturing_expressions(&self) -> bool {
        matches!(self.operation.as_ref(), Operation::Capture(_))
            || self.operation.contains_capturing_expressions()
    }

    fn matches_iter_impl<'a>(
        &'a self,
        matcher: &'a ReMatcher,
        position: usize,
    ) -> Box<dyn Iterator<Item = usize> + 'a> {
        if self.xsd {
            return self.xsd_matches(matcher, position);
        }
        let mut iterators: Vec<Box<dyn Iterator<Item = usize>>> = Vec::new();
        let mut positions = Vec::new();
        let bound = self.max.min(matcher.search.len() - position + 1);
        let mut p = position;
        if self.greedy {
            // Prime the arrays first with iterators up to the maximum length,
            // stopping if there is no match

            // Porting note: is_duplicate_zero_length_match can be dedicated to
            // the Repeat (and not the various subclasses in the original Java
            // code, i.e. GreedyFixed, ReluctantFixed, UnambiguousRepeat),
            // because each of these subclasses overrides matches_iter anyway,
            // so this code can never be reached.
            if self.min == 0 && !matcher.is_duplicate_zero_length_match(self, position) {
                // add a match at the current position if zero occurrences are allowed
                iterators.push(Box::new(std::iter::once(position)));
                positions.push(p);
            }
            for _i in 0..bound {
                let mut it = self.operation.matches_iter(matcher, p);
                if let Some(next) = it.next() {
                    p = next;
                    iterators.push(it);
                    positions.push(p);
                } else if iterators.is_empty() {
                    return Box::new(std::iter::empty());
                } else {
                    break;
                }
            }
            // Now return an iterator which returns all the matching positions
            // in order
            Box::new(ForceProgressIterator::new(
                Box::new(GreedyRepeatIterator::new(
                    matcher,
                    self.operation.as_ref(),
                    iterators,
                    positions,
                    bound,
                    self.min,
                )),
            ))
        } else {
            // reluctant (non-greedy) repeat.
            Box::new(ForceProgressIterator::new(
                Box::new(ReluctantRepeatIterator::new(
                    matcher,
                    self.operation.as_ref(),
                    position,
                    self.min,
                    self.max,
                )),
            ))
        }
    }

    fn children(&self) -> Vec<Operation> {
        vec![self.operation.as_ref().clone()]
    }
}

impl Repeat {
    // Local XSD correction alongside the public anchored matcher and budget
    // (Paligo/regexml#15). Copyright and MPL-2.0 terms in COPYRIGHT and
    // LICENSE-MPL2 are unchanged. This correction is not submitted upstream.
    //
    // XSD has no backreferences or position-dependent empty matches, so a
    // (position, iteration count) state has the same continuations on every
    // visit. Expand each state once instead of walking duplicate derivations.
    // For nullable L, L{min,max} = (L minus epsilon){0,max}: ignore empty
    // transitions and pad the minimum. Otherwise retain the exact minimum.
    // Every explored transition consumes at least one subject character.
    // An unbounded maximum is therefore capped at subject length plus one;
    // finite maxima can use the same cap. Empty padding needs no states even
    // when the declared minimum exceeds that cap. There are at most
    // (remaining length + 1) * (count bound + 1) states per invocation.
    // Every operand evaluation and pull still uses Operation::matches_iter.
    // This bounds repeated derivations, not arbitrary operand evaluation cost.
    //
    // Yield distinct endpoints in descending position order. XSD promises no
    // greedy-first preference: replace_all, tokenize and analyze may report a
    // different valid match. Captures inside repetitions can retain spans from
    // an explored path, not the reported derivation. XPath keeps its traversal.
    fn xsd_matches<'a>(
        &'a self,
        matcher: &'a ReMatcher,
        position: usize,
    ) -> Box<dyn Iterator<Item = usize> + 'a> {
        let bound = self.max.min(matcher.search.len().saturating_add(1));
        let minimum = if self.nullable { 0 } else { self.min };
        let mut reached = std::collections::BTreeSet::new();
        let mut seen = std::collections::BTreeSet::from([(position, 0)]);
        let mut pending = std::collections::VecDeque::from([(position, 0)]);
        while let Some((start, count)) = pending.pop_front() {
            if count >= minimum {
                reached.insert(start);
            }
            if count == bound {
                continue;
            }
            for end in self.operation.matches_iter(matcher, start) {
                if end > start && seen.insert((end, count + 1)) {
                    pending.push_back((end, count + 1));
                }
            }
        }
        Box::new(reached.into_iter().rev())
    }
}

impl RepeatOperation for Repeat {
    fn child(&self) -> Operation {
        self.operation.as_ref().clone()
    }

    fn min(&self) -> usize {
        self.min
    }

    fn max(&self) -> usize {
        self.max
    }

    fn greedy(&self) -> bool {
        self.greedy
    }
}

struct GreedyRepeatIterator<'a> {
    primed: bool,
    matcher: &'a crate::re_matcher::ReMatcher<'a>,
    operation: &'a Operation,
    min: usize,
    iterators: Vec<Box<dyn Iterator<Item = usize> + 'a>>,
    positions: Vec<usize>,
    bound: usize,
}

impl<'a> GreedyRepeatIterator<'a> {
    fn new(
        matcher: &'a ReMatcher<'a>,
        operation: &'a Operation,
        iterators: Vec<Box<dyn Iterator<Item = usize> + 'a>>,
        positions: Vec<usize>,
        bound: usize,
        min: usize,
    ) -> Self {
        Self {
            primed: true,
            matcher,
            operation,
            min,
            iterators,
            positions,
            bound,
        }
    }
}

impl Iterator for GreedyRepeatIterator<'_> {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        let has_next = if self.primed && self.iterators.len() >= self.min {
            !self.iterators.is_empty()
        } else if self.iterators.is_empty() {
            false
        } else {
            loop {
                let top = self.iterators.last_mut().unwrap();
                if let Some(mut p) = top.next() {
                    self.positions.pop();
                    self.positions.push(p);
                    while self.iterators.len() < self.bound {
                        let mut it = self.operation.matches_iter(self.matcher, p);
                        if let Some(next) = it.next() {
                            p = next;
                            self.iterators.push(it);
                            self.positions.push(p)
                        } else {
                            break;
                        }
                    }
                } else {
                    self.iterators.pop();
                    self.positions.pop();
                }
                if self.iterators.len() >= self.min || self.iterators.is_empty() {
                    break;
                }
            }
            !self.iterators.is_empty()
        };
        if has_next {
            self.primed = false;
            self.positions.last().copied()
        } else {
            None
        }
    }
}

struct ReluctantRepeatIterator<'a> {
    matcher: &'a crate::re_matcher::ReMatcher<'a>,
    operation: &'a Operation,
    min: usize,
    max: usize,
    counter: usize,
    position: Option<usize>,
}

impl<'a> ReluctantRepeatIterator<'a> {
    fn new(
        matcher: &'a ReMatcher<'a>,
        operation: &'a Operation,
        position: usize,
        min: usize,
        max: usize,
    ) -> Self {
        Self {
            matcher,
            operation,
            min,
            max,
            counter: 0,
            position: Some(position),
        }
    }
}

impl Iterator for ReluctantRepeatIterator<'_> {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(position) = self.position {
                let mut it = self.operation.matches_iter(self.matcher, position);
                if let Some(position) = it.next() {
                    self.counter += 1;
                    if self.counter > self.max {
                        self.position = None;
                    } else {
                        self.position = Some(position);
                    }
                }
            } else if self.min == 0 && self.counter == 0 {
                self.counter += 1;
            } else {
                self.position = None;
            }
            if self.counter >= self.min || self.position.is_none() {
                break;
            }
        }
        self.position
    }
}

#[cfg(test)]
mod tests {
    use crate::Regex;

    #[test]
    fn test_nullable_counted_xsd() {
        // Minimum completing budget measures engine operations, not wall time.
        let operations = |regex: &Regex, subject: &str| {
            let mut high = 10_000;
            assert!(regex.is_full_match_bounded(subject, high).is_ok(), "operation ceiling: {subject:?}");
            let mut low = 0;
            while low + 1 < high {
                let middle = low + (high - low) / 2;
                if regex.is_full_match_bounded(subject, middle).is_err() {
                    low = middle;
                } else {
                    high = middle;
                }
            }
            high
        };
        let costly = Regex::xsd("(a|a|a|a|a|aa)+c", "").unwrap();
        for length in [3, 5, 7, 12, 30] {
            let subject = "a".repeat(length);
            let count = operations(&costly, &subject);
            let full = costly.is_full_match(&subject);
            let search = costly.is_match(&subject);
            let bounded = costly.is_full_match_bounded(&subject, 10_000);
            println!("COST length={length} operations={count} full={full} search={search} bounded={bounded:?}");
            assert!(!full && !search, "length={length}");
            assert_eq!(bounded, Ok(false), "length={length}, operations={count}");
            assert_eq!(costly.replace_all(&subject, "X"), Ok(subject.clone()));
            assert_eq!(costly.tokenize(&subject).unwrap().collect::<Vec<_>>(), vec![subject.clone()]);
            assert_eq!(costly.analyze(&subject).unwrap().collect::<Vec<_>>(), vec![crate::analyze_string::AnalyzeEntry::NonMatch(subject)]);
        }
        let preference = Regex::xsd("(a|ab|){1,2}.", "").unwrap();
        println!("PREFERENCE replace={:?} tokens={:?} analyze={:?} operations={}",
            preference.replace_all("abc", "X"),
            preference.tokenize("abc").unwrap().collect::<Vec<_>>(),
            preference.analyze("abc").unwrap().collect::<Vec<_>>(),
            operations(&preference, "abc"));
        assert_eq!(preference.replace_all("abc", "X"), Ok("X".to_owned()));
        assert_eq!(preference.tokenize("abc").unwrap().collect::<Vec<_>>(), vec!["", ""]);
        assert_eq!(preference.analyze("abc").unwrap().collect::<Vec<_>>(), vec![
            crate::analyze_string::AnalyzeEntry::Match(vec![
                crate::analyze_string::MatchEntry::String("ab".to_owned()),
                crate::analyze_string::MatchEntry::Group { nr: 1, value: vec![] },
                crate::analyze_string::MatchEntry::String("c".to_owned()),
            ])
        ]);
        let nullable = Regex::xsd("(a?){5}", "").unwrap();
        let found = nullable.is_match("aa");
        println!("XSD nullable is_match aa: {found}");
        let nullable = Regex::xsd("(a?){2}", "").unwrap();
        let empty = nullable.is_match("");
        let replacement = nullable.replace_all("bbb", "X");
        println!("XSD nullable empty: {empty}; replace_all: {replacement:?}");
        let mut correct = found && empty
            && matches!(replacement, Err(crate::Error::MatchesEmptyString));
        for duplicates in [4, 5, 6] {
            let pattern = format!("({}aa)+ab", "a|".repeat(duplicates));
            let regex = Regex::xsd(&pattern, "").unwrap();
            for subject in ["aab", "aaab", "aaaab"] {
                let full = regex.is_full_match(subject);
                let bounded = regex.is_full_match_bounded(subject, 100_000);
                let search = regex.is_match(subject);
                println!("XSD duplicates={duplicates} subject={subject}: full={full} bounded={bounded:?} search={search}");
                correct &= full && bounded == Ok(true) && search;
            }
        }
        for (pattern, subject, retained) in [
            ("^(a?){2}$", "aaa", true),
            ("^(a?){0}$", "a", true),
            ("^(a?){20}a{20}$", "aaaaaaaaaaaaaaaaaaaa", false),
            ("^(a|a|a|a|a|aa)+ab$", "aab", false),
        ] {
            let actual = Regex::xpath(pattern, "").unwrap().is_match(subject);
            println!("XPath unchanged {pattern} / {subject:?}: {actual}");
            assert_eq!(actual, retained, "XPath traversal remains upstream behavior");
        }
        assert!(correct, "XSD repetition witnesses must match their language answers");
        let suffix = Regex::xsd("(a?){2}b", "").unwrap();
        assert_eq!(suffix.replace_all("aab", "X"), Ok("X".to_owned()));
        let duplicate = Regex::xsd("(a|a|a|a|a|aa)+ab", "").unwrap();
        assert_eq!(
            duplicate.is_full_match_bounded("aab", 1),
            Err(crate::Error::BudgetExceeded)
        );
        for (pattern, subject, expected) in [
            ("(a|aa){2}", "aa", true),
            ("(a|aa){2}", "a", false),
            ("(a|aa){2}", "aaaa", true),
            ("(a|aa){2}", "aaaaa", false),
            ("(a|aa){20,}", "aaa", false),
            ("(a?){20,}", "a", true),
            ("(|a){1000000}", "aa", true),
            ("(a?){0}a{0}", "a", false),
            ("(a?){2}", "", true),
            ("(a?){2}", "aa", true),
            ("(a?){2}", "aaa", false),
            ("(a?){20}a{20}", "aaaaaaaaaaaaaaaaaaaa", true),
            ("(a*){8}", "", true),
            ("(|a){8}", "aaa", true),
            ("((a?){2}){3}", "aaaaaa", true),
            ("((a?){2}){3}", "aaaaaaa", false),
            ("(a?){3,5}", "a", true),
            ("(a?){3,5}", "aaaaaa", false),
            ("(a?){3,}", "", true),
        ] {
            let regex = Regex::xsd(pattern, "").unwrap();
            assert_eq!(regex.is_full_match_bounded(subject, 100_000), Ok(expected), "{pattern} / {subject:?}");
            assert_eq!(regex.is_full_match(subject), expected, "{pattern} / {subject:?}");
        }
    }

    #[test]
    fn test_repeat_simple() {
        let regex = Regex::xpath(r#"a*"#, "").unwrap();
        let op = regex.path("0");

        // unambiguous repeat
        let matches = regex.matcher("a").operation_matches(op.clone());
        assert_eq!(matches, vec!["a"]);

        let matches = regex.matcher("").operation_matches(op);
        assert_eq!(matches, vec![""]);
    }

    #[test]
    fn test_repeat_choice() {
        let regex = Regex::xpath(r#"(?:a|b)*"#, "").unwrap();
        let op = regex.path("0");

        let matches = regex.matcher("").operation_matches(op.clone());
        assert_eq!(matches, vec![""]);

        let matches = regex.matcher("a").operation_matches(op.clone());
        assert_eq!(matches, vec!["a", ""]);
        let matches = regex.matcher("aba").operation_matches(op.clone());
        assert_eq!(matches, vec!["aba", "ab", "a", ""]);

        let matches = regex.matcher("bab").operation_matches(op);
        assert_eq!(matches, vec!["bab", "ba", "b", ""]);
    }

    #[test]
    fn test_repeat_choice_with_option_first() {
        let regex = Regex::xpath(r#"(?:a?|b)*"#, "").unwrap();
        let op = regex.path("0");

        let matches = regex.matcher("bab").operation_matches(op);

        assert!(matches.contains(&"bab".to_string()));
    }

    #[test]
    fn test_repeat_option() {
        let regex = Regex::xpath(r#"(?:a?)*"#, "").unwrap();
        let op = regex.path("0");

        let matches = regex.matcher("aaa").operation_matches(op);

        assert!(matches.contains(&"aaa".to_string()));
    }

    #[test]
    fn test_repeat_choice_with_option_last() {
        let regex = Regex::xpath(r#"(?:b|a?)*"#, "").unwrap();
        let op = regex.path("0");

        let matches = regex.matcher("bab").operation_matches(op);
        assert_eq!(matches[0], "bab");
    }

    // #[test]
    // fn test_repeat_with_atom_behind() {
    //     let regex = Regex::xpath(r#"^(.*)+B"#, "").unwrap();
    //     let op = regex.path("0");

    //     let matches = regex.matcher("AB").operation_matches(op);
    //     assert_eq!(matches, vec!["AB"]);
    // }
}
