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
    nullable_xsd: bool,
}

impl Repeat {
    pub(crate) fn new(operation: Operation, min: usize, max: usize, greedy: bool) -> Self {
        Self {
            operation: Box::new(operation),
            min,
            max,
            greedy,
            nullable_xsd: false,
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
        let nullable_xsd = flags.language() == Language::XSD
            && operation.matches_empty_string() == MATCHES_ZLS_ANYWHERE;
        let min = if self.min == 0 && operation.matches_empty_string() == MATCHES_ZLS_ANYWHERE {
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
            nullable_xsd,
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
        if self.nullable_xsd {
            return self.nullable_matches(matcher, position);
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
                position,
                matcher.program.flags.language(),
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
                position,
                matcher.program.flags.language(),
            ))
        }
    }

    fn children(&self) -> Vec<Operation> {
        vec![self.operation.as_ref().clone()]
    }
}

impl Repeat {
    // Local fork correction alongside the anchored matcher and operation budget
    // (Paligo/regexml#15): nullable repetition for anchored and unanchored XSD matching.
    // This correction has not been submitted upstream. Copyright and MPL-2.0
    // terms remain in COPYRIGHT and LICENSE-MPL2 without alteration.
    //
    // In XSD there are no backreferences or position-dependent empty matches.
    // If epsilon is in L, L{min,max} equals (L minus epsilon){0,max}:
    // empty iterations can pad any shorter derivation to the minimum.
    // Breadth-first discovery records the fewest consuming iterations to each
    // position. Revisiting it cannot permit a new suffix within max, so each
    // position is expanded once, without enumerating duplicate empty paths.
    // This also avoids the old subject-length cap on mandatory empty iterations
    // and ForceProgressIterator's premature end after duplicate endpoints.
    // All XSD entry points use this path, including the empty-string probe.
    // Endpoint sets are preserved, but capture order inside nullable repetition
    // need not agree with upstream. XPath retains its original traversal and
    // its known nullable-count and duplicate-endpoint membership defects.
    fn nullable_matches<'a>(
        &'a self,
        matcher: &'a ReMatcher,
        position: usize,
    ) -> Box<dyn Iterator<Item = usize> + 'a> {
        let mut reached = std::collections::BTreeSet::from([position]);
        let mut pending = std::collections::VecDeque::from([(position, 0)]);
        while let Some((start, count)) = pending.pop_front() {
            if reached.len() == matcher.search.len() - position + 1 {
                break;
            }
            if count == self.max {
                continue;
            }
            for end in self.operation.matches_iter(matcher, start) {
                if end > start && reached.insert(end) {
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
