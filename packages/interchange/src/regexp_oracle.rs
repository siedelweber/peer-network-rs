//! mod:module:regexp-oracle
//!
//! Test-only Thompson automaton for ASCII literals, classes, concatenation,
//! alternation and repetition. It shares neither parsing nor execution code
//! with the production matcher. Unsupported syntax is a test fixture error.
//! Every parenthesized operand is a choice with fresh branch states; the
//! unbounded-repeat back edge relies on this isolation from sibling exits.

use std::collections::BTreeSet;

#[derive(Clone)]
enum Expression {
    Bytes(Vec<u8>),
    Sequence(Vec<Self>),
    Choice(Vec<Self>),
    Repeat(Box<Self>, usize, Option<usize>),
}

struct Parser<'a> {
    source: &'a [u8],
    offset: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.source.get(self.offset).copied()
    }

    fn take(&mut self) -> u8 {
        let byte = self.source[self.offset];
        self.offset += 1;
        byte
    }

    fn number(&mut self) -> usize {
        let start = self.offset;
        let mut value = 0;
        while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            value = value * 10 + usize::from(self.take() - b'0');
        }
        assert!(self.offset > start, "fixture needs a repetition count");
        value
    }

    fn choice(&mut self) -> Expression {
        let mut alternatives = vec![self.sequence()];
        while self.peek() == Some(b'|') {
            self.take();
            alternatives.push(self.sequence());
        }
        Expression::Choice(alternatives)
    }

    fn sequence(&mut self) -> Expression {
        let mut terms = Vec::new();
        while !matches!(self.peek(), None | Some(b')' | b'|')) {
            let atom = match self.take() {
                b'(' => {
                    let expression = self.choice();
                    assert_eq!(self.take(), b')');
                    expression
                }
                b'[' => {
                    let mut bytes = Vec::new();
                    assert_ne!(self.peek(), Some(b'^'), "unsupported negated fixture class");
                    while self.peek() != Some(b']') {
                        let first = self.take();
                        assert!(!b"\\[".contains(&first), "unsupported fixture class syntax");
                        if self.peek() == Some(b'-') {
                            self.take();
                            let last = self.take();
                            assert!(!b"\\[".contains(&last), "unsupported fixture class syntax");
                            assert!(first <= last);
                            bytes.extend(first..=last);
                        } else {
                            bytes.push(first);
                        }
                    }
                    self.take();
                    Expression::Bytes(bytes)
                }
                b'\\' => {
                    let escaped = self.take();
                    assert!(b"\\|.-?*+{}()[]^".contains(&escaped), "unsupported fixture escape");
                    Expression::Bytes(vec![escaped])
                }
                byte => {
                    assert!(!b".*+?{}]".contains(&byte), "unsupported fixture syntax");
                    Expression::Bytes(vec![byte])
                }
            };
            let bounds = match self.peek() {
                Some(b'?') => Some((0, Some(1))),
                Some(b'*') => Some((0, None)),
                Some(b'+') => Some((1, None)),
                Some(b'{') => {
                    self.take();
                    let min = self.number();
                    let max = if self.peek() == Some(b',') {
                        self.take();
                        (self.peek() != Some(b'}')).then(|| self.number())
                    } else {
                        Some(min)
                    };
                    assert_eq!(self.peek(), Some(b'}'));
                    assert!(max.is_none_or(|max| min <= max));
                    Some((min, max))
                }
                _ => None,
            };
            terms.push(if let Some((min, max)) = bounds {
                self.take();
                Expression::Repeat(Box::new(atom), min, max)
            } else {
                atom
            });
        }
        Expression::Sequence(terms)
    }
}

#[derive(Default)]
struct State {
    epsilon: Vec<usize>,
    consuming: Vec<(Vec<u8>, usize)>,
}

#[derive(Default)]
struct Automaton(Vec<State>);

impl Automaton {
    fn state(&mut self) -> usize {
        self.0.push(State::default());
        self.0.len() - 1
    }

    fn compile(&mut self, expression: &Expression, start: usize, end: usize) {
        match expression {
            Expression::Bytes(bytes) => self.0[start].consuming.push((bytes.clone(), end)),
            Expression::Sequence(terms) => {
                let mut cursor = start;
                for term in terms {
                    let next = self.state();
                    self.compile(term, cursor, next);
                    cursor = next;
                }
                self.0[cursor].epsilon.push(end);
            }
            Expression::Choice(alternatives) => {
                for alternative in alternatives {
                    let branch = self.state();
                    self.0[start].epsilon.push(branch);
                    self.compile(alternative, branch, end);
                }
            }
            Expression::Repeat(child, min, max) => {
                let mut cursor = start;
                for _ in 0..*min {
                    let next = self.state();
                    self.compile(child, cursor, next);
                    cursor = next;
                }
                self.0[cursor].epsilon.push(end);
                if let Some(max) = max {
                    for _ in *min..*max {
                        let next = self.state();
                        self.compile(child, cursor, next);
                        cursor = next;
                        self.0[cursor].epsilon.push(end);
                    }
                } else {
                    let next = self.state();
                    self.compile(child, cursor, next);
                    self.0[next].epsilon.push(cursor);
                }
            }
        }
    }

    fn closure(&self, mut states: BTreeSet<usize>) -> BTreeSet<usize> {
        let mut pending: Vec<_> = states.iter().copied().collect();
        while let Some(state) = pending.pop() {
            for next in &self.0[state].epsilon {
                if states.insert(*next) {
                    pending.push(*next);
                }
            }
        }
        states
    }
}

/// Decide whole-string membership without consulting the vendored engine.
///
/// # Panics
/// Panics only for non-ASCII input or syntax outside the declared fixture subset.
pub(super) fn accepts(pattern: &str, subject: &str) -> bool {
    assert!(pattern.is_ascii() && subject.is_ascii());
    let mut parser = Parser {
        source: pattern.as_bytes(),
        offset: 0,
    };
    let expression = parser.choice();
    assert_eq!(parser.offset, pattern.len());
    let mut automaton = Automaton::default();
    let start = automaton.state();
    let end = automaton.state();
    automaton.compile(&expression, start, end);
    let mut states = automaton.closure(BTreeSet::from([start]));
    for byte in subject.bytes() {
        let mut next = BTreeSet::new();
        for state in states {
            for (bytes, destination) in &automaton.0[state].consuming {
                if bytes.contains(&byte) {
                    next.insert(*destination);
                }
            }
        }
        states = automaton.closure(next);
    }
    states.contains(&end)
}
