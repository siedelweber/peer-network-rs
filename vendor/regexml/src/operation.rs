use enum_dispatch::enum_dispatch;

use crate::character_class::CharacterClass;
use crate::op_atom::Atom;
use crate::op_back_reference::BackReference;
use crate::op_bol::Bol;
use crate::op_capture::Capture;
use crate::op_character_class::CharClass;
use crate::op_choice::Choice;
use crate::op_end_program::EndProgram;
use crate::op_eol::Eol;
use crate::op_greedy_fixed::GreedyFixed;
use crate::op_nothing::Nothing;
use crate::op_reluctant_fixed::ReluctantFixed;
use crate::op_repeat::Repeat;
use crate::op_sequence::Sequence;
use crate::op_unambiguous_repeat::UnambiguousRepeat;

use crate::re_flags::{Language, ReFlags};
use crate::re_matcher::ReMatcher;

pub(crate) const MATCHES_ZLS_AT_START: u32 = 1;
pub(crate) const MATCHES_ZLS_AT_END: u32 = 2;
pub(crate) const MATCHES_ZLS_ANYWHERE: u32 = 7;
pub(crate) const MATCHES_ZLS_NEVER: u32 = 1024;

#[enum_dispatch]
pub(crate) trait OperationControl {
    /// Get the length of the matches returned by this operation if they are
    /// fixed-length.
    fn get_match_length(&self) -> Option<usize> {
        None
    }

    /// Get the minimum length of the matches returned by this operation.
    fn get_minimum_match_length(&self) -> usize {
        self.get_match_length().unwrap_or(0)
    }

    /// Get a character class identifying the set of the characters that can
    /// appear as the first character of a non-empty string that matches this
    /// term. This is allowed to be an over-estimate (that is, the returned
    /// Character class must match every character that can legitimately appear
    /// at the start of the matched string, but it can also match other
    /// characters).
    fn get_initial_character_class(&self, _case_blind: bool) -> CharacterClass {
        CharacterClass::all()
    }

    /// Get an optimized version of this operation.
    ///
    // TODO: I don't know how to spell a generic one for this, which just
    // clones the operation, so I've replicated them for the various structs.
    fn optimize(self, _flags: &ReFlags) -> Operation;

    /// Ask whether the regular expression is known, after static analysis, to
    /// match a zero-length string.
    ///
    /// Specifically:
    ///
    /// * MATCHES_ZLS_AT_START if the expression is statically known to match a
    ///   zero-length string at the start of the supplied input
    ///
    /// * MATCHES_ZLS_AT_END} if it is statically known to return a zero-length
    ///   string at the end of the supplied input.
    ///
    /// * MATCHES_ZLS_ANYWHERE if it is statically known to match a zero-length
    ///   string anywhere in the input.
    ///
    /// * MATCHES_ZLS_NEVER if it is statically known that the regex will never
    ///   match a zero length string.
    ///
    /// Returning 0 means that it is not known statically whether or not the
    /// regex will match a zero-length string; this case typically arises when
    /// back-references are involved.
    fn matches_empty_string(&self) -> u32;

    /// Get an iterator returning all the matches for this operation.
    ///
    /// The `matcher` supplies the context for the matching; may be updated
    /// with information about captured groups.
    ///
    /// The position is the start position to seek a match.
    ///
    /// This is the raw implementation; everything that walks the operation
    /// tree calls [`Operation::matches_iter`] instead, so that the steps it
    /// takes are counted against the matcher's budget.
    fn matches_iter_impl<'a>(
        &'a self,
        matcher: &'a ReMatcher<'a>,
        position: usize,
    ) -> Box<dyn Iterator<Item = usize> + 'a>;

    /// Ask whether the expression contains any capturing sub-expressions
    /// Returns true if the expression contains any capturing sub-expressions
    /// (but not if it is a capturing expression itself, unless it contains
    /// nested capturing expressions).
    fn contains_capturing_expressions(&self) -> bool {
        false
    }

    /// Access child information so we can structurally dive into
    /// a regex, mostly for testing purposes.
    /// allow unused code to exist as we do use it in the tests
    #[allow(dead_code)]
    fn children(&self) -> Vec<Operation> {
        Vec::new()
    }
}

pub(crate) trait RepeatOperation {
    fn child(&self) -> Operation;
    fn min(&self) -> usize;
    fn max(&self) -> usize;
    fn greedy(&self) -> bool;
}

#[enum_dispatch(OperationControl)]
#[derive(Debug, Clone)]
pub(crate) enum Operation {
    Bol,
    Atom,
    BackReference,
    Capture,
    Choice,
    EndProgram,
    Eol,
    Nothing,
    Repeat,
    Sequence,
    CharClass,
    GreedyFixed,
    ReluctantFixed,
    UnambiguousRepeat,
}

impl Operation {
    /// Get an iterator returning all the matches for this operation, counting
    /// the work it does against the matcher's operation budget.
    ///
    /// Every step of the backtracking walk passes through here: an operation
    /// can only hand control to a sub-operation by asking it for an iterator,
    /// and can only make progress by pulling the next match out of one. So
    /// counting both events bounds the total work done by a match, and a
    /// bounded match that runs out of budget stops producing matches, which
    /// unwinds the walk.
    ///
    /// When no budget is set (the default) the iterator is returned as-is, so
    /// unbounded matching does no extra allocation.
    pub(crate) fn matches_iter<'a>(
        &'a self,
        matcher: &'a ReMatcher<'a>,
        position: usize,
    ) -> Box<dyn Iterator<Item = usize> + 'a> {
        if !matcher.is_bounded() {
            return self.matches_iter_impl(matcher, position);
        }
        if !matcher.tick() {
            return Box::new(std::iter::empty());
        }
        Box::new(BudgetIterator {
            matcher,
            base: self.matches_iter_impl(matcher, position),
        })
    }

    pub(crate) fn repeat_operation(&self) -> Option<&dyn RepeatOperation> {
        match self {
            Operation::Repeat(repeat) => Some(repeat),
            Operation::GreedyFixed(greedy_fixed) => Some(greedy_fixed),
            Operation::ReluctantFixed(reluctant_fixed) => Some(reluctant_fixed),
            Operation::UnambiguousRepeat(unambiguous_repeat) => Some(unambiguous_repeat),
            _ => None,
        }
    }
}

// The BudgetIterator counts every match it produces against the matcher's
// operation budget. Once the budget is used up it stops producing matches,
// which makes the operations above it in the walk backtrack and give up.
struct BudgetIterator<'a> {
    matcher: &'a ReMatcher<'a>,
    base: Box<dyn Iterator<Item = usize> + 'a>,
}

impl Iterator for BudgetIterator<'_> {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.matcher.tick() {
            return None;
        }
        self.base.next()
    }
}

// A repetition can produce duplicate non-empty endpoints from distinct paths;
// those paths must not terminate XSD membership before another suffix is tried.
// In XSD, cut off repeated endpoints only at the repetition's starting position
// (zero-length progress). Nullable XSD operands use their own endpoint search.
// XPath keeps the upstream duplicate cut-off and its known membership defects.
// Local correction; existing COPYRIGHT and LICENSE-MPL2 terms are unchanged.
pub(crate) struct ForceProgressIterator<'a> {
    base: Box<dyn Iterator<Item = usize> + 'a>,
    count_zero_length: usize,
    current_pos: Option<usize>,
    zero_length_position: Option<usize>,
}

impl<'a> ForceProgressIterator<'a> {
    pub(crate) fn new(
        base: Box<dyn Iterator<Item = usize> + 'a>,
        position: usize,
        language: Language,
    ) -> Self {
        Self {
            base,
            count_zero_length: 0,
            current_pos: None,
            zero_length_position: (language == Language::XSD).then_some(position),
        }
    }
}
impl Iterator for ForceProgressIterator<'_> {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count_zero_length > 3 {
            return None;
        }
        let p = Some(self.base.next()?);
        if p == self.current_pos
            && (self.zero_length_position.is_none() || p == self.zero_length_position)
        {
            self.count_zero_length += 1;
        } else {
            self.count_zero_length = 0;
            self.current_pos = p;
        }
        p
    }
}
