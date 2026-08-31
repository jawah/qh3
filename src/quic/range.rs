use std::fmt;
use std::ops::Range;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RangeSetError {
    EmptyRange,
    TooManyRanges { limit: usize },
}

impl fmt::Display for RangeSetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyRange => f.write_str("range must have start < end"),
            Self::TooManyRanges { limit } => write!(f, "range count exceeds limit {limit}"),
        }
    }
}

impl std::error::Error for RangeSetError {}

/// Sorted, disjoint unsigned half-open ranges. Adjacent ranges are coalesced.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RangeSet {
    ranges: Vec<Range<u64>>,
    max_ranges: Option<usize>,
}

impl Default for RangeSet {
    fn default() -> Self {
        Self::new()
    }
}

impl RangeSet {
    pub const fn new() -> Self {
        Self {
            ranges: Vec::new(),
            max_ranges: None,
        }
    }

    pub const fn with_max_ranges(max_ranges: usize) -> Self {
        Self {
            ranges: Vec::new(),
            max_ranges: Some(max_ranges),
        }
    }

    pub fn len(&self) -> usize {
        self.ranges.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    pub fn add(&mut self, start: u64, end: u64) -> Result<(), RangeSetError> {
        if start >= end {
            return Err(RangeSetError::EmptyRange);
        }

        let first = self.ranges.partition_point(|range| range.end < start);
        let mut last = first;
        let mut merged_start = start;
        let mut merged_end = end;
        while let Some(range) = self.ranges.get(last) {
            if range.start > merged_end {
                break;
            }
            merged_start = merged_start.min(range.start);
            merged_end = merged_end.max(range.end);
            last += 1;
        }

        let new_len = self.ranges.len() - (last - first) + 1;
        self.check_len(new_len)?;
        self.ranges
            .splice(first..last, std::iter::once(merged_start..merged_end));
        Ok(())
    }

    pub fn subtract(&mut self, start: u64, end: u64) -> Result<(), RangeSetError> {
        if start >= end {
            return Err(RangeSetError::EmptyRange);
        }

        let split = self
            .ranges
            .iter()
            .any(|range| range.start < start && end < range.end);
        self.check_len(self.ranges.len() + usize::from(split))?;

        let mut output = Vec::with_capacity(self.ranges.len() + usize::from(split));
        for range in self.ranges.drain(..) {
            if range.end <= start || range.start >= end {
                output.push(range);
                continue;
            }
            if range.start < start {
                output.push(range.start..start);
            }
            if end < range.end {
                output.push(end..range.end);
            }
        }
        self.ranges = output;
        Ok(())
    }

    pub fn contains(&self, value: u64) -> bool {
        let index = self.ranges.partition_point(|range| range.end <= value);
        self.ranges
            .get(index)
            .is_some_and(|range| range.start <= value)
    }

    pub fn pop_first(&mut self) -> Option<Range<u64>> {
        if self.ranges.is_empty() {
            None
        } else {
            Some(self.ranges.remove(0))
        }
    }

    /// Retains the newest ranges and returns the start of the oldest retained
    /// range when any older ranges were removed.
    pub(super) fn retain_last(&mut self, max_ranges: usize) -> Option<u64> {
        if self.ranges.len() <= max_ranges {
            return None;
        }
        let remove = self.ranges.len() - max_ranges;
        let floor = self.ranges.get(remove).map(|range| range.start);
        self.ranges.drain(..remove);
        floor
    }

    pub fn bounds(&self) -> Option<Range<u64>> {
        Some(self.ranges.first()?.start..self.ranges.last()?.end)
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = &Range<u64>> + DoubleEndedIterator {
        self.ranges.iter()
    }

    fn check_len(&self, len: usize) -> Result<(), RangeSetError> {
        if self.max_ranges.is_some_and(|limit| len > limit) {
            Err(RangeSetError::TooManyRanges {
                limit: self.max_ranges.unwrap_or(0),
            })
        } else {
            Ok(())
        }
    }
}

impl<'a> IntoIterator for &'a RangeSet {
    type Item = &'a Range<u64>;
    type IntoIter = std::slice::Iter<'a, Range<u64>>;

    fn into_iter(self) -> Self::IntoIter {
        self.ranges.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ranges(set: &RangeSet) -> Vec<Range<u64>> {
        set.iter().cloned().collect()
    }

    #[test]
    fn adds_sorted_and_coalesces_overlap_and_adjacency() {
        let mut set = RangeSet::new();
        set.add(10, 20).unwrap();
        set.add(30, 40).unwrap();
        set.add(20, 30).unwrap();
        set.add(5, 8).unwrap();
        assert_eq!(ranges(&set), vec![5..8, 10..40]);
        assert_eq!(set.bounds(), Some(5..40));
    }

    #[test]
    fn subtracts_across_and_splits_ranges() {
        let mut set = RangeSet::new();
        set.add(0, 10).unwrap();
        set.add(20, 30).unwrap();
        set.subtract(3, 27).unwrap();
        assert_eq!(ranges(&set), vec![0..3, 27..30]);
        set.subtract(0, u64::MAX).unwrap();
        assert!(set.is_empty());
        assert_eq!(set.bounds(), None);
    }

    #[test]
    fn contains_observes_half_open_bounds() {
        let mut set = RangeSet::new();
        set.add(2, 4).unwrap();
        assert!(!set.contains(1));
        assert!(set.contains(2));
        assert!(set.contains(3));
        assert!(!set.contains(4));
    }

    #[test]
    fn pop_first_is_safe_when_empty() {
        let mut set = RangeSet::new();
        assert_eq!(set.pop_first(), None);
        set.add(7, 9).unwrap();
        assert_eq!(set.pop_first(), Some(7..9));
        assert_eq!(set.pop_first(), None);
    }

    #[test]
    fn retains_last_ranges_and_reports_floor() {
        let mut set = RangeSet::new();
        set.add(0, 1).unwrap();
        set.add(2, 3).unwrap();
        set.add(4, 5).unwrap();

        assert_eq!(set.retain_last(2), Some(2));
        assert_eq!(ranges(&set), vec![2..3, 4..5]);
        assert_eq!(set.retain_last(2), None);
    }

    #[test]
    fn rejects_invalid_ranges_without_mutation() {
        let mut set = RangeSet::new();
        set.add(1, 2).unwrap();
        let before = set.clone();
        assert_eq!(set.add(2, 2), Err(RangeSetError::EmptyRange));
        assert_eq!(set.subtract(9, 3), Err(RangeSetError::EmptyRange));
        assert_eq!(set, before);
    }

    #[test]
    fn bounded_set_fails_atomically() {
        let mut set = RangeSet::with_max_ranges(1);
        set.add(0, 10).unwrap();
        assert_eq!(
            set.add(20, 30),
            Err(RangeSetError::TooManyRanges { limit: 1 })
        );
        assert_eq!(ranges(&set), vec![0..10]);
        assert_eq!(
            set.subtract(3, 7),
            Err(RangeSetError::TooManyRanges { limit: 1 })
        );
        assert_eq!(ranges(&set), vec![0..10]);
        set.add(10, 20).unwrap();
        assert_eq!(ranges(&set), vec![0..20]);
    }

    #[test]
    fn handles_unsigned_extremes() {
        let mut set = RangeSet::new();
        set.add(u64::MAX - 1, u64::MAX).unwrap();
        assert!(set.contains(u64::MAX - 1));
        assert!(!set.contains(u64::MAX));
        set.subtract(u64::MAX - 1, u64::MAX).unwrap();
        assert!(set.is_empty());
    }
}
