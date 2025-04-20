use pyo3::prelude::*;
use std::cmp::{max, min};

#[pyclass(module = "qh3._hazmat")]
#[derive(Clone)]
pub struct RangeSet {
    ranges: Vec<(i64, i64)>,
}

#[pymethods]
impl RangeSet {
    #[new]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        RangeSet { ranges: Vec::new() }
    }

    #[pyo3(signature = (start, stop=None))]
    #[inline(always)]
    pub fn add(&mut self, start: i64, stop: Option<i64>) {
        let mut start = start;
        let mut stop = stop.unwrap_or(start + 1);
        assert!(stop > start);

        let mut i = 0;
        while i < self.ranges.len() {
            let (r_start, r_stop) = self.ranges[i];
            if stop < r_start {
                self.ranges.insert(i, (start, stop));
                return;
            } else if start > r_stop {
                i += 1;
                continue;
            } else {
                start = min(start, r_start);
                stop = max(stop, r_stop);
                self.ranges.remove(i);
                while i < self.ranges.len() && self.ranges[i].0 <= stop {
                    stop = max(stop, self.ranges[i].1);
                    self.ranges.remove(i);
                }
                self.ranges.insert(i, (start, stop));
                return;
            }
        }
        self.ranges.push((start, stop));
    }

    #[inline(always)]
    pub fn subtract(&mut self, start: i64, stop: i64) {
        assert!(stop > start);
        let mut i = 0;
        while i < self.ranges.len() {
            let (r_start, r_stop) = self.ranges[i];
            if stop <= r_start {
                return;
            } else if start >= r_stop {
                i += 1;
                continue;
            } else if start <= r_start && stop >= r_stop {
                self.ranges.remove(i);
                continue;
            } else if start > r_start {
                self.ranges[i] = (r_start, start);
                if stop < r_stop {
                    self.ranges.insert(i + 1, (stop, r_stop));
                    return;
                }
            } else {
                self.ranges[i] = (stop, r_stop);
                i += 1;
            }
        }
    }

    #[inline(always)]
    pub fn shift(&mut self) -> (i64, i64) {
        self.ranges.remove(0)
    }

    #[inline(always)]
    pub fn bounds(&self) -> (i64, i64) {
        let first = self.ranges.first().expect("RangeSet is empty");
        let last = self.ranges.last().unwrap();
        (first.0, last.1)
    }

    pub fn __len__(&self) -> usize {
        self.ranges.len()
    }

    pub fn __getitem__(&self, idx: isize) -> PyResult<(i64, i64)> {
        let len = self.ranges.len() as isize;
        let index = if idx < 0 { len + idx } else { idx };
        if index < 0 || index >= len {
            return Err(pyo3::exceptions::PyIndexError::new_err(
                "index out of range",
            ));
        }
        Ok(self.ranges[index as usize])
    }

    pub fn __contains__(&self, val: i64) -> bool {
        for (start, stop) in &self.ranges {
            if val >= *start && val < *stop {
                return true;
            }
        }
        false
    }

    pub fn __eq__(&self, other: PyRef<RangeSet>) -> bool {
        self.ranges == other.ranges
    }

    pub fn __repr__(&self) -> String {
        let parts: Vec<String> = self
            .ranges
            .iter()
            .map(|(s, e)| format!("range({}, {})", s, e))
            .collect();
        format!("RangeSet([{}])", parts.join(", "))
    }
}
