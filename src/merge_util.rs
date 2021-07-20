// Blog post: https://creativcoder.dev/merge-k-sorted-arrays-rust
// Merge k sorted arrays

use std::collections::BinaryHeap;
use std::cmp::Reverse;
use std::cmp::Ordering;

#[derive(Debug, Eq)]
struct Item<'a> {
    arr: &'a &'a [u32],
    idx: usize
}

impl<'a> PartialEq for Item<'a> {
    fn eq(&self, other: &Self) -> bool {
        self.get_item() == other.get_item()
    }
}

impl<'a> PartialOrd for Item<'a> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.get_item().partial_cmp(&other.get_item())
    }
}

impl<'a> Ord for Item<'a> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.get_item().cmp(&other.get_item())
    }
}

impl<'a> Item<'a> {
    fn new(arr: &'a &[u32], idx: usize) -> Self {
        Self { arr, idx }
    }

    fn get_item(&self) -> u32 {
        self.arr[self.idx]
    }
}

pub fn merge_vectors(arrays: Vec<&[u32]>) -> Vec<u32> {
    let mut sorted = Vec::with_capacity(arrays.iter().map(|a| a.len()).sum());

    let mut heap = BinaryHeap::with_capacity(arrays.len());
    for arr in &arrays {
        let item = Item::new(arr, 0);
        heap.push(Reverse(item));
    }

    while !heap.is_empty() {
        let mut it = heap.pop().unwrap();
        sorted.push(it.0.get_item());
        it.0.idx += 1;
        if it.0.idx < it.0.arr.len() {
            heap.push(it)
        }
    }

    sorted
}
