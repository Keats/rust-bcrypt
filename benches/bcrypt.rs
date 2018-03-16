#![feature(test)]
extern crate bcrypt;
extern crate test;

use bcrypt::{hash, DEFAULT_COST};

#[bench]
fn bench_cost_4(b: &mut test::Bencher) {
    b.iter(|| hash("hunter2", 4));
}

#[bench]
fn bench_cost_10(b: &mut test::Bencher) {
    b.iter(|| hash("hunter2", 10));
}

#[bench]
fn bench_cost_default(b: &mut test::Bencher) {
    b.iter(|| hash("hunter2", DEFAULT_COST));
}

#[bench]
fn bench_cost_14(b: &mut test::Bencher) {
    b.iter(|| hash("hunter2", 14));
}
