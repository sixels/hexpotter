# Hexpotter

**Hexpotter** is a high-performance, multi-pattern binary scanning library for Rust.

## Usage
```Rust
use hexpotter::{Hexpotter, Scan};

fn main() {
    let patterns = vec![
        "48 89 5C 24 08",              // Exact match
        "E8 ?? ?? ?? ?? 48 89 44 24",  // Full wildcard (??)
        "8B 0D F? ?? ?? ??",           // Nibble wildcard (F?)
    ];
    let scanner = Hexpotter::new(patterns);

    let data = std::fs::read("dump.bin").unwrap();
    scanner.scan(&data, |m| {
        println!("Found Pattern ID {} at offset 0x{:X}", m.id(), m.start());        
        Scan::Continue
    });
}
```
