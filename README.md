# A module for nmap xml

## Examples
Basic usage:

```rust
use rust_nmap;

let result = rust_nmap::parse_nmap_xml("/xxx/nmap_result.xml");
println!("{:?}", result.unwrap());
```