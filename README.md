## IRMAseal wasm bindings
This crate automatically generates javascript wasm-bindgen bindings
to call into the IRMAseal rust library from javacript.

## Prerequisites 
Make sure the latest version of wasm-pack is installed:
```
cargo install --git https://github.com/rustwasm/wasm-pack.git
```

## Building
To build the bindings package, run: 
```
wasm-pack build --release -d pkg/ --out-name index --scope e4a
```
Note that this includes a scope.

## Publishing

```
wasm-pack publish
```
