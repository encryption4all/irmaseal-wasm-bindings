## IRMAseal wasm bindings
This crate automatically generates javascript wasm-bindgen bindings
to call into the IRMAseal rust library from javacript.

## Prerequisites 

```
cargo install wasm-pack
```

## Building

```
wasm-pack build --release -out-name index --no-typescript
```

## Publishing

```
wasm-pack publish
```
