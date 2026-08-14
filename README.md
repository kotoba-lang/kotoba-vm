# kotoba-vm

**The IPLD actor invocation kernel for a Kotoba app-chain.** Filecoin's FVM in shape (Machine / Call Manager / Kernel / syscalls / invocation-local handles / message-local overlay), not Filecoin's FVM in mechanism.

This repo is the missing execution plane behind `inga.state`'s `:invoke-fn` seam. Consensus does not import it. It is injected, the same way `codebase.actor` is.

> kotoba-vm names itself here because the short name does not tell you which VM.
> It is **not** `kototama` (Wasm host), **not** `codebase.actor` (a pure function),
> **not** `io-filecoin` (a protocol client), **not** `kotoba-lang/machine`
> (hardware descriptors), and **not** the historical etzhayyim Rust Pregel crate
> of the same name.

## Shape (FIP-0030 analogue)

```
guest (v1 register machine, or a test-only host-fn)
  ↕ kotoba.vm syscalls
Kernel (handles, overlay)
  ↕
Call Manager (stack, fuel, revert)
  ↕
Machine apply-message
  ↕ externs: get-fn / put!   (io-ipld storage port)
inga.state :invoke-fn adapter (callee state only)
```

Takes F1 / F2 / F3 from ADR-2608038000. Rejects Expected Consensus, HAMT, MPT, EVM opcodes, FIL gas markets, PoRep/PoSt. Fuel exhaustion is a **value**, never a throw, and never a Wasm `unreachable` trap.

## What a guest may do

IPLD: `open` / `read` / `write` / `link` / `stat`. Self: `root` / `set-state`. Nested: `actor/call` (depth cap 8). That is the whole surface.

Writes land in a message-local overlay. Success flushes through `:put!`. Revert drops the overlay. A nested call snapshots the overlay; child failure restores it (the caller's writes from before the call stay; the callee's do not). Handles are invocation-local.

The guest never sees `:get-fn` or `:put!`. A replica that disagrees on bytes under a CID throws `:ipld/cid-mismatch` — a storage fault, not an actor refusal.

## What this is not for

Do not put this kernel on the kotobase query / index hot path (ADR-2608610000). A prolly-tree transaction through an FVM-style host/guest boundary is the cost that decision measured. This kernel runs **committed messages**, not database reads.

Wasm is not the production guest. Compiler Wasm fuel traps; the production path is `.cljc`. A later `.kotoba` / wasm guest is additive behind the same syscalls.

## Code CID (v1)

```clojure
{"kotoba.vm/guest" 1
 "methods" {"inc" [["self" "s"] ["open" "s" "h"] …]}}
;; or, test seam only:
{"kotoba.vm/guest" 1
 "host" "counter"}
```

## Use

```clojure
(require '[kotoba.vm :as vm]
         '[ipld.core :as ipld])

(def store (vm/memory-store))
(def machine {:get-fn (:get-fn store) :put! (:put! store)})
(def code (vm/put-code! (:put! machine)
                        {"kotoba.vm/guest" 1
                         "methods" {"inc" [["self" "s"]
                                           ["open" "s" "h"]
                                           ["node" "h" "n"]
                                           ["get" "n" "count" "c"]
                                           ["inc" "c" "c"]
                                           ["put" "n" "count" "c" "n"]
                                           ["write-node" "n" "s"]
                                           ["set-state" "s"]
                                           ["return" "c"]]}}))
(def state (ipld/put-node! (:put! machine) {"count" 0}))

(vm/apply-message machine
  {:actors {"alice" {:code code :state state :nonce 0 :balance 0}}
   :from "bob" :to "alice" :method "inc" :args [] :fuel 10000})
;; => {:ok? true :actors {…} :receipt {:exit :ok :return 1 …}}

;; Thin adapter for inga.state — writes only the callee's record.
((vm/invoke-fn machine)
 {:address "alice" :caller "bob" :code code :state state
  :method "inc" :args [] :fuel 10000})
;; => {:state <cid>} or {:refused :fuel-exhausted|:no-code|…}
```

Cross-actor mutation needs `apply-message`. `invoke-fn` cannot write another actor's record; that is the consensus seam's invariant, not a VM limitation.

## Test / lint

```bash
clojure -M:test
clojure -M:lint
```

The suite is written to fail if the claimed property is broken: determinism, fuel-as-value, IPLD roundtrip, cross-actor call, nested revert, store isolation, boundary accounting, the inga-shaped seam, CID-mismatch as throw.
