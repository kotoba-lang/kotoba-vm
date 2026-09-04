(ns kotoba.vm.evm.core
  "EVM core: Paris-fork instruction dispatch over a stack + memory machine.

  The word type is `kotoba.vm.evm.u256` — one BigInt-backed representation
  on both runtimes. Arithmetic and comparisons ride it directly. Bitwise
  ops (AND/OR/XOR/NOT/SHL/SHR/SAR/BYTE) go through the canonical 64-digit
  hex form: word → 32 big-endian bytes → bytewise op → word. One route,
  both runtimes, nothing to drift.

  Keccak rides `kotoba.vm.keccak` (portable, vector-verified) — never
  re-implemented here. ADDMOD/MULMOD need full-precision intermediates,
  which ride the runtime bigint through the decimal/hex string surface
  of u256.

  Machine shape (an immutable map):

    {:code       byte-seq        running code (vector of 0..255)
     :stack      [...]           top of stack LAST (conj/pop at the end)
     :memory     byte-seq        byte-addressed, grows in 32-byte pages
     :pc         int             index of the next opcode
     :gas        int             remaining gas
     :steps      int             executed-op counter (halting bound)
     :calldata   byte-seq        attached by the caller
     :returndata byte-seq        empty until the calls slice fills it
     :storage    map             slot-hex → word (mock KAMT shape)
     :env        map             ADDRESS/CALLER/BALANCE/block context
     :status     keyword         :running | terminal
     :output     byte-seq        RETURN/REVERT payload}

  `run` steps until a terminal status:

    :stopped   STOP (no output)
    :halted    RETURN (output = memory slice)
    :reverted  REVERT (output = memory slice)
    :invalid   exceptional halt — invalid opcode, stack underflow/
               overflow, out-of-gas, JUMP to a non-JUMPDEST, truncated
               PUSH immediate

  Storage, accounts, and calls belong to later slices, which extend
  dispatch, not this loop. Gas follows the Paris static schedule for the
  ops executed here; KECCAK256 adds its dynamic 6/word cost. EXP's
  dynamic per-byte cost is a documented omission (flat 10 gas) — the
  profile stays :partial."
  (:require [kotoba.vm.evm.u256 :as u256]
            [kotoba.vm.evm.storage :as storage]
            [kotoba.vm.evm.env :as env]
            [kotoba.vm.keccak :as keccak]))

(def max-stack-depth 1024)
(def max-steps 1000000)

;; ---- gas tiers (Yellow Paper Appendix H subset, Paris) -----------------

(def ^:private gas-tiers
  {:zero 0
   :base 2
   :verylow 3
   :low 5
   :mid 8
   :high 10
   :keccak-base 30
   :keccak-word 6})

(defn- g [tier] (get gas-tiers tier 0))

(def ^:private op-gas
  {0x00 :zero        ;; STOP
   0x01 :verylow     ;; ADD
   0x02 :verylow     ;; MUL
   0x03 :verylow     ;; SUB
   0x04 :low         ;; DIV
   0x05 :low         ;; SDIV
   0x06 :low         ;; MOD
   0x07 :low         ;; SMOD
   0x08 :mid         ;; ADDMOD
   0x09 :mid         ;; MULMOD
   0x0a :high        ;; EXP — flat; dynamic byte cost is a profiled omission
   0x0b :verylow     ;; SIGNEXTEND
   0x10 :verylow     ;; LT
   0x11 :verylow     ;; GT
   0x12 :verylow     ;; SLT
   0x13 :verylow     ;; SGT
   0x14 :verylow     ;; EQ
   0x15 :base        ;; ISZERO
   0x16 :verylow     ;; AND
   0x17 :verylow     ;; OR
   0x18 :verylow     ;; XOR
   0x19 :verylow     ;; NOT
   0x1a :base        ;; BYTE
   0x1b :verylow     ;; SHL
   0x1c :verylow     ;; SHR
   0x1d :verylow     ;; SAR
   0x20 :keccak-base ;; KECCAK256 (+ dynamic 6/word)
   0x30 :base       ;; ADDRESS
   0x31 :base       ;; BALANCE (mock ledger; cold-access cost is an omission)
   0x32 :base       ;; ORIGIN
   0x33 :base       ;; CALLER
   0x34 :base       ;; CALLVALUE
   0x3a :base       ;; GASPRICE
   0x3d :base       ;; RETURNDATASIZE (0 until the calls slice)
   0x40 :base       ;; BLOCKHASH (mock map)
   0x41 :base       ;; COINBASE
   0x42 :base       ;; TIMESTAMP
   0x43 :base       ;; NUMBER
   0x44 :base       ;; PREVRANDAO (difficulty field, post-merge)
   0x45 :base       ;; GASLIMIT
   0x46 :base       ;; CHAINID (314 = Filecoin mainnet, FIP-0054 shape)
   0x48 :base       ;; BASEFEE
   0x50 :base        ;; POP
   0x51 :verylow    ;; MLOAD
   0x52 :verylow    ;; MSTORE
   0x53 :verylow    ;; MSTORE8
   0x54 :high       ;; SLOAD — cold 2100 per the Paris access-list-free schedule
   0x55 :high       ;; SSTORE — mock schedule: flat 20000 (set) / 2900 (clear)
   0x56 :mid         ;; JUMP
   0x57 :high        ;; JUMPI
   0x58 :base        ;; PC
   0x5b :base        ;; JUMPDEST
   0x5f :base        ;; PUSH0 (Paris, EIP-3855)
   0xf3 :zero        ;; RETURN
   0xfd :zero        ;; REVERT
   0xfe :zero})      ;; INVALID (all gas consumed at dispatch)

(defn- static-gas
  [op]
  (cond
    (contains? op-gas op) (g (op-gas op))
    (and (>= op 0x60) (<= op 0x7f)) (g :verylow)   ;; PUSH1..PUSH32
    (and (>= op 0x80) (<= op 0x8f)) (g :verylow)   ;; DUP1..DUP16
    (and (>= op 0x90) (<= op 0x9f)) (g :verylow)   ;; SWAP1..SWAP16
    :else :invalid))

;; ---- words <-> bytes ----------------------------------------------------

(defn- format-hex-byte [v]
  #?(:clj (format "%02x" v)
     :cljs (let [s (.toString (js/Number v) 16)]
             (if (< v 16) (str "0" s) s))))

(defn word->bytes
  "u256 → vector of 32 ints 0..255, big-endian (the EVM word order)."
  [x]
  (let [hx (u256/to-hex-string x)]
    (mapv (fn [i]
            #?(:clj (Integer/parseInt (subs hx (* 2 i) (+ 2 (* 2 i))) 16)
               :cljs (js/parseInt (subs hx (* 2 i) (+ 2 (* 2 i))) 16)))
          (range 32))))

(defn bytes->word
  "Byte seq → u256, big-endian, left-padded to 32 bytes."
  [bs]
  (let [bs (vec bs)
        n (count bs)]
    (when (> n 32)
      (throw (ex-info "bytes->word: longer than a word" {:n n})))
    (u256/from-hex-string
     (str (apply str (repeat (- 64 (* 2 n)) "0"))
          (apply str (map #(format-hex-byte (bit-and (int %) 0xff)) bs))))))

(def ^:private one (u256/from-long 1))
(def ^:private zero-word (u256/from-long 0))

(defn- bool->word [b] (if b one zero-word))

;; ---- bigint shims (full-precision ADDMOD/MULMOD intermediates) ----------

(defn- to-big
  "u256 → runtime bigint via the decimal string surface."
  [x]
  #?(:clj (java.math.BigInteger. (u256/to-string x))
     :cljs (js/BigInt (u256/to-string x))))

(defn- from-big
  "Non-negative bigint → u256 via the hex string surface."
  [bi]
  (let [s #?(:clj (.toString ^java.math.BigInteger bi 16)
             :cljs (.toString bi 16))]
    (u256/from-hex-string
     (str (apply str (repeat (- 64 (count s)) "0")) s))))

;; ---- bitwise over the byte form ------------------------------------------

(defn- bit-op
  [f a b]
  (bytes->word (mapv f (word->bytes a) (word->bytes b))))

(defn- u-and [a b] (bit-op bit-and a b))
(defn- u-or [a b] (bit-op bit-or a b))
(defn- u-xor [a b] (bit-op bit-xor a b))

(defn- u-not
  [a]
  (bytes->word (mapv #(bit-and 0xff (bit-not %)) (word->bytes a))))

(defn- word->long
  "u256 → small non-negative int for shifts/indexes/offsets. Throws past
  2^51 — callers treat that as the exceptional-halt path (out of range)."
  [x]
  (let [s (u256/to-string x)]
    (when (> (count s) 15)
      (throw (ex-info "word out of machine range" {:v s})))
    #?(:clj (Long/parseLong s)
       :cljs (js/Number x))))

(defn- shift-amount
  "Shift/index operand → int, clamped to 256+ (anything ≥ 256 behaves
  identically for SHL/SHR/SAR: the result saturates)."
  [x]
  (try
    (min 256 (word->long x))
    (catch #?(:clj Exception :cljs js/Error) _
      256)))

(defn- shl-bytes
  "Byte string shl by s bits (0 <= s < 256), big-endian, mod 2^256."
  [bs s]
  (let [whole (quot s 8)
        part (mod s 8)
        ;; shift the byte string left by `whole` bytes first
        byte-shifted (into (subvec bs whole) (repeat whole 0))]
    (if (zero? part)
      byte-shifted
      (loop [acc (vec byte-shifted)
             carry 0
             i 31]
        (if (neg? i)
          acc
          (let [v (nth acc i)
                nv (bit-and 0xff (+ (bit-shift-left v part) carry))]
            (recur (assoc acc i nv)
                   ;; the bits that flowed out of this byte's top
                   (bit-and 0xff (bit-shift-right v (- 8 part)))
                   (dec i))))))))

(defn- shr-bytes
  "Byte string logical shr by s bits (0 <= s < 256), big-endian."
  [bs s]
  (let [whole (quot s 8)
        part (mod s 8)
        ;; vec target: (into '() …) would cons-reverse the bytes
        byte-shifted (vec (concat (repeat whole 0)
                                  (subvec bs 0 (- 32 whole))))]
    (if (zero? part)
      byte-shifted
      (loop [acc (vec byte-shifted)
             carry 0
             i 0]
        (if (>= i 32)
          acc
          (let [v (nth acc i)
                nv (bit-and 0xff (+ (bit-shift-right v part) carry))]
            (recur (assoc acc i nv)
                   (bit-and 0xff (bit-shift-left v (- 8 part)))
                   (inc i))))))))

(defn- u-shl
  "SHL(shift, x): x << shift mod 2^256, 0 when shift >= 256."
  [shift x]
  (let [s (shift-amount shift)]
    (cond
      (zero? s) x
      (>= s 256) zero-word
      :else (bytes->word (shl-bytes (word->bytes x) s)))))

(defn- u-shr
  "SHR(shift, x): logical shift right, 0 when shift >= 256."
  [shift x]
  (let [s (shift-amount shift)]
    (cond
      (zero? s) x
      (>= s 256) zero-word
      :else (bytes->word (shr-bytes (word->bytes x) s)))))

(defn- negative?
  "True when the word's sign bit (bit 255) is set."
  [x]
  (>= (nth (word->bytes x) 0) 0x80))

(defn- u-sar
  "SAR(shift, x): arithmetic shift right on the two's-complement reading.
  shift >= 256: 0 for non-negative x, all-ones for negative. Negative
  words: NOT first, shift logically, NOT again (the two's-complement
  identity −x = NOT(x−1) makes that exact)."
  [shift x]
  (let [s (shift-amount shift)]
    (cond
      (zero? s) x
      (>= s 256) (if (negative? x)
                   (u256/from-hex-string
                    "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                   zero-word)
      :else (bytes->word
             (if (negative? x)
               (mapv #(bit-and 0xff (bit-not %))
                     (shr-bytes (mapv #(bit-and 0xff (bit-not %)) (word->bytes x)) s))
               (shr-bytes (word->bytes x) s))))))

(defn- u-byte
  "BYTE(i, x): i-th byte of x, big-endian indexed (0 = most significant).
  i >= 32 → 0."
  [i x]
  (let [idx (try
              (word->long i)
              (catch #?(:clj Exception :cljs js/Error) _ 32))]
    (if (>= idx 32)
      zero-word
      (bytes->word [(nth (word->bytes x) idx)]))))

(defn- u-slt
  [a b]
  (bool->word (let [sa (negative? a) sb (negative? b)]
                (if (= sa sb) (u256/lt a b) sa))))

(defn- u-sgt
  [a b]
  (bool->word (let [sa (negative? a) sb (negative? b)]
                (if (= sa sb) (u256/gt a b) sb))))

(defn- u-lt-w [a b] (bool->word (u256/lt a b)))
(defn- u-gt-w [a b] (bool->word (u256/gt a b)))
(defn- u-eq-w [a b] (bool->word (u256/eq a b)))

(defn- u-iszero [a] (bool->word (u256/eq a zero-word)))

(defn- u-div-nz
  "DIV: a/b with a = the top operand. 0 when EITHER operand is 0 —
  u256/div throws on a zero dividend too, but the EVM's DIV is defined
  (as 0) for x/0 only; 0/x is an ordinary 0."
  [a b]
  (if (or (u256/eq b zero-word) (u256/eq a zero-word))
    zero-word
    (u256/div a b)))

(defn- u-mod-nz
  "MOD: a mod b, 0 when b is 0 (a zero dividend is just 0)."
  [a b]
  (if (u256/eq b zero-word)
    zero-word
    (u256/mod a b)))

(defn- negate-word
  "Two's-complement negation on the u256 surface: 0 - x."
  [x] (u256/sub zero-word x))

(defn- u-sdiv
  "SDIV: signed division truncating toward zero; 0 on zero divisor.
  Absolute values, quotient sign applied — truncation falls out of the
  unsigned floor division on non-negative operands. The saturation edge
  2^255 / -1 = 2^255 falls out of the negation wrap."
  [a b]
  (if (u256/eq b zero-word)
    zero-word
    (let [sa (negative? a)
          sb (negative? b)
          aa (if sa (negate-word a) a)
          ab (if sb (negate-word b) b)
          q (if (u256/eq aa zero-word)
              zero-word
              (u256/div aa ab))]
      (if (not= sa sb)
        (negate-word q)
        q))))

(defn- u-smod
  "SMOD: sign of the result follows the dividend. 0 on zero divisor."
  [a b]
  (if (u256/eq b zero-word)
    zero-word
    (let [sa (negative? a)
          sb (negative? b)
          aa (if sa (negate-word a) a)
          ab (if sb (negate-word b) b)
          r (u256/mod aa ab)]
      (if sa (negate-word r) r))))

(defn- u-addmod
  "ADDMOD: (a+b) mod n at full intermediate precision (257 bits — fits
  a runtime bigint through the string surface), 0 when n is 0."
  [a b n]
  (if (u256/eq n zero-word)
    zero-word
    (let [s #?(:clj (.add ^java.math.BigInteger (to-big a) ^java.math.BigInteger (to-big b))
               :cljs (+ (to-big a) (to-big b)))
          n' (to-big n)
          r #?(:clj (.remainder ^java.math.BigInteger s ^java.math.BigInteger n')
               :cljs (rem s n'))]
      (from-big r))))

(defn- u-mulmod
  "MULMOD: (a*b) mod n at full intermediate precision (512 bits — fits a
  runtime bigint through the string surface), 0 when n is 0."
  [a b n]
  (if (u256/eq n zero-word)
    zero-word
    (let [p #?(:clj (.multiply ^java.math.BigInteger (to-big a) ^java.math.BigInteger (to-big b))
               :cljs (* (to-big a) (to-big b)))
          n' (to-big n)
          r #?(:clj (.remainder ^java.math.BigInteger p ^java.math.BigInteger n')
               :cljs (rem p n'))]
      (from-big r))))

(defn- u-exp
  "EXP: a**b mod 2^256, flat 10 gas (the dynamic per-byte cost is a
  documented omission — profile stays :partial). Square-and-multiply;
  u256/mul wrapping mod 2^256 IS the requested result."
  [a b]
  (loop [acc one
         base a
         e b
         guard 0]
    (cond
      (u256/eq e zero-word) acc
      (> guard 256) acc
      :else (let [low-byte (last (word->bytes e))
                  odd-bit (= 1 (bit-and low-byte 1))]
              (recur (if odd-bit (u256/mul acc base) acc)
                     (u256/mul base base)
                     (u-shr one e)
                     (inc guard))))))

;; ---- memory --------------------------------------------------------------

(defn- memory-extend
  "Grow :memory so offset..offset+size is addressable. EVM memory grows
  in 32-byte pages; identity when already long enough."
  [mem offset size]
  (let [needed (+ offset size)]
    (if (<= needed (count mem))
      mem
      (let [pages (quot (+ needed 31) 32)
            new-size (* 32 pages)]
        (into (vec mem) (repeat (- new-size (count mem)) 0))))))

(defn- mem-load
  "Memory bytes offset..offset+size (extending first)."
  [mem offset size]
  (let [mem (memory-extend mem offset size)]
    [mem (subvec mem offset (+ offset size))]))

(defn- mem-store
  "Write value-bytes at offset, extending first."
  [mem offset value-bytes]
  (let [n (count value-bytes)
        mem (memory-extend mem offset n)]
    (reduce (fn [m i] (assoc m (+ offset i) (nth value-bytes i)))
            mem
            (range n))))

;; ---- stack ----------------------------------------------------------------

(defn- underflow? [stack n] (< (count stack) n))

(defn- pops
  "Pop n items (from the END — top of stack last). Returns [popped
  oldest-first, rest] or :underflow."
  [stack n]
  (if (underflow? stack n)
    :underflow
    [(subvec stack (- (count stack) n))
     (subvec stack 0 (- (count stack) n))]))

(defn- push-word
  [stack v]
  (if (>= (count stack) max-stack-depth)
    :overflow
    (conj stack v)))

;; ---- code reads -------------------------------------------------------------

(defn- valid-jumpdest?
  "True when i is a JUMPDEST (0x5b) that is NOT push-immediate data.
  Walks backward: a byte is 'covered' if it sits inside the immediate of
  a PUSH1..32; skip those spans explicitly."
  [code i]
  (and (>= i 0)
       (< i (count code))
       (= 0x5b (nth code i))
       (loop [j 0]
         (if (>= j i)
           true
           (let [op (nth code j)]
             (if (and (>= op 0x60) (<= op 0x7f))
               ;; PUSHn: skip its n immediate bytes
               (let [n (- op 0x5f)]
                 (recur (+ j 1 n)))
               (recur (inc j))))))))

;; ---- gas --------------------------------------------------------------------

(defn- charge
  "Charge gas; :out-of-gas sentinel when the balance goes negative."
  [gas amount]
  (if (> amount gas) :out-of-gas (- gas amount)))

(defn- keccak-gas
  "30 + 6*ceil(size/32)."
  [size]
  (+ (g :keccak-base)
     (* (g :keccak-word) (quot (+ size 31) 32))))

;; ---- memory expansion gas (the c formula, memory-only) ------------------------

(defn- expansion-charge
  "Delta gas to grow memory from its current size to cover
  offset..offset+size. Returns [new-gas new-mem] or :out-of-gas."
  [m offset size]
  (let [mem (:memory m)
        old-words (quot (count mem) 32)
        needed (+ offset size)
        new-words (quot (+ needed 31) 32)]
    (if (<= new-words old-words)
      [(:gas m) mem]
      (let [new-cost (+ (* 3 new-words) (quot (* new-words new-words) 512))
            old-cost (+ (* 3 old-words) (quot (* old-words old-words) 512))
            delta (- new-cost old-cost)]
        (if-let [gas' (charge (:gas m) delta)]
          [gas' (memory-extend mem offset size)]
          :out-of-gas)))))

;; ---- step -------------------------------------------------------------------

(defn- halt
  "Terminal machine: status set, output attached, gas zeroed on the
  exceptional paths."
  [m status output]
  (assoc m :status status :output output :pc (:pc m)))

(defn- invalid
  [m why]
  (assoc m :status :invalid :gas 0 :invalid-reason why))

(def ^:private max-operand-word
  "Guard for operand conversions."
  15)

(defn- operand->int
  "Stack word → int offset/size. Throws on absurd values (> 2^56): the
  caller converts that into :invalid (an exceptional halt — the real EVM
  OOGs on the memory cost)."
  [x]
  (let [s (u256/to-string x)]
    (when (> (count s) max-operand-word)
      (throw (ex-info "operand out of range" {:v s})))
    #?(:clj (Long/parseLong s)
       :cljs (js/Number x))))

(defn- take-1
  [m]
  (let [[ps rest] (pops (:stack m) 1)]
    (if (= :underflow ps) :underflow [rest (nth ps 0)])))

(defn- take-2
  [m]
  (let [[ps rest] (pops (:stack m) 2)]
    (if (= :underflow ps) :underflow [rest (nth ps 1) (nth ps 0)])))

;; ---- storage & environment (evm-storage+env slice) ---------------------------

(defn- step-sload
  [m]
  (let [r (take-1 m)]
    (if (= :underflow r)
      (invalid m "stack underflow")
      (let [[stack slot] r
            w (storage/sload (get m :storage storage/empty-store) slot)
            stack' (push-word stack w)]
        (if (= :overflow stack')
          (invalid m "stack overflow")
          (assoc m :stack stack' :pc (inc (:pc m))))))))

(defn- step-sstore
  "SSTORE(slot, value): mock schedule — 20000 when the slot changes
  from zero to nonzero, 2900 when it changes to (or stays) zero; a
  no-op rewrite is 100 (warm). Storing zero deletes the key."
  [m]
  (let [r (take-2 m)]
    (if (= :underflow r)
      (invalid m "stack underflow")
      (let [[stack slot value] r
            store (get m :storage storage/empty-store)
            current (storage/sload store slot)
            was-zero? (u256/eq current zero-word)
            now-zero? (u256/eq value zero-word)
            unchanged? (u256/eq current value)
            cost (cond unchanged? 100
                       now-zero? 2900
                       was-zero? 20000
                       :else 2900)
            gas' (charge (:gas m) cost)]
        (if (= :out-of-gas gas')
          (invalid m "out of gas (sstore)")
          (let [stack' (push-word stack value)]
            (if (= :overflow stack')
              (invalid m "stack overflow")
              (assoc m :stack stack'
                     :storage (storage/sstore store slot value)
                     :gas gas'
                     :pc (inc (:pc m))))))))))

(defn- push-env-word
  "Push an env word read off the machine."
  [m w]
  (let [stack' (push-word (:stack m) w)]
    (if (= :overflow stack')
      (invalid m "stack overflow")
      (assoc m :stack stack' :pc (inc (:pc m))))))

(defn- step-balance
  [m]
  (let [r (take-1 m)]
    (if (= :underflow r)
      (invalid m "stack underflow")
      (let [[stack addr] r
            e (get m :env env/default-env)
            stack' (push-word stack (env/balance-of e addr))]
        (if (= :overflow stack')
          (invalid m "stack overflow")
          (assoc m :stack stack' :pc (inc (:pc m))))))))

(defn- step-blockhash
  [m]
  (let [r (take-1 m)]
    (if (= :underflow r)
      (invalid m "stack underflow")
      (let [[stack number] r
            e (get m :env env/default-env)
            stack' (push-word stack (env/blockhash-of e number))]
        (if (= :overflow stack')
          (invalid m "stack overflow")
          (assoc m :stack stack' :pc (inc (:pc m))))))))

(defn- step-env-const
  "Push a plain env/block word (no operands consumed)."
  [m w]
  (push-env-word m w))

(defn- step-returndatasize
  "0 until the calls slice populates returndata."
  [m]
  (push-env-word m zero-word))

(defn- block-word
  [e field] (get-in e [:block field]))

(defn- binop
  "Pop 2, apply f, push 1."
  [m f]
  (let [r (take-2 m)]
    (if (= :underflow r)
      :underflow
      (let [[stack a b] r
            stack' (push-word stack (f a b))]
        (if (= :overflow stack')
          :overflow
          (assoc m :stack stack'))))))

(defn- unop
  [m f]
  (let [[ps rest] (pops (:stack m) 1)]
    (if (= :underflow ps)
      :underflow
      (let [stack' (push-word rest (f (nth ps 0)))]
        (if (= :overflow stack')
          :overflow
          (assoc m :stack stack'))))))

(defn- ternop
  "Pop 3 (a deepest); apply (f c b a) so f reads (a b c) as pushed."
  [m f]
  (let [[ps rest] (pops (:stack m) 3)]
    (if (= :underflow ps)
      :underflow
      (let [[a b c] ps
            stack' (push-word rest (f c b a))]
        (if (= :overflow stack')
          :overflow
          (assoc m :stack stack'))))))

(defn- safe-binop
  "binop where f may throw on absurd operands → :invalid."
  [m f]
  (try
    (let [r (binop m f)]
      (if (= :underflow r) (invalid m "stack underflow") r))
    (catch #?(:clj Exception :cljs js/Error) e
      (invalid m (or (ex-message e) "operand out of range")))))

(defn- safe-unop
  [m f]
  (try
    (let [r (unop m f)]
      (if (= :underflow r) (invalid m "stack underflow") r))
    (catch #?(:clj Exception :cljs js/Error) e
      (invalid m (or (ex-message e) "operand out of range")))))

(defn- safe-ternop
  [m f]
  (try
    (let [r (ternop m f)]
      (if (= :underflow r) (invalid m "stack underflow") r))
    (catch #?(:clj Exception :cljs js/Error) e
      (invalid m (or (ex-message e) "operand out of range")))))

(defn- step-push
  "PUSH0..PUSH32. Immediate runs past code end → :invalid (no implicit
  zero-fill of immediates)."
  [m op]
  (let [n (- op 0x5f)]
    (if (zero? n)
      (let [stack' (push-word (:stack m) zero-word)]
        (if (= :overflow stack')
          (invalid m "stack overflow")
          (assoc m :stack stack' :pc (inc (:pc m)))))
      (let [pc (:pc m)
            end (+ pc n)]
        (if (>= end (count (:code m)))
          (invalid m "truncated push immediate")
          (let [w (bytes->word (subvec (:code m) (inc pc) (inc end)))
                stack' (push-word (:stack m) w)]
            (if (= :overflow stack')
              (invalid m "stack overflow")
              (assoc m :stack stack' :pc (inc end)))))))))

(defn- step-dup
  [m op]
  (let [n (- op 0x7f)]    ;; DUP1 duplicates the top item
    (if (underflow? (:stack m) n)
      (invalid m "stack underflow")
      (let [v (nth (:stack m) (- (count (:stack m)) n))
            stack' (push-word (:stack m) v)]
        (if (= :overflow stack')
          (invalid m "stack overflow")
          (assoc m :stack stack'))))))

(defn- step-swap
  [m op]
  (let [n (- op 0x8f)     ;; SWAP1 exchanges top and 2nd
        stack (:stack m)
        cnt (count stack)]
    (if (< cnt (inc n))
      (invalid m "stack underflow")
      (let [i (dec cnt)
            j (- cnt 1 n)
            vi (nth stack i)
            vj (nth stack j)]
        (assoc m :stack (assoc stack i vj j vi))))))

(defn- step-jump
  [m dest]
  (let [p (try (operand->int dest)
               (catch #?(:clj Exception :cljs js/Error) _ -1))]
    (if (and (>= p 0) (valid-jumpdest? (:code m) p))
      (assoc m :pc p)
      (invalid m "invalid jump destination"))))

(defn- step-keccak
  [m]
  (let [r (take-2 m)]
    (if (= :underflow r)
      (invalid m "stack underflow")
      (let [[stack offset-idx size-idx] r
            m0 (assoc m :stack stack)]
        (try
          (let [offset (operand->int offset-idx)
                size (operand->int size-idx)
                [gas' mem'] (expansion-charge m0 offset size)]
            (if (nil? gas')
              (invalid m "out of gas (memory expansion)")
              (let [cg (keccak-gas size)
                    gas'' (charge gas' cg)]
                (if (or (= :out-of-gas gas'') (nil? gas''))
                  (invalid m "out of gas (keccak)")
                  (let [[mem'' bs] (mem-load mem' offset size)
                        w (bytes->word (keccak/keccak256 bs))
                        stack' (push-word (:stack m0) w)]
                    (if (= :overflow stack')
                      (invalid m "stack overflow")
                      (assoc m0 :memory mem'' :gas gas'' :stack stack')))))))
          (catch #?(:clj Exception :cljs js/Error) e
            (invalid m (or (ex-message e) "keccak operand out of range"))))))))

(defn- step-return-revert
  [m status]
  (let [r (take-2 m)]
    (if (= :underflow r)
      (invalid m "stack underflow")
      (let [[stack offset-idx size-idx] r]
        (try
          (let [offset (operand->int offset-idx)
                size (operand->int size-idx)
                [mem bs] (mem-load (:memory m) offset size)]
            (halt (assoc m :stack stack :memory mem) status bs))
          (catch #?(:clj Exception :cljs js/Error) e
            (invalid m (or (ex-message e) "return operand out of range"))))))))

(defn- step-mstore
  [m byte-size]
  (let [r (take-2 m)]
    (if (= :underflow r)
      (invalid m "stack underflow")
      (let [[stack offset-idx value] r
            m0 (assoc m :stack stack)]
        (try
          (let [offset (operand->int offset-idx)
                [gas' mem'] (expansion-charge m0 offset byte-size)]
            (if (nil? gas')
              (invalid m "out of gas (memory expansion)")
              (let [wb (if (= 32 byte-size)
                         (word->bytes value)
                         [(bit-and 0xff (int (last (word->bytes value))))])
                    mem'' (mem-store mem' offset wb)]
                (assoc m0 :gas gas' :memory mem'' :pc (inc (:pc m0))))))
          (catch #?(:clj Exception :cljs js/Error) e
            (invalid m (or (ex-message e) "mstore operand out of range"))))))))

(defn- step-mload
  [m]
  (let [r (take-1 m)]
    (if (= :underflow r)
      (invalid m "stack underflow")
      (let [[stack offset-idx] r
            m0 (assoc m :stack stack)]
        (try
          (let [offset (operand->int offset-idx)
                [gas' mem'] (expansion-charge m0 offset 32)
                [mem'' w] (if (nil? gas')
                            nil
                            (mem-load mem' offset 32))
                w' (bytes->word w)]
            (if (nil? gas')
              (invalid m "out of gas (memory expansion)")
              (let [stack' (push-word (:stack m0) w')]
                (if (= :overflow stack')
                  (invalid m "stack overflow")
                  (assoc m0 :gas gas' :memory mem'' :stack stack' :pc (inc (:pc m0)))))))
          (catch #?(:clj Exception :cljs js/Error) e
            (invalid m (or (ex-message e) "mload operand out of range"))))))))

(defn- apply-op
  "Execute one opcode on a machine whose pc points at it. Returns the
  next machine (:status :running or terminal)."
  [m op]
  (case op
    0x00 (halt m :stopped [])
    ;; arithmetic
    0x01 (safe-binop m u256/add)
    0x02 (safe-binop m u256/mul)
    0x03 (safe-binop m u256/sub)
    0x04 (safe-binop m u-div-nz)
    0x05 (safe-binop m u-sdiv)
    0x06 (safe-binop m u-mod-nz)
    0x07 (safe-binop m u-smod)
    0x08 (safe-ternop m u-addmod)
    0x09 (safe-ternop m u-mulmod)
    0x0a (safe-binop m u-exp)
    0x0b (safe-binop m u256/signextend)
    ;; comparisons
    0x10 (safe-binop m u-lt-w)
    0x11 (safe-binop m u-gt-w)
    0x12 (safe-binop m u-slt)
    0x13 (safe-binop m u-sgt)
    0x14 (safe-binop m u-eq-w)
    0x15 (safe-unop m u-iszero)
    ;; bitwise
    0x16 (safe-binop m u-and)
    0x17 (safe-binop m u-or)
    0x18 (safe-binop m u-xor)
    0x19 (safe-unop m u-not)
    0x1a (safe-binop m u-byte)
    0x1b (safe-binop m u-shl)
    0x1c (safe-binop m u-shr)
    0x1d (safe-binop m u-sar)
    0x20 (step-keccak m)
    ;; flow / stack
    0x50 (if (underflow? (:stack m) 1)
           (invalid m "stack underflow")
           (assoc m :stack (pop (:stack m))))
    0x51 (step-mload m)
    0x52 (step-mstore m 32)
    0x53 (step-mstore m 1)
    0x30 (let [e (get m :env env/default-env)] (step-env-const m (:address e)))
    0x31 (step-balance m)
    0x32 (let [e (get m :env env/default-env)] (step-env-const m (:origin e)))
    0x33 (let [e (get m :env env/default-env)] (step-env-const m (:caller e)))
    0x34 (let [e (get m :env env/default-env)] (step-env-const m (:callvalue e)))
    0x3a (let [e (get m :env env/default-env)] (step-env-const m (:gasprice e)))
    0x3d (step-returndatasize m)
    0x40 (step-blockhash m)
    0x41 (let [e (get m :env env/default-env)] (step-env-const m (block-word e :coinbase)))
    0x42 (let [e (get m :env env/default-env)] (step-env-const m (block-word e :timestamp)))
    0x43 (let [e (get m :env env/default-env)] (step-env-const m (block-word e :number)))
    0x44 (let [e (get m :env env/default-env)] (step-env-const m (block-word e :difficulty)))
    0x45 (let [e (get m :env env/default-env)] (step-env-const m (block-word e :gaslimit)))
    0x46 (let [e (get m :env env/default-env)] (step-env-const m (block-word e :chainid)))
    0x48 (let [e (get m :env env/default-env)] (step-env-const m (block-word e :basefee)))
    0x54 (step-sload m)
    0x55 (step-sstore m)
    0x56 (let [r (take-1 m)]
           (if (= :underflow r)
             (invalid m "stack underflow")
             (let [[stack dest] r]
               (step-jump (assoc m :stack stack) dest))))
    0x57 (let [r (take-2 m)]
           (if (= :underflow r)
             (invalid m "stack underflow")
             (let [[stack cond dest] r]
               (if (u256/eq cond zero-word)
                 (assoc m :stack stack :pc (inc (:pc m)))
                 (step-jump (assoc m :stack stack) dest)))))
    0x58 (let [stack' (push-word (:stack m) (u256/from-long (:pc m)))]
           (if (= :overflow stack')
             (invalid m "stack overflow")
             (assoc m :stack stack')))
    0x5b (assoc m :pc (inc (:pc m)))
    0x5f (step-push m 0x5f)
    0xf3 (step-return-revert m :halted)
    0xfd (step-return-revert m :reverted)
    0xfe (invalid m "INVALID opcode")
    (cond
      (and (>= op 0x60) (<= op 0x7f)) (step-push m op)
      (and (>= op 0x80) (<= op 0x8f)) (step-dup m op)
      (and (>= op 0x90) (<= op 0x9f)) (step-swap m op)
      :else (invalid m "invalid opcode"))))

(defn- next-pc
  "pc after an op, given pc0 (the pc of the opcode just executed).
  PUSH1..32 handlers already advanced :pc past their immediate — keep
  their value; every other non-jump op advances by 1."
  [m op pc0]
  (if (and (>= op 0x60) (<= op 0x7f)
           (not= (:pc m) pc0))
    (:pc m)
    (inc pc0)))

(defn step
  "One instruction. Returns the machine with :status :running or a
  terminal status. Static gas is charged first; INVALID consumes all."
  [m]
  (let [pc (:pc m)
        code (:code m)]
    (cond
      (>= (:steps m) max-steps) (invalid m "step limit")
      (or (neg? pc) (>= pc (count code))) (halt m :stopped [])
      :else
      (let [op (nth code pc)
            sg (static-gas op)]
        (if (= :invalid sg)
          (invalid m (str "invalid opcode 0x" (format-hex-byte op)))
          (let [gas (if (= op 0xfe) 0 (charge (:gas m) sg))]
            (if (= :out-of-gas gas)
              (invalid m "out of gas")
              (let [m' (apply-op (assoc m :gas gas :steps (inc (:steps m))) op)]
                (if (= :running (:status m'))
                  (assoc m' :pc (next-pc m' op pc))
                  m')))))))))

(defn make-machine
  "Fresh machine over code with optional gas, calldata, storage, and env."
  ([code] (make-machine code 1000000 []))
  ([code gas] (make-machine code gas []))
  ([code gas calldata]
   (make-machine code gas calldata {} nil))
  ([code gas calldata storage env]
   {:code (vec code)
    :stack []
    :memory []
    :pc 0
    :gas (int gas)
    :steps 0
    :calldata (vec calldata)
    :returndata []
    :storage (or storage storage/empty-store)
    :env (or env env/default-env)
    :status :running
    :output []}))

(defn run
  "Step until a terminal status (bounded by max-steps)."
  ([m] (run m max-steps))
  ([m limit]
   (loop [m m n 0]
     (if (= :running (:status m))
       (if (>= n limit)
         (invalid m "step limit")
         (recur (step m) (inc n)))
       m))))
