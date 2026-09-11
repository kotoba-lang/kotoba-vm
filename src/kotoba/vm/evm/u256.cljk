(ns kotoba.vm.evm.u256
  "EVM 256-bit unsigned integers on a single BigInt backbone.

  One internal representation for both runtimes: an arbitrary-precision
  integer kept normalized into [0, 2^256). :clj rides java.math.BigInteger
  (raw, NOT clojure.lang.BigInt — clojure.core's bit-ops refuse BigInt and
  that refusal cost this slice a full debug cycle); :cljs rides JS BigInt,
  masked back into range with BigInt.asUintN — the same two's-complement
  trick kotoba.vm.keccak uses at 64 bits, widened to 256.

  Because both runtimes speak arbitrary precision, the same test vectors
  (values well past 2^53, built from hex strings — never JS numbers) pass
  unchanged.

  Ops cover the EVM arithmetic/comparison face the core dispatcher needs:
  add sub mul div mod lt gt eq signextend. Division by zero throws, which
  the EVM models as an exceptional halt."
  (:refer-clojure :exclude [mod]))

(def ^:private two-pow-256
  #?(:clj (java.math.BigInteger.
           "115792089237316195423570985008687907853269984665640564039457584007913129639936")
     :cljs (js/BigInt
            "115792089237316195423570985008687907853269984665640564039457584007913129639936")))

(def ^:private mask-256 #?(:clj (.subtract ^java.math.BigInteger two-pow-256 java.math.BigInteger/ONE)
                       :cljs (js/BigInt.asUintN 256 (js/BigInt -1))))

(defn- ->bi
  "Coerce any integer shape to the runtime's raw bigint (BigInteger on
  :clj — never clojure.lang.BigInt — BigInt on :cljs)."
  [x]
  #?(:clj (cond
            (instance? java.math.BigInteger x) x
            (instance? clojure.lang.BigInt x) (.toBigInteger ^clojure.lang.BigInt x)
            :else (java.math.BigInteger. (str x)))
     :cljs (js/BigInt x)))

(defn- norm
  "Fold any integer (including a negative two's-complement reading) into
  the canonical unsigned [0, 2^256) range."
  [x]
  #?(:clj (.and ^java.math.BigInteger (->bi x) ^java.math.BigInteger mask-256)
     :cljs (js/BigInt.asUintN 256 (->bi x))))

(defn from-hex-string
  "Parse a 0x-prefixed (or bare) hex string into a u256. Values beyond
  2^53 must come through here on :cljs — JS numbers lose precision."
  ([s] (from-hex-string s true))
  ([s allow-prefix?]
   (let [s (if (and allow-prefix? (re-find #"^0[xX]" s)) (subs s 2) s)]
     (if (empty? s)
       (norm 0)
       (do (when-not (re-find #"^[0-9a-fA-F]+$" s)
             (throw (ex-info "not a hex u256" {:s s})))
           #?(:clj (norm (java.math.BigInteger. s 16))
              :cljs (norm (js/BigInt (str "0x" s)))))))))

(defn from-long
  "u256 from a (non-negative or negative — two's complement) runtime long."
  [n] (norm n))

(def zero-hex
  "Canonical 64-digit zero hex string."
  "0000000000000000000000000000000000000000000000000000000000000000")

(defn to-hex-string
  "Canonical 64-hex-digit little-case rendering (the EVM word shape)."
  [x]
  (let [x (norm x)]
    #?(:clj (format "%064x" x)
       :cljs (let [s (.toString x 16)]
               (str (apply str (repeat (- 64 (count s)) "0")) s)))))

(defn to-string
  "Decimal rendering (diagnostics, error messages)."
  [x]
  (.toString (norm x) 10))

(defn add
  "ADD: wraps modulo 2^256 (a + b over the top is silently truncated —
  that wraparound IS the specified behavior, not a bug)."
  [a b] (norm #?(:clj (.add ^java.math.BigInteger (->bi a) ^java.math.BigInteger (->bi b))
                 :cljs (+ (->bi a) (->bi b)))))

(defn sub
  "SUB: a - b mod 2^256, so 0 - 1 is the all-ones word."
  [a b] (norm #?(:clj (.subtract ^java.math.BigInteger (->bi a) ^java.math.BigInteger (->bi b))
                 :cljs (- (->bi a) (->bi b)))))

(defn mul
  "MUL: low 256 bits of a * b."
  [a b] (norm #?(:clj (.multiply ^java.math.BigInteger (->bi a) ^java.math.BigInteger (->bi b))
                 :cljs (* (->bi a) (->bi b)))))

(defn div
  "DIV: unsigned integer division. Division by zero throws — the EVM
  turns that into an exceptional halt one layer up."
  [a b]
  (let [a (norm a) b (norm b)]
    (when (zero? #?(:clj (.compareTo a java.math.BigInteger/ZERO) :cljs a))
      (throw (ex-info "u256 division by zero" {})))
    (when (zero? #?(:clj (.compareTo b java.math.BigInteger/ZERO) :cljs b))
      (throw (ex-info "u256 division by zero" {})))
    #?(:clj (.divide ^java.math.BigInteger a ^java.math.BigInteger b)
       :cljs (/ a b))))

(defn mod
  "MOD: unsigned remainder, 0 on a zero modulus (the EVM's MOD by zero
  is defined as 0, not an exception)."
  [a b]
  (let [a (norm a) b (norm b)]
    (if (zero? #?(:clj (.compareTo b java.math.BigInteger/ZERO) :cljs b))
      (norm 0)
      #?(:clj (.remainder ^java.math.BigInteger a ^java.math.BigInteger b)
         :cljs (js/BigInt.asUintN 256 (rem a b))))))

(defn lt [a b] (neg? (compare (norm a) (norm b))))
(defn gt [a b] (pos? (compare (norm a) (norm b))))
(defn eq [a b] (zero? (compare (norm a) (norm b))))

(defn signextend
  "SIGNEXTEND(b, x): sign-extend x from byte index b to a full word.
  b >= 31 (or negative, pre-checked by the dispatcher) is identity.
  All bit work goes through the raw bigint type (BigInteger methods on
  :clj, BigInt ops on :cljs) — clojure.core's bit-ops are not portable
  at this width."
  [b x]
  (let [b (norm b)
        x (norm x)
        i #?(:clj (.intValue ^java.math.BigInteger b) :cljs (js/Number b))]
    (if (>= i 32)
      x
      (let [bits (* 8 (inc i))
            one #?(:clj java.math.BigInteger/ONE :cljs (js/BigInt 1))
            shifted #?(:clj (.shiftLeft ^java.math.BigInteger one bits)
                       :cljs (js/BigInt.asUintN 256 (.shiftLeft one (js/BigInt bits))))
            se-mask (norm (dec #?(:clj shifted :cljs (js/BigInt shifted))))
            sign-bit (norm #?(:clj (.shiftLeft ^java.math.BigInteger one (+ 7 (* 8 i)))
                              :cljs (.shiftLeft one (js/BigInt (+ 7 (* 8 i))))))
            sign-bit-set? (not
                           (zero? #?(:clj (.compareTo (.and ^java.math.BigInteger x
                              ^java.math.BigInteger sign-bit)
                            java.math.BigInteger/ZERO)
                                     :cljs (js/BigInt.asUintN 256 (bit-and x sign-bit)))))]
        (if sign-bit-set?
          ;; sign bit on: every bit above the (i+1)-byte window becomes 1.
          (norm #?(:clj (.or ^java.math.BigInteger x
                             (.xor ^java.math.BigInteger mask-256 ^java.math.BigInteger se-mask))
                   :cljs (js/BigInt.asUintN 256 (bit-or x (bit-xor mask-256 se-mask)))))
          (norm #?(:clj (.and ^java.math.BigInteger x ^java.math.BigInteger se-mask)
                   :cljs (js/BigInt.asUintN 256 (bit-and x se-mask)))))))))
