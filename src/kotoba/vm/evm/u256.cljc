(ns kotoba.vm.evm.u256)

;; 256-bit unsigned integer arithmetic (EVM w 3 semantics) on a single
;; BigInt. :clj -> clojure.lang.BigInt, :cljs -> native BigInt. Same
;; public API and same test vectors on both runtimes.
;;
;; Note: `bigint` and `+'`/`-'`/`*'` are not resolvable from kondo in
;; .cljc files, and all operands are normalized to BigInt before use,
;; so plain `+`/`-`/`*` are exact here.

(defn- pow2
  "2^n as a BigInt, exact for n up to 256."
  [n]
  #?(:clj (clojure.lang.BigInt/fromBigInteger (.pow (java.math.BigInteger. "2") n))
     :cljs (bit-shift-left (js/BigInt 1) n)))

(def ^:private pow2-256 (pow2 256))

(defn- ->big
  "Normalize any integer (Long / BigInt / JS number) to the runtime BigInt."
  [x]
  #?(:clj (cond
            (instance? clojure.lang.BigInt x) x
            (instance? java.math.BigInteger x) (clojure.lang.BigInt/fromBigInteger x)
            :else (clojure.lang.BigInt/fromLong x))
     :cljs (if (instance? js/BigInt x) x (js/BigInt x))))

(defn from-long [x] (->big x))

(defn zero [] (->big 0))

(defn one [] (->big 1))

(defn max-value [] (dec pow2-256))

(defn add [a b] (mod (+ (->big a) (->big b)) pow2-256))
(defn sub [a b] (mod (- (->big a) (->big b)) pow2-256))
(defn mul [a b] (mod (* (->big a) (->big b)) pow2-256))

(defn div
  "EVM UDIV: division by zero is 0, quotient truncates."
  [a b]
  (let [x (->big a) y (->big b)]
    (if (zero? y) (->big 0) (quot x y))))

(defn mod-val
  "EVM UMOD: modulo by zero is 0."
  [a b]
  (let [x (->big a) y (->big b)]
    (if (zero? y) (->big 0) (rem x y))))

(defn lt [a b] (< (->big a) (->big b)))
(defn gt [a b] (> (->big a) (->big b)))
(defn eq [a b] (= (->big a) (->big b)))

(defn signextend
  "EVM SIGNEXTEND(b, x): extend the sign byte of x from byte index b."
  [b x]
  (let [bi (->big b) xi (->big x)]
    (if (>= bi 32)
      xi
      (let [m (pow2 (+ (* bi 8) 8))
            sign-byte (rem (quot xi (pow2 (* bi 8))) (->big 256))]
        ;; bits 8b+8 .. 255 set to the sign bit
        (if (>= sign-byte 128)
          (mod (+ xi (- pow2-256 m)) pow2-256)
          (rem xi m))))))

(defn from-hex-string
  "Parse a 0x-prefixed or bare hex string. Returns nil when invalid.
  Values >= 2^256 are reduced mod 2^256."
  [s]
  (if (re-matches #"(0x)?[0-9a-fA-F]+" s)
    (let [t (if (and (>= (count s) 2) (= "0x" (subs s 0 2))) (subs s 2) s)]
      (mod #?(:clj (clojure.lang.BigInt/fromBigInteger (java.math.BigInteger. t 16))
              :cljs (js/BigInt (str "0x" t)))
           pow2-256))
    nil))

(defn from-string-decimal
  "Parse a base-10 string. Returns nil when invalid."
  [s]
  (if (re-matches #"[0-9]+" s)
    (mod #?(:clj (clojure.lang.BigInt/fromBigInteger (java.math.BigInteger. s))
            :cljs (js/BigInt s))
         pow2-256)
    nil))

(defn to-string
  "Base-10 decimal string."
  [x] (str (->big x)))

(defn to-hex-string
  "0x-prefixed lowercase hex string (no leading zeros)."
  [x]
  (let [b (->big x)]
    (str "0x"
         #?(:clj (.toString ^java.math.BigInteger (biginteger b) 16)
            :cljs (.toString b 16)))))
