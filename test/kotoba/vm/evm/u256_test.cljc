(ns kotoba.vm.evm.u256-test
  (:require [clojure.test :refer [deftest is]]
            [kotoba.vm.evm.u256 :as u]))

(deftest identity-values
  (is (= (u/zero) (u/from-long 0)))
  (is (= (u/one) (u/from-long 1)))
  (is (u/eq (u/max-value)
            (u/from-hex-string "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")))
  (is (u/gt (u/max-value) (u/one))))

(deftest basic-arith
  (is (u/eq (u/add (u/one) (u/one)) (u/from-long 2)))
  (is (u/eq (u/sub (u/from-long 3) (u/one)) (u/from-long 2)))
  (is (u/eq (u/mul (u/from-long 6) (u/from-long 7)) (u/from-long 42)))
  (is (u/eq (u/div (u/from-long 7) (u/from-long 2)) (u/from-long 3)))
  (is (u/eq (u/mod-val (u/from-long 7) (u/from-long 3)) (u/from-long 1)))
  ;; division / modulo by zero is 0 per EVM
  (is (u/eq (u/div (u/one) (u/zero)) (u/zero)))
  (is (u/eq (u/mod-val (u/one) (u/zero)) (u/zero))))

(deftest overflow-wraps
  ;; max + 1 wraps to 0
  (is (u/eq (u/add (u/max-value) (u/one)) (u/zero)))
  ;; 0 - 1 wraps to max
  (is (u/eq (u/sub (u/zero) (u/one)) (u/max-value)))
  ;; 2^128 * 2^128 wraps: low 256 bits of 2^256 = 0
  (is (u/eq (u/mul (u/from-hex-string "0x100000000000000000000000000000000")
                   (u/from-hex-string "0x100000000000000000000000000000000"))
            (u/zero)))
  ;; (2^128) * (2^128 + 1) = 2^256 + 2^128 -> wraps to 2^128
  (is (u/eq (u/mul (u/from-hex-string "0x100000000000000000000000000000000")
                   (u/add (u/from-hex-string "0x100000000000000000000000000000000") (u/one)))
            (u/from-hex-string "0x100000000000000000000000000000000"))))

(deftest big-values-round-trip
  ;; 2^53-precision-breaking values must go through strings
  (let [v (u/from-hex-string "0x123456789abcdef0123456789abcdef0123456789abcdef")]
    (is (u/gt v (u/from-long 1000000000000000000000000)))
    (is (u/eq v (u/from-string-decimal
                  (u/to-string v))))
    (is (= "0x123456789abcdef0123456789abcdef0123456789abcdef"
           (u/to-hex-string v))))
  (is (u/gt (u/from-hex-string "0x0123456789abcdef0123456789abcdef0123456789abcdef")
            (u/from-hex-string "0x0123456789abcdef0123456789abcdef0123456789abcde0")))
  (is (u/lt (u/from-hex-string "0x0123456789abcdef0123456789abcdef0123456789abcde0")
            (u/from-hex-string "0x0123456789abcdef0123456789abcdef0123456789abcdef")))
  (is (u/eq (u/from-hex-string "0x0123456789abcdef0123456789abcdef0123456789abcdef")
            (u/from-hex-string "0x0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")))
  (is (= (u/to-hex-string (u/from-hex-string "0x0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"))
         "0x123456789abcdef0123456789abcdef0123456789abcdef")))

(deftest parse-errors
  (is (nil? (u/from-hex-string "0xzz")))
  (is (nil? (u/from-hex-string "not hex")))
  (is (nil? (u/from-string-decimal "-1")))
  (is (nil? (u/from-string-decimal "12a")))
  (is (u/eq (u/from-string-decimal "42") (u/from-long 42)))
  (is (u/eq (u/from-hex-string "2a") (u/from-long 42))))

(deftest signextend
  ;; canonical EVM examples
  ;; signextend 0, 0xff -> all ones
  (is (u/eq (u/signextend (u/zero) (u/from-hex-string "0xff")) (u/max-value)))
  ;; signextend 0, 0x7f -> 0x7f
  (is (u/eq (u/signextend (u/zero) (u/from-hex-string "0x7f")) (u/from-hex-string "0x7f")))
  ;; signextend 1, 0xff11 -> 0xff..ff11 (max - 238)
  (is (u/eq (u/signextend (u/one) (u/from-hex-string "0xff11"))
            (u/from-hex-string (str "0x" (apply str (repeat 30 "ff")) "ff11"))))
  ;; signextend 1, 0x7f11 -> 0x7f11
  (is (u/eq (u/signextend (u/one) (u/from-hex-string "0x7f11")) (u/from-hex-string "0x7f11")))
  ;; b >= 31 -> x unchanged
  (let [x (u/from-hex-string "0x123456789abcdef0123456789abcdef0123456789abcdef")]
    (is (u/eq (u/signextend (u/from-long 31) x) x))
    (is (u/eq (u/signextend (u/from-long 32) x) x))))

(deftest signextend-two-complement
  ;; 0xffff (sign bit of byte 1 set) extended from byte 0 -> 0xffffffffffffffff
  (is (u/eq (u/signextend (u/one) (u/from-hex-string "0xffff"))
            (u/max-value)))
  ;; 0x80 (sign bit of byte 0 set) -> 0xff..ff80 (max - 127)
  (is (u/eq (u/signextend (u/zero) (u/from-hex-string "0x80"))
            (u/from-hex-string (str "0x" (apply str (repeat 31 "ff")) "80"))))
  ;; 0x7fff sign bit of byte 1 clear -> 0x7fff
  (is (u/eq (u/signextend (u/one) (u/from-hex-string "0x7fff"))
            (u/from-hex-string "0x7fff"))))
