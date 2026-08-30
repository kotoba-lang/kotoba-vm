(ns kotoba.vm-profile-test
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.test :refer [deftest is testing]]))

(def profile
  (-> "kototama-profile.edn" io/file slurp edn/read-string))

(deftest declaration-targets-versioned-kototama
  (is (= :kototama.vm/implementation-profile-v1 (:schema profile)))
  (is (= {:schema :kototama.vm/spec-v1
          :version 1
          :repository "https://github.com/kotoba-lang/kototama"}
         (:spec profile)))
  (is (= :kotoba-vm (get-in profile [:implementation :name]))))

(deftest current-evidence-is-described-without-false-compatibility-claims
  (is (= :partial (get-in profile [:profiles :core/v1 :status])))
  (is (seq (get-in profile [:profiles :core/v1 :omissions])))
  (is (= :shape-only
         (get-in profile [:profiles :fvm-actor/v1 :status])))
  (is (empty? (get-in profile [:profiles :fvm-actor/v1 :levels])))
  (is (= :not-implemented
         (get-in profile [:profiles :evm/v1 :status])))
  (is (= :not-implemented
         (get-in profile [:profiles :fevm/v1 :status])))
  (is (= #{:filecoin-network-compatibility
           :evm-compatibility
           :fevm-compatibility
           :consensus}
         (set (:non-claims profile)))))

(deftest every-incomplete-profile-names-its-omissions
  (doseq [[profile-name declaration] (:profiles profile)]
    (testing (name profile-name)
      (is (seq (:omissions declaration))))))
