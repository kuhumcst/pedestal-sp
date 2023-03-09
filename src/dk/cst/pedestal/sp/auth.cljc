(ns dk.cst.pedestal.sp.auth
  "Create inline authorisation logic using SAML assertions. The `if-permit` and
  `only-permit` macros can be used from both Clojure and ClojureScript.

  For route-level authorisation + ahead-of-time checks from within interceptors,
  use the `permit-request?` function from `dk.cst.pedestal.sp.interceptors`."
  (:require [clojure.data :as data]
            #?(:clj [ring.util.codec :as codec])
            [clojure.string :as str])
  #?(:cljs (:require-macros [dk.cst.pedestal.sp.auth])))

(defn- safe-base64
  "Replace certain characters in base64 with ones that won't be URL-encoded."
  [s]
  (str/replace s #"/|\+|=" {"/" "_", "+" "-", "=" "."}))

(defn- unsafe-base64
  "Undo the transformation of 'safe-base64'."
  [s]
  (str/replace s #"_|-|\." {"_" "/", "-" "+", "." "="}))

(defn safe-encode
  "Encode a `url` as base64 with certain problematic characters replaced.

  This encoding should survive any URL encoding/decoding scheme it may be passed
  through, ensuring that the input `url` survives until decoded."
  [url]
  (safe-base64 #?(:clj  (codec/base64-encode (.getBytes (codec/url-encode url)))
                  :cljs (js/btoa (js/encodeURIComponent url)))))

(defn safe-decode
  "Decode a URL encoded as `base64` via 'safe-encode'."
  [base64]
  #?(:clj  (-> base64 unsafe-base64 codec/base64-decode slurp codec/url-decode)
     :cljs (-> base64 unsafe-base64 js/atob js/decodeURIComponent)))

;; TODO: misplaced...? put in another CLJC file?
(defn saml-path
  "Get the specified `saml-type` in `paths` with an encoded `RelayState`."
  [paths saml-type & [RelayState]]
  (str (get paths saml-type) (when RelayState
                               (str "?RelayState=" (safe-encode RelayState)))))

(defn submap?
  "Is `m` a submap of `parent`?"
  [m parent]
  (nil? (first (data/diff m parent))))

(defn request->assertions
  [request]
  (get-in request [:session :saml :assertions]))

(defn condition->auth-test
  "Return a function to test an assertions map based on a given `condition`:

    :authenticated - requires authentication to access.
              :all - can be accessed by anyone, no restrictions apply.
             :none - no access by anyone under any circumstances.
               map - allow access when the assertions contain this submap.
                fn - takes assertions as input and returns true if accessible."
  [condition]
  (cond
    (keyword? condition) (case condition
                           :authenticated some?
                           :all (constantly true)
                           :none (constantly false))
    (map? condition) #(submap? condition %)
    (fn? condition) condition))

(defn auth-override
  "Create an auth test override from the `assertions` map.

  During development, the assertions map may contain a :condition key defining
  an alternative test used to override the conditions of a production system."
  [assertions]
  (condition->auth-test (:condition assertions)))

(defmacro if-permit
  "Checks that `assertions` satisfies `condition`. When true, returns the
  first clause of `body`; else returns the second clause."
  [[assertions condition] & body]
  `(if ((or (auth-override ~assertions)
            (condition->auth-test ~condition)) ~assertions)
     ~@body))

(defmacro only-permit
  "Checks that `assertions` satisfies `condition`. If true, returns `body`;
  else throws an exception."
  [[assertions condition] & body]
  `(if ((or (auth-override ~assertions)
            (condition->auth-test ~condition)) ~assertions)
     (do ~@body)
     (throw (ex-info "Unsatisfied condition" {::condition ~condition}))))

#?(:clj
   (defn enforce-condition
     "Fail fast if the `request` assertions do not meet a `condition`."
     [request condition]
     (only-permit [(request->assertions request) condition])))

(comment
  (let [url "https://glossematics.dk/app/search?limit=10&offset=0&correspondent=%23np56%2C%23np145"]
    (= url (safe-decode (safe-encode url))))
  #_.)