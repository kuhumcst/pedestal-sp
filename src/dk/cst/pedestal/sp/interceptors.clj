(ns dk.cst.pedestal.sp.interceptors
  "Standard interceptors for the SAML login flow + a few helper interceptors.

  In addition, this namespace also contains interceptors used to create custom
  SAML-authorized routes. A SAML-authorized route is constructed by appending to
  the output of the `chain` function.

  By default, the SAML RelayState is assumed to be a redirect URL which has been
  encoded using the 'safe-encode' function in 'dk.cst.pedestal.sp.auth'.

  Route-level authorisation checks can be made using the `permit-request?` fn
  from within an interceptor. For inline condition definitions and checks
  (available in both Clojure/ClojureScript) refer to `dk.cst.pedestal.sp.auth`."
  (:require [clojure.pprint :refer [pprint]]
            [clojure.walk :as walk]
            [io.pedestal.interceptor :as ic]
            [io.pedestal.interceptor.chain :as chain]
            [io.pedestal.interceptor.error :as error]
            [io.pedestal.http.route :as route]
            [io.pedestal.http.ring-middlewares :as middlewares]
            [ring.util.codec :as codec]
            [hiccup.core :as hiccup]
            [time-literals.read-write :as tl]
            [saml20-clj.core :as saml]
            [saml20-clj.coerce :as coerce]
            [saml20-clj.encode-decode :as saml-decode]
            [dk.cst.pedestal.sp.static :refer [css-centred css-spaced]]
            [dk.cst.pedestal.sp.auth :as sp.auth]))

;; Make sure that echo-assertions prints timestamps in a nice way
(tl/print-time-literals-clj!)

;; The ring session wrapper grandfathers in the :cookies key in the request map.
(defn request->consent-state
  [request]
  (when-let [consent (get-in request [:cookies "consent" :value])]
    (->> (codec/form-decode consent)
         (map (fn [[k v]] [(keyword k) v]))
         (into {}))))

(defn authenticated?
  "Has the user making this `request` authenticated via SAML?"
  [request]
  (boolean (sp.auth/request->assertions request)))

(defn echo-response-ic
  "Handler echoing full SAML response (including assertions) in session store."
  [req]
  {:status  200
   :headers {"Content-Type" "text/xml"}
   :body    (get-in req [:session :saml :response])})

(defn echo-request-ic
  "Handler echoing full SAML request in session store."
  [req]
  (if-let [saml-request (get-in req [:session :saml :request])]
    {:status  200
     :headers {"Content-Type" "text/xml"}
     :body    saml-request}
    {:status  404
     :headers {}}))

(defn echo-assertions-ic
  "Handler echoing SAML response assertions in session store."
  [req]
  {:status  200
   :headers {"Content-Type"        "application/edn"
             "Content-Disposition" "filename=\"assertions.edn\""}
   :body    (-> (get-in req [:session :saml :assertions])
                (pprint)
                (with-out-str))})

(defn echo-session-ic
  "Handler echoing all current SAML-related information in session store."
  [req]
  (if-let [saml-session (get-in req [:session :saml])]
    {:status  200
     :headers {"Content-Type"        "application/edn"
               "Content-Disposition" "filename=\"session.edn\""}
     :body    (with-out-str (pprint saml-session))}
    {:status  404
     :headers {}}))

(defn metadata-ic
  "SAML Metadata handler from an expanded `conf`. Returns the metadata as XML."
  [{:keys [app-name
           acs-url
           sp-cert]
    :as   conf}]
  (fn [_]
    {:status  200
     :headers {"Content-Type" "text/xml"}
     :body    (saml/metadata conf)}))

(defn request-ic
  "SAML request handler from an expanded `conf`. Redirects login to IdP.
  Custom RelayState taking the form of a URL can be provided as a query-param."
  [{:keys [app-name
           acs-url
           idp-url
           issuer
           credential
           state-manager
           relay-state]
    :as   conf}]
  (fn [{:keys [query-params] :as req}]
    (let [saml-request (saml/request (dissoc conf :relay-state))
          relay-state* (or (:RelayState query-params)
                           relay-state
                           "/")]
      ;; Note that the RelayState is URI-encoded inside 'idp-redirect-response'.
      (assoc (saml/idp-redirect-response saml-request idp-url relay-state*)
        :session {:saml {:request     (coerce/->xml-string saml-request)
                         :relay-state relay-state*}}))))

(defn- massage-assertions
  "Makes the saml20-clj `assertions` (a direct XML conversion) more palatable.
  The returned map can more easily be queried e.g. for authorisation purposes."
  [assertions]
  (->> (first assertions)
       (walk/postwalk (fn [x]
                        (cond
                          (seq? x) (set x)
                          :else x)))))

;; TODO: add error handler
;; TODO: validate response some more?
(defn response-ic
  "SAML response handler from an expanded `conf`. Accepts response from IdP.
  Will treat RelayState as a location, redirecting there after authentication."
  [{:keys [idp-cert
           sp-private-key
           validation
           paths]
    :as   conf}]
  (fn [{:keys [form-params session] :as request}]
    (let [{:keys [SAMLResponse RelayState]} form-params
          {:keys [saml-consent]} paths
          {:keys [pedestal-sp]} (request->consent-state request)
          response   (-> SAMLResponse
                         saml-decode/base64->str
                         (saml/validate idp-cert sp-private-key validation))
          xml        (saml/->xml-string response)
          assertions (-> (saml/assertions response)
                         (massage-assertions))]
      {:status  303
       :session (update session :saml merge {:assertions assertions
                                             :response   xml})
       :headers (if (and saml-consent (not= "on" pedestal-sp))
                  {"Location" (str saml-consent "?RelayState=" RelayState)}
                  {"Location" (sp.auth/safe-decode RelayState)})})))

(defn logout-ic
  "Delete current SAML-related session info related to the user, i.e. log out.

  This is an API endpoint by default, so it returns 204. That will not by itself
  refresh the browser page, but a 303 redirect can be triggered by providing
  a RelayState query parameter similar to how the SAML login response endpoint
  works."
  [{:keys [form-params] :as req}]
  (let [{:keys [RelayState]} form-params
        session (not-empty (update req :session dissoc :saml))]
    (if RelayState
      {:status  303
       :headers {"Location" (sp.auth/safe-decode RelayState)}
       :session session}
      {:status  204
       :headers {}
       :session session})))

(defn session-ic
  "Interceptor that adds Ring session data to a request."
  [{:keys [session] :as conf}]
  (middlewares/session session))

(defn override-ic
  "Interceptor that adds a `condition` override to the SAML assertions map."
  [condition]
  {:name  ::override
   :enter (fn [ctx]
            (assoc-in ctx [:request :session :saml :assertions :condition]
                      condition))})

(defn guard-ic
  "Interceptor that will throw exceptions based on the given `condition`.

  By also including the condition as metadata, other interceptors can look up
  conditions for different routes ahead of time (see: 'permit-request?' fn)."
  [condition]
  (let [authorized? (sp.auth/condition->auth-test condition)
        auth-meta   {::condition condition
                     ::auth-test authorized?}]
    (assert authorized? (str "Invalid condition: " condition))
    (with-meta
      (ic/interceptor
        {:name  ::guard
         :enter (fn [{:keys [request] :as ctx}]
                  (let [assertions  (sp.auth/request->assertions request)
                        authorized? (or (sp.auth/auth-override assertions)
                                        authorized?)]
                    (if (not (authorized? assertions))
                      (throw (ex-info "Failed auth" auth-meta))
                      ctx)))})
      auth-meta)))

(defn- ->no-authentication-handler
  "Create a response handler to use when user is not authenticated. By default,
  the user is provided with a hyperlink to the SAML endpoint defined in `conf`."
  [{:keys [paths] :as conf}]
  (fn [{:keys [uri] :as req}]
    {:status  403
     :headers {"Content-Type" "text/html"}
     :body    (hiccup/html
                [:html
                 [:head
                  [:meta {:charset "utf-8"}]
                  [:meta {:name    "viewport"
                          :content "width=device-width, initial-scale=1.0"}]]
                 [:body
                  [:h1 "Login required"]
                  [:p "You must "
                   [:a {:href (sp.auth/saml-path paths :saml-login uri)}
                    "log in"]
                   " before you can access this resource."]]])}))

(def ^:private no-authorization-response
  {:status  403
   :headers {"Content-Type" "text/html"}
   :body    (hiccup/html
              [:html
               [:head
                [:meta {:charset "utf-8"}]
                [:meta {:name    "viewport"
                        :content "width=device-width, initial-scale=1.0"}]]
               [:body
                [:h1 "Forbidden"]
                [:p "You do not have permission to access this resource."]]])})

(defn failure-ic
  "Error-handling interceptor creating responses for errors thrown by ::guard."
  [conf]
  (error/error-dispatch [{:keys [request] :as ctx} ex]
    [{:exception-type :clojure.lang.ExceptionInfo}]
    (if (::condition (ex-data ex))
      (if (authenticated? request)
        (assoc ctx :response no-authorization-response)
        (assoc ctx :response ((->no-authentication-handler conf) request)))
      (assoc ctx ::chain/error ex))

    :else (assoc ctx ::chain/error ex)))

(defn consent-form
  "Build a form for use with the 'consent-ic' based on a `consent-url`,
  a `consent` map and a `RelayState`."
  [consent-url
   {:keys [agreed
           pedestal-sp
           summary
           checkboxes]
    :as   consent}
   RelayState]
  (hiccup/html
    [:html
     [:head
      [:meta {:charset "utf-8"}]
      [:meta {:name    "viewport"
              :content "width=device-width, initial-scale=1.0"}]]
     [:body {:style (str css-centred "height: 100vh;")}
      [:form {:action consent-url
              :method "get"}
       [:fieldset {:style "min-width: 200px; max-width: 400px"}
        [:legend
         [:strong "Consent"]]
        (cond
          (not-empty checkboxes)
          [:details {:open (not agreed)}
           [:summary summary]
           [:ul
            (for [{:keys [name label checked]} checkboxes]
              [:li
               [:label {:style (str css-spaced)}
                label
                [:input {:type    "checkbox"
                         :name    name
                         :checked (boolean checked)}]]])]]

          summary
          [:p summary])

        ;; Session cookie expiration is a special case.
        (when (or summary (not-empty checkboxes))
          [:hr])
        [:label {:style css-spaced}
         "Stay signed in?"
         [:input {:type    "checkbox"
                  :name    "pedestal-sp"
                  :checked (boolean pedestal-sp)}]]
        [:input {:type  "hidden"
                 :name  "agreed"
                 :value "on"}]
        (when RelayState
          [:input {:type  "hidden"
                   :name  "RelayState"
                   :value RelayState}])
        [:p {:style "text-align: right;"}
         [:input {:type  "submit"
                  :value (if agreed
                           "Update"
                           "Confirm")}]]]]]]))

(defn- merge-params
  "Merge `params` into the checkboxes of a `consent` description."
  [consent {:keys [agreed pedestal-sp] :as params}]
  (let [params* (dissoc params :agreed :pedestal-sp :RelayState)
        check   (fn [{:keys [name] :as checkbox}]
                  (assoc checkbox :checked (boolean (get params* name false))))]
    (-> consent
        (assoc :agreed agreed)
        (assoc :pedestal-sp pedestal-sp)
        (update :checkboxes (partial mapv check)))))

(defn consent-ic
  "Interceptor used to request consent from authenticated users based on `conf`.
  Only handles session expiration by default, but can be used for e.g. GDPR.

  The interceptor has 3 states:
    - The user is shown the 'initial' view as part of the authentication flow.
    - The user agrees/disagrees to the specified policies by submitting the
      form which will set up required cookies and 'redirect' to the RelayState.
    - Subsequent visits to the consent url will all be the 'edit' view which
      sources the consent from the consent cookie state."
  [{:keys [consent paths] :as conf}]
  (fn [{:keys [query-params headers cookies] :as request}]
    (let [{:keys [RelayState pedestal-sp]} query-params
          {:keys [saml-consent]} paths
          {:strs [referer]} headers
          consent-state (request->consent-state request)
          consent*      (if consent-state
                          (merge-params consent consent-state)
                          (assoc consent :pedestal-sp "on"))
          cookie-attrs  (get-in conf [:session :cookie-attrs])
          query-params* (dissoc query-params :RelayState)]
      (cond
        ;; Initial state
        (and (empty? query-params*) RelayState)
        {:status  200
         :headers {"Content-Type" "text/html"}
         :body    (consent-form saml-consent consent* RelayState)}

        ;; Redirect state
        RelayState
        {:status  302
         :cookies (merge
                    {"consent" (assoc cookie-attrs
                                 :value query-params*)}

                    ;; Controls the client-side expiration of session cookies;
                    ;; server-side expiration is a property of the session store
                    ;; defined in the Pedestal SP config map.
                    (-> (select-keys cookies ["pedestal-sp"])
                        (update "pedestal-sp"
                                merge (if (= pedestal-sp "on")
                                        cookie-attrs
                                        (assoc (dissoc cookie-attrs :max-age)
                                          :expires "")))))
         :headers {"Location" (sp.auth/safe-decode RelayState)}}

        ;; Edit state
        :else
        {:status  200
         :headers {"Content-Type" "text/html"}
         :body    (consent-form saml-consent consent* referer)}))))

(defn- get-ic*
  [interceptors ic-name]
  (loop [[ic & remaining] interceptors]
    (cond
      (= (:name ic) ic-name) ic
      remaining (recur remaining))))

(def ^:private get-ic
  (memoize get-ic*))

(defn routing-for
  "Resolve routing for `query-string` and `verb` using the router in the `ctx`.
  This is a modified version of `io.pedestal.http.route/try-routing-for`."
  [ctx query-string verb]
  (let [router-ic (get-ic (::chain/stack ctx) ::route/router)
        context   ((:enter router-ic) {:request {:path-info      query-string
                                                 :request-method verb}})]
    (:route context)))

(defn url-for
  "Call *url-for* in `ctx` with `args`."
  [{:keys [bindings] :as ctx} & args]
  (let [*url-for* @(get bindings #'io.pedestal.http.route/*url-for*)]
    (apply *url-for* args)))

(defn routing->auth-test
  "Given a `routing` map for a single route, return the auth test attached as
  metadata to the ::session-guard interceptor.

  Note: routing maps are returned by `routing-for`."
  [{:keys [interceptors] :as routing}]
  (or (::auth-test (meta (get-ic interceptors ::guard)))
      (constantly true)))

(defn permit-request?
  "Is a `route` or `query-string` allowed within the current interceptor `ctx`?
  Checks conditions set by interceptor chain constructed with the chain fn.

  Note that unresolved routes will result in a truthy response, but the return
  value will be :not-found in that case!"
  ([{:keys [request] :as ctx} query-string verb]
   (if-let [routing (routing-for ctx query-string verb)]
     (let [assertions  (sp.auth/request->assertions request)
           authorized? (or (sp.auth/auth-override assertions)
                           (routing->auth-test routing))]
       (authorized? assertions))
     :not-found))
  ([ctx route]
   (let [query-string (if (keyword? route)
                        (url-for ctx route)
                        route)]
     (permit-request? ctx query-string :get))))

;; TODO: duplicate cookies from session-ic?
;; It seems that the presence of the 'session-ic' results in duplicate cookies
;; being issued for certain paths. However, these cookies seem to be entirely
;; temporary session cookies, so they may not matter much in practice.
(defn auth-chain
  "Create an interceptor chain to make sure that a user is authorized to access
  a resource based on the expanded `conf` and a `condition`.

  Even if a route is not restricted, it might make sense to prepend it with an
  'auth-chain' anyway, as this will (by default) reset the TTL of the session
  whenever a user accesses the route in question. Use :all as the `condition`
  to allow universal access to a route.

  During development, the required authorisation can be modified by setting
  the :auth-override key of the conf to a different condition, e.g. :all."
  [{:keys [auth-override] :as conf} condition]
  (if auth-override
    [(failure-ic conf)
     (session-ic conf)
     (override-ic auth-override)
     (guard-ic condition)]

    [(failure-ic conf)
     (session-ic conf)
     (guard-ic condition)]))
