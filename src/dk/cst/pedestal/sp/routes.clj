(ns dk.cst.pedestal.sp.routes
  "Create a fully-functional set of SAML-conscious routes based on a config map.

  The routes comprise interceptors from `dk.cst.pedestal.sp.interceptors`."
  (:require [io.pedestal.http.body-params :refer [body-params]]
            [dk.cst.pedestal.sp.interceptors :as sp.ic]))

;; TODO: add function for creating a minimal routes set
(defn all
  "Create SAML routes in table syntax based on a `conf` map."
  [{:keys [paths] :as conf}]
  (let [{:keys [saml-meta
                saml-login
                saml-logout
                saml-consent
                saml-session
                saml-request
                saml-response
                saml-assertions]} paths
        body-params   (body-params)
        all           (sp.ic/auth-chain conf :all)
        authenticated (sp.ic/auth-chain conf :authenticated)]
    #{;; Standard endpoints required for an sp-initiated SAML login flow
      [saml-meta :get (sp.ic/metadata-ic conf) :route-name ::saml-meta]
      [saml-login :get (conj all (sp.ic/request-ic conf)) :route-name ::saml-req]
      [saml-login :post (conj all body-params (sp.ic/response-ic conf)) :route-name ::saml-resp]

      ;; Logout endpoint, similar to - but not part of - the standard endpoints
      [saml-logout :post (conj all body-params `sp.ic/logout-ic)]

      ;; TODO: split into :get and :post?
      ;; A generic consent interceptor is also included in the package.
      [saml-consent :get (conj authenticated (sp.ic/consent-ic conf)) :route-name ::saml-consent]

      ;; User-centric metadata endpoints, not related to the SAML login flow
      [saml-session :get (conj all `sp.ic/echo-session-ic)]
      [saml-request :get (conj authenticated `sp.ic/echo-request-ic)]
      [saml-response :get (conj authenticated `sp.ic/echo-response-ic)]
      [saml-assertions :get (conj authenticated `sp.ic/echo-assertions-ic)]}))
