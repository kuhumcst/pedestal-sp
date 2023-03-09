Pedestal SP
===========
[![pedestal-sp](https://img.shields.io/clojars/v/dk.cst/pedestal-sp.svg)](https://clojars.org/dk.cst/pedestal-sp)

Enhance your [Pedestal](https://github.com/pedestal/pedestal) web service with [SAML](https://en.wikipedia.org/wiki/Security_Assertion_Markup_Language) 2.0 routes to turn to it a valid [Service Provider](https://en.wikipedia.org/wiki/Service_provider_(SAML)) - or _SP_ for short.

* [Why use this?](#why-use-this)
* [Setup](#setup)
* [Authentication and authorisation](#authentication-and-authorisation)
* [SAML authentication endpoints](#saml-authentication-endpoints)
* [Other endpoints](#other-endpoints)

> _This project was made using [quephird/saml-test](https://github.com/quephird/saml-test) as a reference while applying the much more recent, actively developed fork of the [saml20-clj](https://github.com/metabase/saml20-clj) library by Metabase._

Why use this?
-------------
In academia - as well as in the corporate  world - SAML is a very popular way to implement [Single Sign-On](https://en.wikipedia.org/wiki/Single_sign-on) (SSO) for web services.<sup>[†](#saml-overview)</sup>

To log in to a web service, the so-called Service Provider (SP) must delegate user authentication to one or more Identity Providers (IdP). A common way to do this is by setting up [Shibboleth-sp](https://wiki.shibboleth.net/confluence/display/SP3/Home) as a separate web service and then integrating that with your own web service through a fairly involved setup involving XML files, using a Java web server as the middle-man.

Personally, I like keep things more tightly integrated and simpler to understand. You should consider using **Pedestal SP** if you need users to authenticate via a SAML IdP and think integrating with Shibboleth-sp sounds too complex.

> _<a name="saml-overview"><sup>†</sup></a> Take a look at [this video](https://www.youtube.com/watch?v=SvppXbpv-5k) to get a quick overview of how SAML works._

Who uses this?
--------------
We do! [Glossematics.dk](https://glossematics) depends on Pedestal SP to enable logging in through SAML.

Be aware...
-----------
To make this library work with an IdP you will most likely also need to make sure your content is served as HTTPS. You can use one of the servers supported by Pedestal for this, but personally I prefer using something like nginx or caddy to handle this aspect of modern web development.

Furthermore, this library depends on [/metabase/saml20-clj](https://github.com/metabase/saml20-clj) which wraps a more recent version of OpenSAML than is currently available on Maven Central. You will likely need to add the Shibboleth repository, e.g. using `deps.edn`:

```clojure
{...
 :mvn/repos {"opensaml" {:url "https://build.shibboleth.net/nexus/content/repositories/releases/"}}
 ...}
```

Setup
-----
**Pedestal SP** is divided into the following namespaces:

* `dk.cst.pedestal.sp.routes`: prepackaged SAML routes to add to your Pedestal web service.
* `dk.cst.pedestal.sp.conf`: config map creation + relevant Clojure Spec definitions.
* `dk.cst.pedestal.sp.auth`: functions for setting/checking authentication and authorisation.
* `dk.cst.pedestal.sp.interceptors`: interceptors for SAML authentication and observability.
* `dk.cst.pedestal.sp.example`: an example web service using **Pedestal SP**.

Like Pedestal itself, **Pedestal SP** is configured using a config map containing just a few required keys, mostly related to encryption. Before consumption, the base config is expanded using `sp.conf/init` and passed to the `sp.routes/all` function. The same config map should be reused when defining auth interceptor chains using `sp.ic/chain`.

Here's an example using a minimal config:

````clojure
(require '[dk.cst.pedestal.sp.routes :as sp.routes]
         '[dk.cst.pedestal.sp.conf :as sp.conf])

(def base-conf
  {:sp-url     "https://localhost:4433"
   :idp-url    "https://localhost:7000"
   :idp-cert   (slurp "/path/to/idp-public-cert.pem")
   :credential {:alias    "mylocalsp"
                :filename "/path/to/keystore.jks"
                :password (System/getenv "KEYSTORE_PASS")}})

(def conf
  (sp.conf/init base-conf))

;; This constructor function will provide a ready-made set of SAML routes.
;; You may also define the routes yourself too using the provided interceptors.
(def routes
  (sp.routes/all conf))
````

### Mock IdP
While developing your SAML SP, your probably want a mock IdP to develop up against. I followed the instructions at [quephird/saml-test](
https://github.com/quephird/saml-test#getting-things-running), specifically the parts related to getting the Node-based IdP running and creating a certificate for it. Once you have generated a certificate you can set the following keys in the config map:

```clojure
:idp-url  "https://localhost:7000"
:idp-cert (slurp "/path/to/idp-public-cert.pem")
```

Once you're ready to put your web service into production, it should simply be a matter of swapping the mock IdP for the real one<sup>[†](#idp-caveat)</sup>.

### Keystore
Java - and by extension Clojure - applications use a [Java KeyStore](https://en.wikipedia.org/wiki/Java_KeyStore) as the main way to store and access encryption keys. It is simply a file you create using the `keytool` CLI, with some associated Java methods providing access to the certificates within.

The KeyStore provides the credentials needed to properly sign your SAML requests. You give your web service access to the keystore by providing three required keys in the `:credential` submap of your config:

```clojure
:credential {:alias    "mylocalsp"
             :filename "/path/to/keystore.jks"
             :password (System/getenv "KEYSTORE_PASS")}
```

> _Note: make sure to add `-keyalg RSA` to the keytool command that use to create your keystore. This is expected by the underlying saml20-clj library._ 

### Your service
Now all that remains is defining the identity of your web service. While developing you will want to use a local URL, but obviously for a production system you will want to use the proper URL:

```clojure
:sp-url "http://localhost:8080"
```

Altogether, these 4 keys (`:idp-url`, `:idp-cert`, `:credential`, `:sp-url`) make up the required parts of the base config. The remaining keys are all optional.

> _<a name="idp-caveat"><sup>†</sup></a> Depending on what IdP you're integrating with, additional steps might need to be taken. That is beyond the scope of this little setup guide._

Authentication and authorisation
--------------------------------
SAML is meant to be a complete package for handling authentication and authorisation. **Pedestal SP** builds on this design with helpful functions in a simple to understand system based on Pedestal interceptors and the familiar Ring session middleware.

All authorisation checks in **Pedestal SP** compare the user assertions that have been provided by the IdP to some kind of restriction defined by the developer. This includes authorisation checks at the route level, as well as inline authorisation checks - the latter which can be made in both Clojure and ClojureScript.

### SAML-authenticated sessions
By default, the act of logging in via a SAML IdP is treated as successful authentication, though you can specify additional parameters that must be met through the `:validation` map in the config. The available options are explained in the `saml20-clj.sp.response/validate` function of [metabase/saml20-clj](https://github.com/metabase/saml20-clj). The authentication itself has been delegated entirely to this library.

Once authenticated, the IdP response and its assertions are stored in an in-memory Ring session store with a limited TTL. The session store and other Ring session-related parameters can be customised via the `:session` key of the config map. Refer to `ring.middleware.session/wrap-session` for the available configuration options.

### Route authorisation
Two route-level authorisation helper functions - `chain` and `permit-request?` - can be found in the `dk.cst.pedestal.sp.interceptors` namespace (aliased as `sp.ic` in the examples below). The `sp.ic/chain` function can be used to build an interceptor chain to restrict a route, e.g.

```clojure
["/some/route" (conj (sp.ic/chain conf :authenticated) `protected-page)]
```

The above snippet defines a route that can only be accessed by an authenticated user. More stringent authorisation requirements can be specified too; these dig more deeply into the IdP assertions about the user.

When generating dynamic content for the user, it quite often becomes necessary to know ahead of time if the user is authorised to access a specific resource. To solve this common issue, **Pedestal SP** also comes with the `sp.ic/permit-request?` function which can be used to check authorisation status within an `sp.ic/chain`:

```clojure
(when (sp.ic/permit-request? ctx "/some/route")
  [:p "You may visit " [:a {:href "/some/route"} "this route"]])
```

By dynamically looking up the route in the router (provided via the Interceptor context) in order to trial requests ahead of time, the code defining the authorisation restrictions is completely decoupled from the code depending on these restrictions.

### Inline authorisation
Two macros are provided `dk.cst.pedestal.sp.auth` to define authorisation restrictions embedded in both Clojure and ClojureScript code: `if-permit` and `only-permit`. The first macro branches like a regular `if`-form, while the second one will throw an exception when the user assertions do not meet the given restriction.

These inline authorisation checks can be used to e.g. build out a single-route backend API endpoint or fine-tune the HTML UI generated by a Single Page Application (SPA) to reflect the authorisation level of the user. Note that in the second case, it becomes to necessary to figure out a way to transport the user assertions from the backend to the frontend.

Whether you use route-level authorisation or inline authorisation checks (backend or frontend) depends on the type of application you're developing. In a typical SPA you will probably need all three at some point.

SAML authentication endpoints
-----------------------------
It is helpful to understand the flow of an SP-initiated SAML login and how it is represented in **Pedestal SP**.
Typically, the login flow will start in one of two ways:

* The user clicks a button or hyperlink labeled "log in" or something similar.
* The user attempts to access an off-limits resource and is either nudged towards or directly redirected to a SAML login flow.

> _Note: The code in the `dk.cst.pedestal.sp.example` namespace illustrates how to make a basic SAML-enabled login page. It makes use of (or links to) all of the `/saml/...` endpoints described below._

### 302 GET `/saml/login`
The SAML login flow starts with an HTTP GET request to `/saml/login`, likely along with `?RelayState=/path/to/resource` as a query string. The RelayState will be passed around the entire SAML flow and - if present - will be used to redirect the user back to where they came from at the end of a successful login. This first SAML endpoint redirects the user to the IdP specified in the config map.

### 200 GET `<URL of IdP>`
We specify _who_ the IdP is in our config map, but we have no control over it otherwise. The IdP is where the actual login takes place. Once logged in, the IdP is supposed to redirect back to our `/saml/login` endpoint, this time using an HTTP POST request.

### 303 POST `/saml/login`
Our SP now receives signed data from the IdP which we decrypt and verify. This data contains assertions about the logged in user. Based on this information we either deny access or redirect the user to the initial resource they were trying to access, which the IdP hopefully provided in the `RelayState` query parameter. This is the end of the SAML login flow.

From here on, we use a session cookie in the browser (named `pedestal-sp` by default) to verify the user's identity. The chain of authentication interceptors can be used to gate restricted resources at different endpoints.

There is also a metadata endpoint which isn't directly invoked as part of the login flow:

### 200 GET `/saml/meta`
Service Provider metadata exposed as XML. This is SAML-related information about your web service made available to any IdP that you choose to integrate with.

Other endpoints
---------------
Apart from the standard SAML authentication endpoints, by default **Pedestal SP** also provides a few convenience endpoints:

### 204/303 POST `/saml/logout`
Making a post request to this endpoint will return HTTP status 204 and delete SAML-related information pertaining to the user from the session store of the web service. Providing a `RelayState` query parameter will result in a 303 redirect instead, treating the value of the parameter as the requested location. This behaviour supports using this endpoint both via an async API call and via regular HTML form submission.

### 200 GET `/saml/response`
Echoes back the SAML response XML received from the IdP during login - or HTTP status 403 when logged out. Serves as example usage of the `restrictions` interceptor chain.

### 200 GET `/saml/assertions`
Echoes back the user assertions contained in the SAML response received from the IdP during login - or HTTP status 403 when logged out. The  assertions are returned as EDN. Serves as example usage of the `restrictions` interceptor chain.
