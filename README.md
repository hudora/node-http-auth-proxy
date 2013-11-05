node-http-auth-proxy - authenticate HTTP requests against another server
========================================================================

Installation and configuration
------------------------------

* the proxy was developed with node v0.2.5, download it from http://nodejs.org/
* to use the proxy you have to install all required dependencies via `make dependencies`
* copy `settings.json.example` to `settings.json`, then edit the configuration of the proxy.
* then run the server via `make` or `node runner.js`


Authentication
--------------

* to validate the authenticity of a request the proxy searches for the configured
  cookie. If the cookie can be found is gets checked for manipulation or if the session
  timed out.
* if the cookie is invalid or if there is no proxy at all the proxy redirects the user
  to the configured authentication server. The authentication server then validates
  the current user in some way or another and finally returns the user back to the
  proxy server to execute the original request.
* the redirection request from the authentication server to the proxy contains a magic token
  and the user's email address. Both values have to be sent as GET parameters with the names
  configured in the `settings.json`. You will find an example authentication server in the
  file [authserver.js](https://github.com/hudora/node-http-auth-proxy/blob/master/doc/authserver.js).
* the email address of the authenticated user will be forwarded to the server secured by the
  proxy by the means of an additional HTTP request header, 'x-auth-proxy-username'. The 
  destination server might react by filtering or modifying its response to the request 
  depending on which user was authenticated by the proxy.


Exceptions
----------

* the proxy allows to configuration URL paths which shouldn't be authenticated. To do so
  there is the `exceptions` configuration option. The option is a list of regular expressions
  to be matched against the requested URL for each request:
      "exceptions": [
         "^/api.php",
         "^/icons/(.*)"
      ]


[![Bitdeli Badge](https://d2weczhvl823v0.cloudfront.net/hudora/node-http-auth-proxy/trend.png)](https://bitdeli.com/free "Bitdeli Badge")

