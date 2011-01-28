/**
 * simple HTTP proxy with Google Apps authentication
 */

require.paths.unshift(__dirname + '/../lib/node-elf-logger/lib/');

var sys = require('sys'),
    fs = require('fs'),
    querystring = require('querystring'),
    url = require('url'),
    crypto = require('crypto'),
    http = require('http'),
    elf = require("elf-logger");

var _ = require(__dirname + '/../lib/underscore/underscore.js');


/** create and return a new proxy instance */
exports.createProxy = function(configFilenameOrConfiguration) {
  return new ProxyServer(configFilenameOrConfiguration);
};

/** proxy class constructor */
function ProxyServer(configFilenameOrConfiguration) {
  if(typeof(configFilenameOrConfiguration) == 'object') {
    this.config = configFilenameOrConfiguration;
    this.startServer();
  }
  else {
    var self = this;
    fs.readFile(configFilenameOrConfiguration, function(err, data) {
      if(err) throw err;
      self.config = JSON.parse(data);
      self.startServer();
    });
  }
}

/** start a new proxy server */
ProxyServer.prototype.startServer = function() {
  var self = this,
      server = http.createServer(function(req, resp) {
        self.handleRequest(req, resp);
      });

  // validate the settings read from the file
  if(!this.config.destination || !this.config.destination.host)
    throw 'destination host configuration missing!';

  // configure and start the server
  var port = this.config.port || 8000,
      host = this.config.host || 'localhost';
  server.listen(port, host);
  elf.createLogger(server, {
    'stream': process.stdout
  });
};

/** called to handle a single incoming request to the proxy */
ProxyServer.prototype.handleRequest = function(hostReq, hostResp) {
  var self = this,
      dest = this.config.destination,
      protocol = hostReq.headers['x-forwarded-protocol'] || 'http';

  // did we return from the auth server with the magic token? Then do nothing to
  // the request. All other requests musted be checked to the authentication cookie.
  // If there is no valid authentication we're redirecting the user to the auth side
  var authCookie = this.checkForAndValidateMagicToken(hostReq);
  if(!authCookie) {
    var auth = this.checkForAuthCookie(hostReq.headers);
    if(!this.isAuthValid(auth)) {
      var thisHost = this.originalHost(hostReq),
          nonce = generateNonce(),
          redirectUrl = querystring.escape(protocol + '://' + thisHost + hostReq.url),
          authUrl = this.config.authUrl + '?nonce=' + nonce + '&redirection=' + redirectUrl;
      hostResp.writeHead(302, { 'Location': authUrl });
      hostResp.end();
      return;
    }
  }

  // data from the client is forwarded to the original host
  var client = http.createClient(dest.port || 80, dest.host),
      clientReq = client.request(hostReq.method, hostReq.url, hostReq.headers);
  clientReq.addListener('response', function(clientResp) {
    clientResp.addListener('data', function(data) {
      hostResp.write(data, 'binary');
    });
    clientResp.addListener('end', function() {
      hostResp.end();
    });

    // set our auth cookie, then send the header back to the client
    var headers = _.map(clientResp.headers, function(value, name) { return [name, value]; });
    if(authCookie)
      headers.push(['Set-Cookie', self.config.cookieName + '=' + authCookie + ';Path=/']);
    hostResp.writeHead(clientResp.statusCode, headers);
  });

  // data from the original host is forwarded to the client
  hostReq.addListener('data', function(data) {
    clientReq.write(data, 'binary');
  });
  hostReq.addListener('end', function() {
    clientReq.end();
  });
};

/** check for the auth server return token in the given URL. If it's valid return true, false otherwise */
ProxyServer.prototype.checkForAndValidateMagicToken = function(req) {
  // did we find our magic token hash value? If not bail out as there's nothing to check
  var params = url.parse(req.url, true).query || {},
      magicToken = params[this.config.magicToken],
      nonce = params[this.config.magicToken + 'Nonce'];
  if(!magicToken)
    return undefined;

  // calculate the hash value we're expecting in the auth server answer
  var requestedUrl = this.originalHost(req) + req.url.split('?')[0],
      hmac = crypto.createHmac('sha1', this.config.magicTokenKey || '???');
  hmac.update(requestedUrl);
  hmac.update(nonce);
  var digest = hmac.digest('base64');

  // does the received token match our expectations?
  if(magicToken != digest)
    return undefined;

  // we got the token, let's calculate the session cookie
  var email = params[this.config.magicToken + 'Email'] || 'anonymous',
      now = Math.round(new Date().getTime() / 1000),
      cookie = email + '&' + (now + (this.config.sessionValidity || 86400));
  hmac = crypto.createHmac('sha1', this.config.magicTokenKey || '???'),
  hash = hmac.update(cookie),
  digest = hmac.digest('base64').substr(0,10);
  cookie += '&' + digest;

  return cookie;
};

/** determine the host the user wanted to access in the first place */
ProxyServer.prototype.originalHost = function(req) {
  return req.headers['x-forwarded-host'] || req.headers['host'];
};

/** check the validity of the authentication cookie */
ProxyServer.prototype.isAuthValid = function(authCookie) {
  // did we get some signature data?
  if(!authCookie)
    return false;
  var parts = authCookie.split('&');
  if(parts.length != 3)
    return false;

  // did we get a valid signature?
  var email = parts[0],
      validity = parseInt(parts[1]),
      cookie = email + '&' + validity;
  hmac = crypto.createHmac('sha1', this.config.magicTokenKey || '???'),
  hash = hmac.update(cookie),
  digest = hmac.digest('base64').substr(0, 10);
  if(parts[2] != digest)
    return false;

  // is the cookie still valid?
  var now = Math.round(new Date().getTime() / 1000);
  if(now >= validity)
    return false;

  // everything's fine, cookie is valid
  return true;
};

/** extract the authentication cookie from the request headers */
ProxyServer.prototype.checkForAuthCookie = function(headers) {
  // do we have any cookies at all in the request?
  var self = this,
      cookies = headers.cookie;
  if(!cookies)
    return undefined;

  // let's search our very own auth cookie
  var extractor = function(cookie) {
    var parts = cookie.trim().split('='),
        name = parts[0],
        value = parts[1];
    return name==self.config.cookieName ? value : undefined;
  };
  var authValue = _(cookies.split(';')).chain().
    map(extractor).
    compact().
    flatten().
    value();

  // and finally return the value
  return authValue[0];
};

/** helper method, generate a nonce like '7d8f3e4a' */
function generateNonce() {
  var charset='0123456789abcdefghijklmnopqrstuvwxyz',
      nonce='';
  for(var i=0; i<8; i++)
    nonce += charset[Math.floor(Math.random()*charset.length)];
  return nonce;
}

