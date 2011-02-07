var http = require('http'),
    url = require('url'),
    crypto = require("crypto"),
    querystring = require('querystring');

var key = 'changeThisPrivateKeyOnYourInstallation';


var server = http.createServer(function(req, resp) {
  var urlParts = url.parse(req.url, true),
      nonce = urlParts.query.nonce,
      redirectTo = url.parse(urlParts.query.redirection, true);

  var redirectUrlWithoutParameters = redirectTo.host +
                                     redirectTo.pathname;

  var hmac = crypto.createHmac("sha1", key);
  hmac.update(redirectUrlWithoutParameters);
  hmac.update(nonce);
  var digest = hmac.digest('base64');

  if(!redirectTo.query)
    redirectTo.query = {};
  redirectTo.query['magicToken'] = digest;
  redirectTo.query['magicTokenNonce'] = nonce;
  redirectTo.query['magicTokenEmail'] = 'foo@bar.org';

  var redirectUrl = redirectTo.protocol + '//' +
                    redirectUrlWithoutParameters + '?' +
                    querystring.stringify(redirectTo.query);
  console.log(req.url);
  console.log('  --> (' + digest + ')  ' + redirectUrl);

  resp.writeHead(302, {
    'Location': redirectUrl,
    'Content-Type': 'text/plain'
  });
  resp.end(redirectUrl + '\n');
});

server.listen(9090, "localhost");
console.log('started sample auth server server');
