var http = require('http'),
    url = require('url'),
    crypto = require("crypto"),
    querystring = require('querystring');

var key = 'changeThisPrivateKeyOnYourInstallation';

var server = http.createServer(function(req, resp) {
  var urlParts = url.parse(req.url, true),
      redirectTo = url.parse(urlParts.query.redirection, true);

  var redirectUrlWithoutParameters = redirectTo.protocol + '//' +
                                     redirectTo.host +
                                     redirectTo.pathname;
  console.log('url without params: <' + redirectUrlWithoutParameters + '>');

  var hmac = crypto.createHmac("sha1", key),
      hash = hmac.update(redirectUrlWithoutParameters),
      digest = hmac.digest('base64');
  if(!redirectTo.query)
    redirectTo.query = {};
  redirectTo.query['magicToken'] = digest;
  redirectTo.query['magicTokenEmail'] = 'foo@bar.org';
  console.log(' digest: <' + digest + '>');

  var redirectUrl = redirectUrlWithoutParameters + '?' +
                    querystring.stringify(redirectTo.query);
  console.log(redirectUrl);

  resp.writeHead(302, {
    'Location': redirectUrl,
    'Content-Type': 'text/plain'
  });
  resp.end(redirectUrl + '\n');
});

server.listen(9090, "localhost");
console.log('started sample auth server server');
