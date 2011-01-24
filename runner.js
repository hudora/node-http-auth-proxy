/**
 * simple http authentication proxy
 * (c) 2010 Axel Schlueter
 */

var sys = require('sys');

// install a default error handler for all execptions not caught otherwise
// process.on('uncaughtException', function (err) {
//   sys.puts('uncaught exception found: ' + err);
// });

// then start the proxy itself
var proxy = require('./lib/http-auth-proxy');
proxy.createProxy('./settings.json');
