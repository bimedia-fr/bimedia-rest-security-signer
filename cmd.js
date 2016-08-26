#!/usr/bin/env node

var fs = require('fs');
var path = require('path');

var minimist = require('minimist');
var argv = minimist(process.argv.slice(2), {
    alias: { v: 'version', h: 'help', p: 'privatekey', u: 'id' }
});


function usage(code) {
  var r = fs.createReadStream(path.join(__dirname, 'usage.txt'));
  if (code) {
      r.once('end', function () { process.exit(code); });
  }
  r.pipe(process.stdout);
}

function error(err) {
  console.error(err.stack || err);
  process.exit(1);
}

var cmd = argv._[0];
if (cmd === 'help' || argv.help) {
    return usage(0);
}

var defined = require('defined');

if (argv.v || argv.version) {
  return console.log(require('./package.json').version);
}

var private = fs.readFileSync(path.resolve(process.cwd(), defined(argv.p, argv.privatekey)));
var Signer = require('./lib/index.js');

console.log(new Signer(defined(argv.u, argv.id), private).sign(cmd).toCurl());
