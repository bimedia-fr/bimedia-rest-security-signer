/*jslint node : true, nomen: true, plusplus: true, vars: true, eqeq:true*/
"use strict";

var crypto = require('crypto');
var url = require('url');

function SignedResult(opts) {
    this.opts = opts;
}

SignedResult.prototype.toRequestParams = function () {
    var opts = {};
    // Request
    opts.url = this.opts.url;
    opts.method = this.opts.method;
    opts.headers = this.opts.headers;

    if (this.opts.body) {
        opts.body = this.opts.body;
    }
    if (this.opts.json) {
        opts.json = this.opts.json;
    }

    // http.request
    var parts = url.parse(this.opts.url);
    opts.protocol = parts.protocol;
    opts.hostname = parts.hostname;
    opts.port = parts.port;
    opts.path = parts.path;

    return opts;
};

SignedResult.prototype.toCurl = function () {
    var opts = this.opts;
    var result = ['curl',
        (opts.method == 'GET' ? '' : '-X ' + opts.method)];
    result = result.concat(Object.keys(opts.headers).map(function (name) {
        return '-H "' + name + ': ' + opts.headers[name] + '"';
    }));
    if (opts.body) {
        result.push('-d');
        result.push(opts.body);
    }
    result.push(opts.url);
    return result.join(' ');
};

SignedResult.prototype.postData = function () {
    return this.opts.body || null;
};

// Main module
function Signer(principal, privatekey) {
    this.principal = principal;
    this.privatekey = privatekey;
}

Signer.prototype.sign = function (options) {

    if (typeof options === 'string') {
        options = {url : options};
    }

    var opts  = {
        url: options.url || '',
        method: options.method || 'GET',
        headers: options.headers || {},
        body: null
    };
    if (opts.method !== 'GET') {
        opts.body = opts.body || '';
        opts.json = opts.json || false;
    }

    var urlParts = url.parse(opts.url, true);
    var params = urlParts.query || {};
    var queryString = Object.keys(params).sort().map(function (item, index, array) {
        return item + (params[item] ? '=' + params[item] : '');
    }).join('&');
    var canonicalizedResource = urlParts.pathname + (queryString ? '?' + queryString : '');

    if (!opts.headers['x-bm-date'] && !opts.headers.date) {
        opts.headers.date = new Date().toUTCString();
    }
    if (!opts.headers['content-type']) {
        opts.headers['content-type'] = '';
    }
    if (opts.method !== 'GET') {
        if (opts.json) {
            opts.headers['content-md5'] = crypto.createHash('md5').update(JSON.stringify(opts.body)).digest("base64");
        } else {
            opts.headers['content-md5'] = crypto.createHash('md5').update(opts.body).digest("base64");
        }
    }
    var canonicalizedHeaders = Object.keys(opts.headers).filter(function (item) {
        return item.startsWith('x-bm-');
    }).sort().map(function (item, index, array) {
        return item + ':' + opts.headers[item];
    }).join("\n");

    var hash = crypto.createSign('RSA-SHA256');
    opts.headers.authorization = "BWS " + this.principal + ":" + hash.update([
        opts.method,
        (opts.headers['content-md5'] || ''),
        opts.headers['content-type'],
        (opts.headers['x-bm-date'] || opts.headers.date),
        canonicalizedHeaders,
        canonicalizedResource
    ].join('\n')).sign(this.privatekey, 'base64');

    return new SignedResult(opts);
};

Signer.sign = function (opts, principal, privatekey) {
    var signer = new Signer(principal, privatekey);
    return signer.sign(opts);
};

module.exports = Signer;
