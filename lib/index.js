/*jslint node : true, nomen: true, plusplus: true, vars: true, eqeq:true*/
"use strict";

var crypto = require('crypto');
var url = require('url');

// Main module

function Signer() {
	this.opts = {};
}

Signer.sign = function(opts, principal, privatekey) {
	
	
	var signer = new Signer();
	
	signer.opts = {
		principal: principal,
		url: opts.url || '',
		method: opts.method || 'GET',
		headers: opts.headers || {},
		post: null
	};
	if(signer.opts.method !== 'GET') {
		signer.opts.body = opts.body || '';
		signer.opts.json = opts.json || false
	}
	
	var urlParts = url.parse(signer.opts.url, true);
	var params = urlParts.query || {};
	var queryString = Object.keys(params).sort().map(function(item, index, array) {
		return item+(params[item] ? '='+params[item] : '');
	}).join('&');
	var canonicalizedResource = urlParts.pathname + (queryString ? '?'+queryString : '');
	
	if(!signer.opts.headers['x-bm-date'] && !signer.opts.headers['date']) {
		signer.opts.headers['date'] = new Date().toUTCString();
	}
	if(!signer.opts.headers['content-type']) {
		signer.opts.headers['content-type'] = '';
	}
	if(signer.opts.method !== 'GET') {
		if(signer.opts.json) {
			signer.opts.headers['content-md5'] = crypto.createHash('md5').update(JSON.stringify(this.opts.body)).digest("base64")
		} else {
			signer.opts.headers['content-md5'] = crypto.createHash('md5').update(this.opts.body).digest("base64")
		}
	}
	var canonicalizedHeaders = Object.keys(signer.opts.headers).filter(function(item) {
		return item.startsWith('x-bm-');
	}).sort().map(function(item, index, array) {
		return item+':'+signer.opts.headers[item];
	}).join("\n");
	
	var hash = crypto.createSign('RSA-SHA256');
	signer.opts.headers.authorization = "BWS "+signer.opts.principal+":"+hash.update(
			signer.opts.method+"\n"+(signer.opts.headers['content-md5'] || '')+"\n"+signer.opts.headers['content-type']+"\n"+(signer.opts.headers['x-bm-date'] 
			|| signer.opts.headers['date'])+"\n"+canonicalizedHeaders+"\n"+canonicalizedResource
	).sign(privatekey, 'base64');	
	
	return signer;
};

Signer.prototype.toRequestParams = function() {
	var opts = {};
	// Request
	opts.url= this.opts.url;
	opts.method = this.opts.method;
	opts.headers = this.opts.headers;
	
	if(this.opts.body) {
		opts.body = this.opts.body;
	}
	if(this.opts.json) {
		opts.json = this.opts.json;
	}
	
	// http.request
	var parts = url.parse(this.opts.url);
	opts.protocol = parts.protocol;
	opts.hostname = parts.hostname;
	opts.port = parts.port;
	opts.path = parts.path;
	
	return opts;
}

Signer.prototype.postData = function() {
	return this.opts.body || null;
}

module.exports = Signer;