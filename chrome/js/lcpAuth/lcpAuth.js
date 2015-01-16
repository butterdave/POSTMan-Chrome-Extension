if (!this.Lcp) {
  this.Lcp = {};
}

this.Lcp.GenerateAuthHeader = (function() {
  function GenerateAuthHeader(httpMethod, requestUrl, macKeyIdentifer, macKey, contentType, payload) {
    var now;
    this.httpMethod = httpMethod;
    this.macKeyIdentifer = macKeyIdentifer;

    var d = new Date();
    var n = d.getTime()+"";
    this.ts = n.substring(0, n.length-3);

    this.nonce = this.randomString(8);
    this.getUrlParts(requestUrl);
    this.extension = this.generateExt(contentType, payload);
    this.normalizedRequestString = this.buildNormalizedRequestString();
    this.mac = this.generateSignature(macKey, this.normalizedRequestString);
    this.header = this.generateHeader();
  }

  GenerateAuthHeader.prototype.getUrlParts = function(requestUrl) {
    var urlParts;
    var parser = document.createElement('a');
    parser.href = requestUrl;
    this.port = parser.port;
    if (!this.port) {
      if (parser.protocol === 'https:') {
        this.port = '443';
      } else {
        this.port = '80';
      }
    }
    this.path = parser.pathname;
    this.hostname = parser.hostname;
  };

  GenerateAuthHeader.prototype.generateExt = function(contentType, payload) {
    var content, extension;
    if (contentType && payload) {
      content = contentType + payload;
      extension = CryptoJS.SHA1(content);
    } else {
      extension = '';
    }
    return extension;
  };

  GenerateAuthHeader.prototype.buildNormalizedRequestString = function() {
    var normalizedRequestString;
    normalizedRequestString = this.ts + '\n' + this.nonce + '\n' + this.httpMethod + '\n' + this.path + '\n' + this.hostname + '\n' + this.port + '\n' + this.extension + '\n';
    return normalizedRequestString;
  };

  GenerateAuthHeader.prototype.encode_utf8 = function(s) {
    return unescape(encodeURIComponent(s));
  }

  GenerateAuthHeader.prototype.randomString = function(len, charSet) {
    charSet = charSet || 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    var randomString = '';
    for (var i = 0; i < len; i++) {
      var randomPoz = Math.floor(Math.random() * charSet.length);
      randomString += charSet.substring(randomPoz,randomPoz+1);
    }
    return randomString;
  };

  GenerateAuthHeader.prototype.generateSignature = function(macKey, normalizedRequestString) {
    macKey = macKey.replace(new RegExp("-", 'g'), "+").replace(new RegExp("_", 'g'), "/");
    var secret = CryptoJS.enc.Base64.parse(macKey);
    var mac = CryptoJS.HmacSHA1(normalizedRequestString, secret).toString(CryptoJS.enc.Base64);
    return mac
  };

  GenerateAuthHeader.prototype.generateHeader = function() {
    return "MAC id=\"" + this.macKeyIdentifer + "\", ts=\"" + this.ts + "\", nonce=\"" + this.nonce + "\", ext=\"" + this.extension + "\", mac=\"" + this.mac + "\"";
  };

  return GenerateAuthHeader;

})();
