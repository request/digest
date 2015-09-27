
var crypto = require('crypto')
var uuid = require('node-uuid')


function digest (user, pass, method, path, authHeader) {
  // TODO: More complete implementation of RFC 2617.
  //   - check challenge.algorithm
  //   - support algorithm="MD5-sess"
  //   - handle challenge.domain
  //   - support qop="auth-int" only
  //   - handle Authentication-Info (not necessarily?)
  //   - check challenge.stale (not necessarily?)
  //   - increase nc (not necessarily?)
  // For reference:
  // http://tools.ietf.org/html/rfc2617#section-3
  // https://github.com/bagder/curl/blob/master/lib/http_digest.c

  var challenge = {}
  var re = /([a-z0-9_-]+)=(?:"([^"]+)"|([a-z0-9_-]+))/gi
  for (;;) {
    var match = re.exec(authHeader)
    if (!match) {
      break
    }
    challenge[match[1]] = match[2] || match[3]
  }

  var ha1 = md5(user + ':' + challenge.realm + ':' + pass)
  var ha2 = md5(method + ':' + path)
  var qop = /(^|,)\s*auth\s*($|,)/.test(challenge.qop) && 'auth'
  var nc = qop && '00000001'
  var cnonce = qop && uuid().replace(/-/g, '')
  var digestResponse = qop
    ? md5(ha1 + ':' + challenge.nonce + ':' + nc + ':' + cnonce + ':' + qop + ':' + ha2)
    : md5(ha1 + ':' + challenge.nonce + ':' + ha2)
  var authValues = {
    username: user,
    realm: challenge.realm,
    nonce: challenge.nonce,
    uri: path,
    qop: qop,
    response: digestResponse,
    nc: nc,
    cnonce: cnonce,
    algorithm: challenge.algorithm,
    opaque: challenge.opaque
  }

  authHeader = []
  for (var k in authValues) {
    if (authValues[k]) {
      if (k === 'qop' || k === 'nc' || k === 'algorithm') {
        authHeader.push(k + '=' + authValues[k])
      } else {
        authHeader.push(k + '="' + authValues[k] + '"')
      }
    }
  }
  var header = 'Digest ' + authHeader.join(', ')
  return header
}

function md5 (str) {
  return crypto.createHash('md5').update(str).digest('hex')
}

module.exports = digest
