/*
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

let winParams = new URLSearchParams(window.location.search);
let clientId =
    winParams.get('client_id') || '903cfaeb-57d9-4ef6-5659-04377794ed65';
let clientSecret =
    winParams.get('client_secret') || '48f7e552-d9b7-42f3-ba76-e5ab5b3c70ab';
// IMPORTANT: Scopes "account_admin" and "link" should only be requested when
// the user is actively requesting the account to be modified or linked.
let defaultScope = 'openid+offline+profile+identities+ga4gh_passport_v1';
let linkScope = defaultScope + '+account_admin+link';
let loginURL = '_HYDRA_URL_/oauth2/auth?audience=&client_id=' + clientId +
    '&nonce=_NONCE_&redirect_uri=_REDIRECT_&response_type=code&scope=_SCOPE_&state=_STATE_';
let tokenURL = '_HYDRA_URL_/oauth2/token';
let userinfoURL = '_HYDRA_URL_/userinfo';
let authCodeExchangeToken =
    'grant_type=authorization_code&redirect_uri=_REDIRECT_&code=_AUTH_CODE_';
let refreshExchangeToken =
    'grant_type=refresh_token&redirect_uri=_REDIRECT_&refresh_token=_REFRESH_TOKEN_';
let realm = 'master';
let accountURL = '_IC_URL_/identity/scim/v2/_REALM_/Me?client_id=' + clientId +
    '&client_secret=' + clientSecret;
let refreshToken = '';

/**
 * validateState ...
 * @param {string} stateID
 * @param {string} nonce
 * @return {boolean} if the state is valid
 */
function validateState(stateID, nonce) {
  let state = window.localStorage.getItem('state');
  if (!state) {
    displayError(
        `request with invalid 'state' ${stateID}, no 'state' in database`,
        `app maybe under attack or test page refreshed using same code.`);
    return false;
  }
  let s = JSON.parse(state);
  if (s.id !== stateID) {
    displayError(
        `request with invalid 'state' ${stateID}, 'state' in database is ${
            s.id}`,
        `app maybe under attack.`);
    return false;
  }
  if (s.nonce && s.nonce !== nonce) {
    displayError(
        `request with invalid 'nonce' ${nonce}, 'nonce' in database is ${
            s.nonce}`,
        `app maybe under attack.`);
    return false;
  }
  clientId = s.clientId;
  clientSecret = s.clientSecret;

  window.localStorage.removeItem('state');
  return true;
}

/**
 * randomString ...
 * @param {string} length
 * @return {string}
 */
function randomString(length) {
  let charset = '0123456789ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghijklmnopqrstuvwxyz';
  result = '';

  while (length > 0) {
    let bytes = new Uint8Array(16);
    let random = window.crypto.getRandomValues(bytes);

    random.forEach(function(c) {
      if (length == 0) {
        return;
      }
      if (c < charset.length) {
        result += charset[c];
        length--;
      }
    });
  }
  return result;
}

/**
 * makeURL ...
 * @param {string} pattern
 * @param {string} token
 * @param {string} scope
 * @param {string} state
 * @param {string} nonce
 * @return {string} url
 */
function makeURL(pattern, token, scope, state, nonce) {
  let path = window.location.protocol + '//' + window.location.hostname +
      (window.location.port ? ':' + window.location.port : '') +
      window.location.pathname;
  let redirect = window.location.href.split('?')[0];
  state = state || '';
  nonce = nonce || '';
  return pattern.replace(/_PATH_/g, encodeURI(path))
      .replace(/_AUTH_CODE_/g, encodeURIComponent(token))
      .replace(/_REFRESH_TOKEN_/g, encodeURIComponent(token))
      .replace(/_REDIRECT_/g, encodeURIComponent(redirect))
      .replace(/_HYDRA_URL_/g, encodeURI($('#hydra_url').val()))
      .replace(/_IC_URL_/g, encodeURI($('#ic_url').val()))
      .replace(/_TOKEN_/g, encodeURIComponent($('#passport').val()))
      .replace(/_SCOPE_/g, scope || defaultScope)
      .replace(/_REALM_/g, realm)
      .replace(/_STATE_/g, state)
      .replace(/_NONCE_/g, nonce);
}

/**
 * auth starts a login
 */
function auth() {
  let stateID = randomString(16);
  let nonce = '';  // not supplying nonce for code flow
  let state = {
    id: stateID,
    nonce: nonce,
    clientId: clientId,
    clientSecret: clientSecret
  };
  window.localStorage.setItem('state', JSON.stringify(state));

  let url = makeURL(
      loginURL, /*token*/ undefined, defaultScope, stateID, nonce);
  window.location.href = url;
}

/**
 * linkauth starts a login for link account.
 */
function linkauth() {
  let authCode = $('#auth_code').val();
  let tok = $('#access_token').val();
  if (authCode && !tok) {
    displayError(
        'must exchange code first (assuming it has the \'link\' scope)...');
    return;
  }
  if (tok) {
    window.localStorage.setItem('primary_token', tok);
  }
  auth(linkScope);
}

/**
 * tokenExchange exchanges authcode to token.
 */
function tokenExchange() {
  let authCode = $('#auth_code').val();
  if (!authCode) {
    displayError('must login first...');
    return;
  }
  let url = makeURL(tokenURL);
  $.ajax({
    url: url,
    type: 'POST',
    data: makeURL(authCodeExchangeToken, authCode),
    beforeSend: function(xhr) {
      xhr.setRequestHeader(
          'Authorization', 'Basic ' + btoa(clientId + ':' + clientSecret));
    },
    success: function(resp) {
      $('#log').text('Authorization: ' + JSON.stringify(resp, undefined, 2));
      $('#access_token').val(resp.access_token);
      $('#refresh_token').val(resp.refresh_token || '');
      refreshToken = resp.refresh_token;
    },
    error: function(err) {
      displayError(
          'token exchange failed', '', JSON.stringify(err, undefined, 2));
    }
  });
}

/**
 * linkAccount ...
 * @param {string} authCode
 */
function linkAccount(authCode) {
  let primaryToken = window.localStorage.getItem('primary_token');
  window.localStorage.removeItem('primary_token');
  $('#access_token').val(primaryToken);
  let url = makeURL(tokenURL);
  $.ajax({
    url: url,
    type: 'POST',
    data: makeURL(authCodeExchangeToken, authCode),
    beforeSend: function(xhr) {
      xhr.setRequestHeader(
          'Authorization', 'Basic ' + btoa(clientId + ':' + clientSecret));
    },
    success: function(resp) {
      scimLink(primaryToken, resp.access_token);
    },
    error: function(err) {
      displayError(
          'token exchange (for linking) failed', '',
          JSON.stringify(err, undefined, 2));
    }
  });
}

/**
 * scimLink links scims
 * @param {string} primaryToken
 * @param {string} linkToken
 */
function scimLink(primaryToken, linkToken) {
  let url = makeURL(accountURL);
  let data =
      `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"add","path":"emails","value":"X-Link-Authorization"}]}`;
  $.ajax({
    url: url,
    type: 'PATCH',
    contentType: 'application/json; charset=utf-8',
    dataType: 'json',
    data: data,
    processData: false,
    beforeSend: function(xhr) {
      xhr.setRequestHeader('Authorization', 'Bearer ' + primaryToken);
      xhr.setRequestHeader('X-Link-Authorization', 'Bearer ' + linkToken);
    },
    success: function(resp) {
      $('#log').text(
          'LINK ACCOUNT SUCCESS:\n\n' + JSON.stringify(resp, undefined, 2));
    },
    error: function(err, status, info) {
      displayError(
          'link account failed', `status: "${status}", info: "${info}"`,
          JSON.stringify(err, undefined, 2));
    }
  });
}

/**
 * userinfo fetches userinfo
 */
function userinfo() {
  let tok = $('#access_token').val();
  if (!tok) {
    displayError('must login first...');
    return;
  }
  let url = makeURL(userinfoURL);
  $.ajax({
    url: url,
    type: 'GET',
    beforeSend: function(xhr) {
      xhr.setRequestHeader('Authorization', 'Bearer ' + tok);
    },
    success: function(resp) {
      $('#log').text('Userinfo: ' + JSON.stringify(resp, undefined, 2));
    },
    error: function(err) {
      displayError('user info failed', '', JSON.stringify(err, undefined, 2));
    }
  });
}

/**
 * refresh tokens with refresh token
 */
function refresh() {
  if (!refreshToken) {
    $('#log').text('must login first...');
    return;
  }
  let url = makeURL(tokenURL);
  $.ajax({
    url: url,
    type: 'POST',
    data: makeURL(refreshExchangeToken, refreshToken),
    beforeSend: function(xhr) {
      xhr.setRequestHeader(
          'Authorization', 'Basic ' + btoa(clientId + ':' + clientSecret));
    },
    success: function(resp) {
      $('#log').text('Authorization: ' + JSON.stringify(resp, undefined, 2));
      $('#access_token').val(resp.access_token);
      $('#refresh_token').val(resp.refresh_token);
      refreshToken = resp.refresh_token;
    },
    error: function(err) {
      displayError(
          'refresh token failed', '', JSON.stringify(err, undefined, 2));
    }
  });
}

/**
 * accountInfo fetches account info
 */
function accountInfo() {
  let tok = $('#access_token').val();
  if (!tok) {
    $('#log').text('must login first...');
    return;
  }
  let url = makeURL(accountURL);
  $.ajax({
    url: url,
    type: 'GET',
    beforeSend: function(xhr) {
      xhr.setRequestHeader('Authorization', 'Bearer ' + tok);
    },
    success: function(resp) {
      $('#log').text('Account Info:\n\n' + JSON.stringify(resp, undefined, 2));
    },
    error: function(err) {
      displayError(
          'account info failed', '', JSON.stringify(err, undefined, 2));
    }
  });
}

/**
 * displayError in page
 * @param {string} error
 * @param {string} desc
 * @param {string} hint
 */
function displayError(error, desc, hint) {
  $('#error').text(error);
  $('#error_desc').text(desc || '');
  $('#error_hint').text(hint || '');
  $('#error_info').removeClass('hidden');
}

/**
 * defaultHydra resets hydra to default
 */
function defaultHydra() {
  let url = document.getElementById("hydra_url");
  url.value = document.getElementById("default-hydra").dataset.url;
}

/**
 * clearPage clears outputs in page
 */
function clearPage() {
  window.localStorage.removeItem('primary_token');
  window.location.href = makeURL('_PATH_');
}

/**
 * debugJWT open token in jwt
 * @param {string} selector
 */
function debugJWT(selector) {
  let token = $(selector).val();
  window.open('https://jwt.io/#debugger-io?token=' + token);
}

/**
 * init ...
 */
function init() {
  let code = winParams.get('code');
  if (code) {
    $('#auth_code').val(code);
    validateState(winParams.get('state'), winParams.get('nonce'));
    if (window.localStorage.getItem('primary_token')) {
      linkAccount(code);
    }
  }

  // register onclick events
  document.getElementById("auth").onclick = auth;
  document.getElementById("linkauth").onclick = linkauth;
  document.getElementById("default-hydra").onclick = defaultHydra;
  document.getElementById("clear").onclick = clearPage;

  document.getElementById("token-exchange").onclick = tokenExchange;
  document.getElementById("userinfo").onclick = userinfo;
  document.getElementById("refresh").onclick = refresh;
  document.getElementById("account-info").onclick = accountInfo;
  document.getElementById("debug-jwt").onclick = function(){
    debugJWT('#access_token');
  };
}

window.onload = init;
