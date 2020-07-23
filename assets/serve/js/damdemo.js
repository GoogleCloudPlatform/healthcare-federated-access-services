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
let scope = 'openid+offline';
let identitiesScope = 'openid+offline+identities';
let loginURL = '_HYDRA_URL_/oauth2/auth?audience=&client_id=_CLIENT-ID_' +
    '&nonce=_NONCE_&redirect_uri=_REDIRECT_&response_type=code&scope=' + scope +
    '&state=_STATE_&max_age=_MAX_AGE_&resource=_RESOURCES_';
let loginIdentitiesURL =
    '_HYDRA_URL_/oauth2/auth?audience=&client_id=_CLIENT-ID_' +
    '&nonce=_NONCE_&redirect_uri=_REDIRECT_&response_type=code&scope=' +
    identitiesScope + '&state=_STATE_';
let tokenURL = '_HYDRA_URL_/oauth2/token';
let authCodeExchangeToken =
    'grant_type=authorization_code&redirect_uri=_REDIRECT_&code=_AUTH_CODE_';
let refreshExchangeToken =
    'grant_type=refresh_token&redirect_uri=_REDIRECT_&refresh_token=_REFRESH_TOKEN_';
let resourcesURL =
    '_DAM_URL_/dam/v1alpha/_REALM_/resources?client_id=_CLIENT-ID_' +
    '&client_secret=_CLIENT-SECRET_';
let resourceURL =
    '_DAM_URL_/dam/_REALM_/resources/_RESOURCE_/views/_VIEW_/roles/_ROLE_/interfaces/_INTERFACE_';
let resources = {};
let checkoutURL = '_DAM_URL_/dam/checkout?client_id=_CLIENT-ID_' +
    '&client_secret=_CLIENT-SECRET_';
let refreshToken = '';
let accountURL = '_DAM_URL_/identity/scim/v2/_REALM_/Me?client_id=_CLIENT-ID_' +
    '&client_secret=_CLIENT-SECRET_';
let apiRelativePathURL = '_DAM_URL_/dam/v1alpha/_REALM_/_API-PATH_?client_id=' +
    '_CLIENT-ID_&client_secret=_CLIENT-SECRET_';
let apiAbsolutePathURL = '_DAM_URL__API-PATH_?client_id=_CLIENT-ID_' +
    '&client_secret=_CLIENT-SECRET_';

/**
 * validateState ...
 * @param {string} stateID
 * @return {string}
 */
function validateState(stateID) {
  if (!stateID) {
    return false;
  }
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
  if (s.clientId) {
    clientId = s.clientId;
    clientSecret = s.clientSecret;
  }

  window.localStorage.removeItem('state');
  $('#resources').text(s.resList);
  return true;
}


/**
 * randomString in given length
 * @param {number} length
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
 * @param {string} params
 * @param {string} state
 * @param {!array} resources
 * @return {string} url
 */
function makeURL(pattern, token, params, state, resources) {
  let path = window.location.protocol + '//' + window.location.hostname +
      (window.location.port ? ':' + window.location.port : '') +
      (window.location.pathname == '/' ? '' : window.location.pathname);
  let damUrl = $('#dam_url').val();
  if (damUrl.startsWith('http://localhost:')) {
    path = path.replace(/^http:\/\/.*:/, 'http://localhost:');
  }
  let redirect = (params && path + '?' + params) || path;
  let realm = $('#realm').val() || 'master';
  state = state || '';
  let resEncoded = '';
  if (resources) {
    for (let i = 0; i < resources.length; i++) {
      let resURL = encodeURIComponent(resources[i]);
      resEncoded = resEncoded ? resEncoded + '&resource=' + resURL : resURL;
    }
  }
  return pattern.replace(/_PATH_/g, encodeURI(path))
      .replace(/_API-PATH_/g, $('#api_path').val() || '') // do not escape path
      .replace(/_AUTH_CODE_/g, encodeURIComponent(token))
      .replace(/_REFRESH_TOKEN_/g, encodeURIComponent(token))
      .replace(/_REALM_/g, encodeURIComponent(realm))
      .replace(/_MAX_AGE_/g, encodeURIComponent($('#ttl').val() || '3600'))
      .replace(/_REDIRECT_/g, encodeURIComponent(redirect))
      .replace(/_VIEW_/g, encodeURIComponent($('#resource_view').val()))
      .replace(/_ROLE_/g, encodeURIComponent($('#resource_role').val()))
      .replace(
          /_INTERFACE_/g, encodeURIComponent($('#resource_interface').val()))
      .replace(/_DAM_URL_/g, encodeURI($('#dam_url').val()))
      .replace(/_HYDRA_URL_/g, encodeURI($('#hydra_url').val()))
      .replace(/_TOKEN_/g, encodeURIComponent($('#passport').val()))
      .replace(/_STATE_/g, state)
      .replace(/_NONCE_/g, state)
      .replace(/_RESOURCES_/g, resEncoded)
      .replace(/_RESOURCE_/g, encodeURIComponent($('#resource_name').val()))
      .replace(/_CLIENT-ID_/g, encodeURIComponent(clientId))
      .replace(/_CLIENT-SECRET_/g, encodeURIComponent(clientSecret));
}

/**
 * auth starts a login
 */
function auth() {
  let type = $('#token_type').val();
  let resources = '';
  let stateID = randomString(16);
  let state = new Object();
  state.id = stateID;
  if (winParams.get('client_id')) {
    state.clientId = clientId;
    state.clientSecret = clientSecret;
  }
  let u = loginURL;

  if (type === 'dataset') {
    resources = $('#resources').val().trim();
    if (!resources) {
      displayError('must include resources first...');
      return;
    }
    state.resList = resources;
  } else if (type === 'endpoint') {
    u = loginIdentitiesURL;
  }

  window.localStorage.setItem('state', JSON.stringify(state));

  let url = makeURL(
      u, /*token*/ undefined, /*params*/ undefined, stateID,
      resources.split('\n'));
  window.location.href = url;
}

/**
 * tokenExchange exchanges auth code to access token
 */
function tokenExchange() {
  let authCode = $('#auth_code').text();
  if (!authCode) {
    displayError('must authorize resources first...');
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
      clearError();
      $('#token').text(resp.access_token);
      $('#access_token_div').addClass('available');
      $('#cart-btn').removeClass('white').addClass('blue');
      refreshToken = resp.refresh_token;
    },
    error: function(err) {
      displayError(
          'token exchanged failed', '', JSON.stringify(err, undefined, 2));
    }
  });
}

/**
 * refresh exchanges refresh token to tokens
 */
function refresh() {
  if (!refreshToken) {
    displayError('must login first...');
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
      clearError();
      $('#token').text(resp.access_token);
      $('#access_token_div').addClass('available');
      $('#cart-btn').removeClass('white').addClass('blue');
      refreshToken = resp.refresh_token;
    },
    error: function(err) {
      $('#log').text(JSON.stringify(err, undefined, 2));
    }
  });
}

/**
 * accountInfo fetches account info
 */
function accountInfo() {
  let tok = $('#token').text();
  if (!tok) {
    displayError('must login first...');
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
 * cartTokens exchange resource tokens
 */
function cartTokens() {
  let token = $('#token').text();
  if (!token) {
    displayError('must authorize resources first...');
    return;
  }
  let url = makeURL(checkoutURL);
  $.ajax({
    url: url,
    type: 'POST',
    beforeSend: function(xhr) {
      xhr.setRequestHeader('Authorization', 'Bearer ' + token);
    },
    success: function(resp) {
      cart = resp;
      clearError();
      $('#log').text('Cart Tokens: ' + JSON.stringify(resp, undefined, 2));
      populateCartTable(resp);
    },
    error: function(err) {
      displayError(
          'cart token request failed', '', JSON.stringify(err, undefined, 2));
    }
  });
}

/**
 * populateResources fetches resource from dam
 */
function populateResources() {
  $.ajax({
    url: makeURL(resourcesURL),
    type: 'GET',
    success: function(resp) {
      resources = {};
      for (let resName in resp.resources) {
        let res = resp.resources[resName];
        let views = {};
        for (let viewName in res.views) {
          let view = res.views[viewName];
          let roles = [];
          for (let role in view.roles) {
            roles.push(role);
          }
          let interf = [];
          for (let intf in view.interfaces) {
            interf.push(intf);
          }
          views[viewName] = { 'roles': roles, 'interfaces': interf };
        }
        resources[resName] = views;
      }
      setupResources();
    },
    error: function(xhr, status, err) {
      setupResources();
    }
  });
}

/**
 * setupResources ...
 */
function setupResources() {
  if (jQuery.isEmptyObject(resources)) {
    resources = {
      'thousand-genomes':
          {'discovery-access': ['discovery'], 'gcs-file-access': ['viewer']}
    };
  }
  populateDropdown('resource_name', Object.keys(resources));
  resourceChanged();
}

/**
 * populateDropdown populate resource list to dropdown menu
 * @param {string} id
 * @param {!array} values
 */
function populateDropdown(id, values) {
  let html = '';
  values = values || [];
  for (let i = 0; i < values.length; i++) {
    html += `<option val="${values[i]}">${values[i]}</option>`;
  }
  $('#' + id).html(html).val($(`#${id} option:first`).val());
}

/**
 * display success info on page
 * @param {string} str
 */
function displaySuccess(str) {
  clearError();
  $('#log').text(str);
}

/**
 * clearError outputs
 */
function clearError() {
  $('#error_info').addClass('hidden');
}

/**
 * displayError ...
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
 * resourceChanged ...
 */
function resourceChanged() {
  let val = $('#resource_name').val();
  let list = Object.keys(resources[val]);
  populateDropdown('resource_view', list);
  viewChanged();
}

/**
 * viewChanged ...
 */
function viewChanged() {
  let val = $('#resource_view').val();
  let list = resources[$('#resource_name').val()][val];
  populateDropdown('resource_role', list.roles);
  populateDropdown('resource_interface', list.interfaces);
}

/**
 * resourceListChanged handles resource list update
 */
function resourceListChanged() {
  let txt = $('#resources').val();
  if (txt.length > 0) {
    $('#auth-btn').removeClass('white').addClass('blue');
  } else {
    $('#auth-btn').removeClass('blue').addClass('white');
  }
}

/**
 * localDam changes dam url to localhost
 */
function localDam() {
  $('#dam_url').val('http://localhost:8081');
  populateResources();
}

/**
 * clearPage resets page
 */
function clearPage() {
  window.location.href = makeURL('_PATH_');
}

/**
 * add selected resource to request list
 */
function add() {
  // Decode resources for now as they are URI encoded when sent as part of
  // auth() request.
  let resURL = decodeURIComponent(makeURL(resourceURL));
  let resources = $('#resources').val();
  resources = resources ? resources + '\n' + resURL : resURL;
  $('#resources').val(resources);
  $('#auth-btn').removeClass('white').addClass('blue');
  clearError();
}

/**
 * populateCartTable information to page
 * @param {!object} cart
 */
function populateCartTable(cart) {
  let html = '<tr><th>Resource</th><th>Paths</th><th>Permissions</th></tr>';
  browsePaths = [];
  for (let name in cart.resources) {
    let res = cart.resources[name];
    // Don't generate clickable url if cart responses other access credentials.
    let hasAccessToken = false;
    let cred = cart.access[res.access];
    if (cred && cred.credentials.access_token) {
      hasAccessToken = true;
    }
    let paths = [];
    for (let interName in res.interfaces) {
      let list = res.interfaces[interName].items;
      for (let idx = 0; idx < list.length; idx++) {
        let inter = list[idx];
        let path = inter.uri;
        if (hasAccessToken && interName == 'http:gcp:gs') {
          let num = browsePaths.length;
          browsePaths.push(
              {url: path, labels: inter.labels, access: res.access});
          path = `<span class="browse" onclick="browseDataset(${num})">${
              escapeHTML(path)}</span>`;
        }
        else {
          path = escapeHTML(path);
        }
        paths.push(path);
      }
    }
    html += `<tr><td>${escapeHTML(name)}</td><td>${paths.join(', ')}</td><td>${
        escapeHTML(res.permissions.join(', '))}</td></tr>`;
  }
  $('#cart_table').html(html);
}

let entityMap = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  '\'': '&#39;',
  '/': '&#x2F;',
  '`': '&#x60;',
  '=': '&#x3D;'
};

/**
 * escapeHTML ...
 * @param {string} string
 * @return {string}
 */
function escapeHTML(string) {
  return String(string).replace(/[&<>"'`=\/]/g, function(s) {
    return entityMap[s];
  });
}

/**
 * browseDataset ...
 * @param {number} index
 */
function browseDataset(index) {
  let entry = browsePaths[index];
  let creds =
      cart.access[entry.access] && cart.access[entry.access].credentials;
  if (!creds) {
    displayError(
        'missing credentials', '',
        JSON.stringify(cart.access[entry.access], undefined, 2));
    return;
  }
  let token = creds.access_token;
  let url = entry.url.length ? entry.url + '/o/' +
          '?access_token=' + token :
                               '';
  if (!url) {
    return;
  }
  $.ajax({
    url: url,
    type: 'GET',
    success: function(resp) {
      displaySuccess(JSON.stringify(resp, undefined, 2));
    },
    error: function(err) {
      displayError(
          'browse request failed', '', JSON.stringify(err, undefined, 2));
    }
  });
}

/**
 * apiAjax
 * @param {string} method
 * @param {string} payload
 * @param {string} outputId
 */
function apiAjax(method, payload, outputId) {
  let tok = $('#token').text();
  if (!tok) {
    displayError('must login first...');
    return;
  }
  let path = $(`#api_path`).val() || "";
  let url = path.startsWith("/")
      ? makeURL(apiAbsolutePathURL) : makeURL(apiRelativePathURL);
  $.ajax({
    url: url,
    type: method,
    beforeSend: function(xhr) {
      xhr.setRequestHeader('Authorization', 'Bearer ' + tok);
    },
    contentType: "application/json",
    data: payload || "",
    success: function(resp) {
      var json = JSON.stringify(resp, undefined, 2);
      displaySuccess(json);
      if (outputId) {
        document.getElementById(outputId).value = cfg;
      }
    },
    error: function(err) {
      displayError(
          'API endpoint failed', path, JSON.stringify(err, undefined, 2));
    }
  });
}

/**
 * API GET
 */
function apiGet() {
  apiAjax("GET");
}

/**
 * API Modify
 * @param {string} method : optional (default "POST")
 */
function apiModify(method) {
  method = method || "POST";
  let payload = document.getElementById('api_payload').value.trim();
  if (!payload) {
    displayError("must first fill out data payload");
    return;
  }
  let realm = $('#realm').val() || 'master';
  if (realm == 'master') {
    displayError("posting changes to the 'master' realm not supported");
    return;
  }
  // sets the outputId to the payload area to make it easier to reuse.
  apiAjax(method, payload, "api_payload");
}

/**
 * API PUT
 */
function apiPut() {
  apiModify("PUT");
}

/**
 * API PATCH
 */
function apiPatch() {
  apiModify("PATCH");
}

/**
 * API DELETE
 */
function apiDelete() {
  apiAjax("DELETE");
}

/**
 * reveal element
 * @param {element!} elem
 */
function reveal(elem) {
  $(elem).parent().addClass('reveal');
  $(elem).hide();
}

/**
 * debugJWT open token in jwt
 * @param {string} selector
 */
function debugJWT(selector) {
  let token = $(selector).text();
  window.open('https://jwt.io/#debugger-io?token=' + token);
}

/**
 * initPage ...
 */
function initPage() {
  let code = winParams.get('code');
  if (code) {
    $('#auth_code').text(code);
    $('#auth_code_div').addClass('available');
  }
  populateResources();
  let error = winParams.get('error');
  if (error) {
    displayError(
        error, winParams.get('error_description'), winParams.get('error_hint'));
  }
  if (validateState(winParams.get('state'))) {
    code && tokenExchange();
    window.history.replaceState({}, document.title, makeURL('_PATH_'));
  }
  resourceListChanged();
  let dam = winParams.get('dam_url');
  if (dam) {
    $('#dam_url').val(dam);
    $('#hydra_url').val(dam);
  }
  let loginType = winParams.get('login_type');
  if (loginType) {
    $('#token_type').val(loginType);
  }
  let realm = winParams.get('realm');
  if (realm) {
    $('#realm').val(realm);
  }
}

/**
 * init page and register event handlers.
 */
function init() {
  initPage();

  // register events
  document.getElementById('dam_url').onchange = populateResources;
  document.getElementById('resource_name').onchange = resourceChanged;
  document.getElementById('resource_view').onchange = viewChanged;
  document.getElementById('resources').onpaste = resourceListChanged;
  document.getElementById('resources').onkeyup = resourceListChanged;
  document.getElementById('add').onclick = add;
  document.getElementById('local-dam').onclick = localDam;
  document.getElementById('clear-page').onclick = clearPage;
  document.getElementById('auth-btn').onclick = auth;
  document.getElementById('reveal-authcode').onclick = () => {
    reveal(document.getElementById('reveal-authcode'));
  };
  document.getElementById('reveal-accesstoken').onclick = () => {
    reveal(document.getElementById('reveal-accesstoken'));
  };
  document.getElementById('debug-jwt').onclick = () => {
    debugJWT('#token');
  };
  document.getElementById('cart-btn').onclick = cartTokens;
  document.getElementById('refresh').onclick = refresh;
  document.getElementById("account-info").onclick = accountInfo;

  document.getElementById("api-get").onclick = apiGet;
  document.getElementById("api-post").onclick = apiModify;  // default: POST
  document.getElementById("api-put").onclick = apiPut;
  document.getElementById("api-patch").onclick = apiPatch;
  document.getElementById("api-delete").onclick = apiDelete;
  $(`.more-btn`).click(function(e) {
    let toggle = $(e.delegateTarget).attr("data-toggle");
    let hide = $(`#${toggle}`).toggleClass("hidden").hasClass("hidden");
    let arrow = hide ? '\u25B2' : '\u25BC';
    $(e.delegateTarget).children(`.arrow`).text(arrow);
  });
  document.getElementById("error_close").onclick = clearError;
}

window.onload = init;
