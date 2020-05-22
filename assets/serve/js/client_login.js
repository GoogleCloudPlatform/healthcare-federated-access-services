/*
 * Copyright 2019 Google LLC
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

let state = {};
let steps = [];
let step = 0;

/**
 * onInit ...
 * @param {string} instructions
 */
function onInit(instructions) {
  if (instructions) {
    followInstructions();
    return;
  }
  let accessTok = getParam('access_token') || '';
  let idTok = getParam('id_token') || '';
  finishRedirect(accessTok, idTok);
}

/**
 * followInstructions ...
 */
function followInstructions() {
  let parts = instructions.split('|');
  for (let i = 0; i < parts.length; i++) {
    let part = parts[i];
    let idx = part.indexOf('=');
    let name = part.substring(0, idx);
    let url = part.substring(idx + 1);
    steps.push({name: name, url: url});
  }
  resolve();
}

/**
 * resolve ...
 */
function resolve() {
  let url = steps[step].url;
  for (let name in state) {
    // Replace all using split and join.
    url = url.split('$[' + name + ']').join(state[name]);
  }
  let type = 'GET';
  if (url.startsWith('POST@')) {
    url = url.substring(5);
    type = 'POST';
  }
  $.ajax({
    url: url,
    type: type,
    xhrFields: {withCredentials: true},
    success: function(resp) {
      let name = steps[step].name;
      state[name] = resp;
      step++;
      if (step >= steps.length) {
        return finishInstructions();
      }
      resolve();
    },
    error: function(err) {
      $('#output').text(JSON.stringify(err, undefined, 2));
    }
  });
}

/**
 * finishInstructions ...
 * @return {string}
 */
function finishInstructions() {
  let idTok = state['ID_TOKEN'] || state['id_token'] || '';
  let accessTok = state['ACCESS_TOKEN'] || state['access_token'] || '';
  if (!accessTok) {
    $('#output').text(
        'ERROR: invalid sequence of steps (does not define ACCESS_TOKEN)');
    return false;
  }
  return finishRedirect(accessTok, idTok);
}

/**
 * finishRedirect ...
 * @param {string} accessTok
 * @param {string} idTok
 * @return {string}
 */
function finishRedirect(accessTok, idTok) {
  let clientId = getParam('client_id');
  let state = getParam('state');
  let scope = getParam('scope');
  let redirect = getParam('redirect_uri');
  let error = getParam('error');
  let errDesc = getParam('error_description');
  let url =
      [location.protocol, '//', location.host, location.pathname].join('');
  // TODO: don't pass pararameters as URL parameters.
  url += '?client_extract=true&state=' + encodeURIComponent(state) +
      '&scope=' + encodeURIComponent(scope) +
      '&redirect_uri=' + encodeURIComponent(redirect) +
      '&client_id=' + encodeURIComponent(clientId) +
      '&id_token=' + encodeURIComponent(idTok) +
      '&access_token=' + encodeURIComponent(accessTok);
  if (error) {
    url += '&error=' + encodeURIComponent(error) +
        '&error_description=' + encodeURIComponent(errDesc);
  }
  window.location.href = url;
  return true;
}

/**
 * getParam ...
 * @param {string} name
 * @return {string}
 */
function getParam(name) {
  return getUrlParam(name, window.location.search.substring(1)) ||
      getUrlParam(name, window.location.hash.substr(1));
}

/**
 * getUrlParam ...
 * @param {string} name
 * @param {string} url
 * @return {string}
 */
function getUrlParam(name, url) {
  let lets = url.split('&');
  for (let i = 0; i < lets.length; i++) {
    let param = lets[i].split('=');
    if (param[0] == name) {
      return decodeURIComponent(param[1].replace(/\+/g, ' '));
    }
  }
  return '';
}

/**
 * init reads the given instructions from "instructions" element
 */
function init() {
  let instructions = document.getElementById("instructions").dataset.instructions;
  onInit(instructions);
}

window.onload = init;
