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

/**
 * onInit
 */
function onInit() {
  var err = getParam('error');
  var desc = getParam('error_description');
  var hint = getParam('error_hint');
  if (err || desc || hint) {
    $('#error').text(err.replace(/_/g, ' '));
    $('#desc').text(desc);
    $('#hint').text(hint);
    $('#fail').removeClass('hidden');
    return;
  }
  $('#success').removeClass('hidden');
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
  var vars = url.split('&');
  for (var i = 0; i < vars.length; i++) {
    var param = vars[i].split('=');
    if (param[0] == name) {
      // Hydra sometimes double-escapes % strings (e.g. "%2528" -> "%28")
      var p =
          param[1].replace(/\+/g, ' ').replace(/%25([0-9A-F][0-9A-F])/g, '%$1');
      return decodeURIComponent(p);
    }
  }
  return '';
}
