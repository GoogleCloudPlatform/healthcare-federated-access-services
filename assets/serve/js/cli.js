/**
 * @fileoverview Description of this file.
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
