/**
 * @fileoverview Description of this file.
 */

/**
 * agree ...
 * @param {string} state
 * @param {string} path
 * @param {string} yes
 */
function agree(state, path, yes) {
  var url = [location.protocol, '//', location.host, path].join('');
  url += '?state=' + encodeURIComponent(state) +
      '&agree=' + encodeURIComponent(yes ? 'y' : 'n');
  window.location.href = url;
}
