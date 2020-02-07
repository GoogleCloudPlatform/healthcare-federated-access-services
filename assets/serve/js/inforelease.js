/**
 * @fileoverview Description of this file.
 */

/**
 * onInit ...
 * @param {string} lst
 */
function onInit(lst) {
  let ul = document.getElementById('list');
  for (let i of lst) {
    let li = document.createElement('li');
    li.appendChild(document.createTextNode(i));
    ul.appendChild(li);
  }
}

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
