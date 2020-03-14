/**
 * @fileoverview Description of this file.
 */

/**
 * onInit ...
 * @param {string} providers a list of providers.
 */
function onInit(providers) {
  if (!providers) return;
  providers.idps && populateProviderHtml('idps', providers.idps);
  if (providers.personas && Object.keys(providers.personas).length > 0) {
    populateProviderHtml('personas', providers.personas);
    $('.playground').removeClass('hide');
  }
}

/**
 * populateProviderHtml ...
 * @param {string} id
 * @param {string} items
 */
function populateProviderHtml(id, items) {
  var html = '';

  html += getProviderHeaderHtml(id, html);
  html += getProviderActionsHtml(items, html);

  $('#providers-container').append(html);
}

/**
 * getProviderHeaderHtml ...
 * @param {string} id
 * @return {string}
 */
function getProviderHeaderHtml(id) {
  if (id === 'idps') {
    $('#main-container').removeClass('persona');
    return '<h4>Log in or Create an account</h4><p>Verify your identity to discover and access data.</p>';
  } else if (id === 'personas') {
    $('#main-container').addClass('persona');
    return '<h4 class="playground">Testing personas</h4><p class="playground">Log in using one of these existing testing personas.</p>';
  }
}

/**
 * getProviderActionsHtml ...
 * @param {string} items
 * @return {string}
 */
function getProviderActionsHtml(items) {
  var names = Object.keys(items);
  names.sort();
  var html = '';
  for (var i = 0; i < names.length; i++) {
    var name = names[i];
    var item = items[name];
    var label = (item.ui && item.ui.label) || name;
    var iconUrl = (item.ui && item.ui.iconUrl) || null;
    html += getProviderCardHtml(item.url, name, label, iconUrl);
  }
  return html;
}

/**
 * getProviderCardHtml ...
 * @param {string} url
 * @param {string} name
 * @param {string} label
 * @param {string} iconUrl
 * @return {string}
 */
function getProviderCardHtml(url, name, label, iconUrl) {
  var cardClass = 'mdl-card mdl-shadow--2dp';
  if (iconUrl) {
    return `<a class="${escapeHtml(cardClass)}" href="${encodeURI(url)}">` +
        `<div class="mdl-card__title flex vertical-center"><img src="${
               encodeURI(iconUrl)}" alt="Icon"/>${escapeHtml(label)}</div>` +
        '</a>';
  }
  return `<a class="${escapeHtml(cardClass)} no-image" href="${
             encodeURI(url)}">` +
      `<div class="mdl-card__title flex vertical-center">${
             escapeHtml(label)}</div>` +
      '</a>';
}

/**
 * escapeHtml ...
 * @param {string} unsafe
 * @return {string}
 */
function escapeHtml(unsafe) {
  return unsafe.replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
}
