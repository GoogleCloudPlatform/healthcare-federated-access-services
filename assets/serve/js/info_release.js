/**
 * @fileoverview Description of this file.
 */


/**
 * changeSelectAny handles checkbox #select-anything state change.
 * disables all autoselected checkbox when checked #select-anything
 */
function changeSelectAnything() {
  let e = document.getElementById("select-anything");
  let cbs = document.querySelectorAll(".autoselected");
  for (i = 0; i < cbs.length; ++i) {
    cbs[i].disabled = e.checked;
  }
}
