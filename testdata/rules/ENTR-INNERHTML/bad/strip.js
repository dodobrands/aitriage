function stripHtml(html) {
  const tmp = document.createElement("div");
  // ruleid: ENTR-INNERHTML
  tmp.innerHTML = html;
  return tmp.textContent;
}
