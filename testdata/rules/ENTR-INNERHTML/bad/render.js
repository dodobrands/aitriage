function render(list, items) {
  list.innerHTML = "";
  // ruleid: ENTR-INNERHTML
  list.innerHTML = items.map((i) => `<li>${i.name}</li>`).join("");
}
