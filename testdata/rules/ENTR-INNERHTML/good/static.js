function reset(list, tbody, el, hero) {
  list.innerHTML = "";
  tbody.innerHTML = '<tr><td colspan="7">No activity found.</td></tr>';
  if (el.innerHTML == "") {
    el.innerHTML += "<br>";
  }
  hero.innerHTML = `
    <h1>Welcome</h1>
    <p>Static copy only.</p>
  `;
}
