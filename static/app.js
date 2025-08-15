document.addEventListener("click", (e)=>{
  const btn = e.target.closest(".pw-toggle");
  if(!btn) return;
  const id = btn.getAttribute("data-target");
  const input = document.getElementById(id);
  if(!input) return;
  input.type = input.type === "password" ? "text" : "password";
  btn.textContent = input.type === "password" ? "👁" : "🙈";
});
