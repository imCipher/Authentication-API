// Hold-to-reveal for EVERY password field on the page.
// Each .field-password gets its own input/button/icon, found INSIDE that field.
document.querySelectorAll(".field-password").forEach(field => {
  const input = field.querySelector("input");
  const toggle = field.querySelector(".field-password__toggle");
  if (!input || !toggle) return;
  const icon = toggle.querySelector("img");

  const show = () => {
    input.type = "text";
    if (icon) icon.src = "/images/eye-open.svg";
  };
  const hide = () => {
    input.type = "password";
    if (icon) icon.src = "/images/eye-closed.svg";
  };

  // mouse / touch / pen
  toggle.addEventListener("pointerdown", e => {
    e.preventDefault();
    toggle.setPointerCapture(e.pointerId);
    show();
  });
  toggle.addEventListener("pointerup", hide);
  toggle.addEventListener("pointercancel", hide);

  // keyboard: hold Space or Enter
  toggle.addEventListener("keydown", e => {
    if (e.code === "Space" || e.code === "Enter") {
      e.preventDefault();
      show();
    }
  });
  toggle.addEventListener("keyup", hide);
  toggle.addEventListener("blur", hide);

  // no long-press menu on phones
  toggle.addEventListener("contextmenu", e => e.preventDefault());
});
