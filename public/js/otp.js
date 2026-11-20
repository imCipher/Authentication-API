// ---------- 1. Turn the single code input into 6 boxes ----------
const real = document.getElementById("token");
const realField = document.getElementById("token-field");

if (real && realField) {
  const LENGTH = 6;

  const group = document.createElement("div");
  group.className = "otp";
  group.setAttribute("role", "group");
  group.setAttribute("aria-label", "Verification code");

  const boxes = Array.from({ length: LENGTH }, (_, i) => {
    const box = document.createElement("input");
    box.type = "text";
    box.inputMode = "numeric";
    box.className = "otp__box";
    box.setAttribute("aria-label", `Digit ${i + 1} of ${LENGTH}`);
    box.autocomplete = i === 0 ? "one-time-code" : "off"; // phone autofill lands in box 1
    group.append(box);
    return box;
  });

  realField.hidden = true; // hide the original input + label (it still gets submitted)
  realField.after(group);

  // copy the boxes into the real input that the form actually submits
  const sync = () => {
    real.value = boxes.map(b => b.value).join("");
  };

  boxes.forEach((box, i) => {
    box.addEventListener("input", () => {
      const digits = box.value.replace(/\D/g, ""); // keep numbers only

      if (digits.length > 1) {
        // paste or phone autofill: spread the digits across the boxes from here
        digits
          .slice(0, LENGTH - i)
          .split("")
          .forEach((d, j) => {
            boxes[i + j].value = d;
          });
        boxes[Math.min(i + digits.length, LENGTH) - 1].focus();
      } else {
        box.value = digits;
        if (digits && i < LENGTH - 1) boxes[i + 1].focus(); // jump to next box
      }
      sync();
    });

    box.addEventListener("keydown", e => {
      if (e.key === "Backspace" && !box.value && i > 0) {
        e.preventDefault();
        boxes[i - 1].value = "";
        boxes[i - 1].focus(); // backspace on an empty box goes back
        sync();
      }
      if (e.key === "ArrowLeft" && i > 0) boxes[i - 1].focus();
      if (e.key === "ArrowRight" && i < LENGTH - 1) boxes[i + 1].focus();
    });

    box.addEventListener("focus", () => box.select()); // typing replaces the digit
  });

  boxes[0].focus();
}

// ---------- 2. Resend countdown ----------
const resend = document.querySelector("[data-resend]");

if (resend) {
  const label = resend.textContent;
  let left = Number(resend.dataset.cooldown) || 60;

  const tick = () => {
    if (left <= 0) {
      resend.disabled = false;
      resend.textContent = label;
      return;
    }
    resend.disabled = true;
    resend.textContent = `Resend code in ${left}s`;
    left -= 1;
    setTimeout(tick, 1000);
  };
  tick();
}
