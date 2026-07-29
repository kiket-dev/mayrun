(() => {
  const buttons = document.querySelectorAll(".copy[data-copy]");

  for (const button of buttons) {
    button.addEventListener("click", async () => {
      const text = button.getAttribute("data-copy");
      if (!text) return;

      try {
        await navigator.clipboard.writeText(text);
        button.dataset.copied = "true";
        button.textContent = "Copied";
        window.setTimeout(() => {
          button.dataset.copied = "false";
          button.textContent = "Copy";
        }, 1600);
      } catch {
        button.textContent = "Failed";
        window.setTimeout(() => {
          button.textContent = "Copy";
        }, 1600);
      }
    });
  }
})();
