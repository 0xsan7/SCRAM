const footer = document.querySelector('.shutter-footer');
const shutter = footer.querySelector('.footer-shutter');
const letter = shutter.previousElementSibling;
const blades = letter.querySelector('.shutter-blades');
const motion = matchMedia('(prefers-reduced-motion: reduce)');

function setPivot(x, y) {
  const shapes = [
    `0 0 21 0 ${x} ${y} 0 21`,
    `${x} 0 100 0 100 21 ${x} ${y}`,
    `0 ${y} ${x} ${y} 21 100 0 100`,
  ];
  for (const [i, blade] of [...blades.children].entries()) {
    blade.setAttribute('points', shapes[i]);
  }
}

let turns = 0;
let nudge;
shutter.hidden = false;
shutter.addEventListener('click', () => {
  turns = (turns + 1) % 4;
  setPivot(77, 77);
  blades.setAttribute('transform', `rotate(${turns * 90} 50 50)`);
  if (motion.matches) return;
  nudge?.cancel();
  nudge = letter.animate([
    { transform: 'none' },
    { transform: 'translateY(-5%) rotate(-6deg)' },
    { transform: 'translateY(1%) rotate(2deg)' },
    { transform: 'none' },
  ], { duration: 420, easing: 'ease-out' });
});
shutter.addEventListener('pointermove', event => {
  if (motion.matches || event.pointerType === 'touch') return;
  const cell = shutter.getBoundingClientRect();
  const horizontal = (event.clientX - cell.left) / cell.width;
  const vertical = (event.clientY - cell.top) / cell.height;
  letter.style.translate = `${(horizontal - .5) * 8}% ${(vertical - .5) * 8}%`;
  letter.style.rotate = `${(horizontal - .5) * 15}deg`;

  // Map the pointer into the inset, then undo the blades’ quarter turn.
  let x = horizontal * 100;
  let y = vertical * 100;
  for (let i = 0; i < turns; i++) [x, y] = [y, 100 - x];
  const inset = value => Math.round(Math.min(89, Math.max(14, value)));
  setPivot(inset(x), inset(y));
});
function resetLetter() {
  letter.style.removeProperty('translate');
  letter.style.removeProperty('rotate');
  setPivot(77, 77);
}
shutter.addEventListener('pointerleave', resetLetter);
motion.addEventListener('change', () => {
  nudge?.cancel();
  resetLetter();
});

const noise = 'ABCDEFGHJKLMNPQRSTUVWXYZ0123456789';
for (const link of footer.querySelectorAll('.footer-link')) {
  const label = link.querySelector('.footer-link-label');
  const text = label.textContent;
  let frame;
  const restore = () => {
    cancelAnimationFrame(frame);
    label.textContent = text;
  };
  link.addEventListener('pointerenter', event => {
    if (motion.matches || event.pointerType !== 'mouse') return;
    const start = performance.now();
    const tick = now => {
      const progress = Math.min(1, (now - start) / 200);
      label.textContent = Array.from(text, (char, i) => {
        if (i < text.length * progress || !/[a-z]/i.test(char)) return char;
        return noise[(i * 11 + Math.floor(progress * 9)) % noise.length];
      }).join('');
      if (progress < 1 && !motion.matches) frame = requestAnimationFrame(tick);
      else restore();
    };
    frame = requestAnimationFrame(tick);
  });
  link.addEventListener('pointerleave', restore);
  link.addEventListener('focus', restore);
}
