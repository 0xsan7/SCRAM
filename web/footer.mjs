const footer = document.querySelector('.shutter-footer');
const shutter = footer.querySelector('.footer-shutter');
const blades = shutter.parentElement.querySelector('.shutter-blades');
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
shutter.hidden = false;
shutter.addEventListener('click', () => {
  turns = (turns + 1) % 4;
  setPivot(77, 77);
  blades.setAttribute('transform', `rotate(${turns * 90} 50 50)`);
});
shutter.addEventListener('pointermove', event => {
  if (motion.matches || event.pointerType === 'touch') return;
  const matrix = blades.getScreenCTM();
  if (!matrix) return;
  const cell = shutter.getBoundingClientRect();
  const opening = blades.ownerSVGElement.getBoundingClientRect();
  const px = opening.left + (event.clientX - cell.left) / cell.width * opening.width;
  const py = opening.top + (event.clientY - cell.top) / cell.height * opening.height;
  const { x, y } = new DOMPoint(px, py).matrixTransform(matrix.inverse());
  const inset = value => Math.round(Math.min(89, Math.max(14, value)));
  setPivot(inset(x), inset(y));
});
shutter.addEventListener('pointerleave', () => setPivot(77, 77));
motion.addEventListener('change', () => setPivot(77, 77));

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
