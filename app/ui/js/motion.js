// @ts-check
// Spring motion without a library: Framer Motion's default spring (stiffness 300, damping 24) is simulated once and
// handed to CSS as a linear() easing in --spring, so every transition and animation in app.css can use it. Browsers
// without linear() keep the overshoot curve app.css defines. Loaded as a plain script in <head>, before first paint.
(function () {
  /** Sampled position of a damped spring going from 0 to 1. @param {number} stiffness @param {number} damping */
  function spring(stiffness, damping) {
    const w0 = Math.sqrt(stiffness), zeta = damping / (2 * Math.sqrt(stiffness));
    const wd = w0 * Math.sqrt(Math.max(1 - zeta * zeta, 1e-6));
    const points = [];
    for (let i = 0; i <= 48; i++) {
      const t = (i / 48) * 1.1;                                         // seconds of simulated time
      const x = zeta < 1
        ? 1 - Math.exp(-zeta * w0 * t) * (Math.cos(wd * t) + (zeta * w0 / wd) * Math.sin(wd * t))
        : 1 - Math.exp(-w0 * t) * (1 + w0 * t);
      points.push(i === 48 ? '1' : x.toFixed(4));
    }
    return 'linear(' + points.join(', ') + ')';
  }
  try {
    if (window.CSS && CSS.supports('transition-timing-function', 'linear(0, 1)')) {
      document.documentElement.style.setProperty('--spring', spring(300, 24));
    }
  } catch (e) { /* keep the fallback curve */ }
})();
