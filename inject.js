/* Sentinel SOC · page-world sensor (runs in the page's own JS context)
 * Detects canvas fingerprinting: text drawn to a canvas followed by a pixel
 * read-back (toDataURL / getImageData) is the classic fingerprinting pattern.
 * Reports once per page via window.postMessage to the content script.
 */
'use strict';

(function () {
  if (window.__sentinelInjected) return;
  window.__sentinelInjected = true;

  let reported = false;
  function report(detail) {
    if (reported) return;
    reported = true;
    window.postMessage({ source: 'sentinel-inject', detail }, '*');
  }

  try {
    const CanvasProto = window.HTMLCanvasElement && window.HTMLCanvasElement.prototype;
    const CtxProto = window.CanvasRenderingContext2D && window.CanvasRenderingContext2D.prototype;
    if (!CanvasProto || !CtxProto) return;

    const origFillText = CtxProto.fillText;
    const origStrokeText = CtxProto.strokeText;
    CtxProto.fillText = function (...args) {
      try { if (this.canvas) this.canvas.__sentinelText = true; } catch (e) {}
      return origFillText.apply(this, args);
    };
    CtxProto.strokeText = function (...args) {
      try { if (this.canvas) this.canvas.__sentinelText = true; } catch (e) {}
      return origStrokeText.apply(this, args);
    };

    const origToDataURL = CanvasProto.toDataURL;
    CanvasProto.toDataURL = function (...args) {
      try {
        if (this.__sentinelText || (this.width * this.height > 10000 && this.width < 300)) {
          report('Canvas read-back (toDataURL) after text rendering or on a small hidden canvas — classic fingerprinting pattern.');
        }
      } catch (e) {}
      return origToDataURL.apply(this, args);
    };

    const origGetImageData = CtxProto.getImageData;
    CtxProto.getImageData = function (...args) {
      try {
        if (this.canvas && this.canvas.__sentinelText) {
          report('Canvas pixel read-back (getImageData) after text rendering — classic fingerprinting pattern.');
        }
      } catch (e) {}
      return origGetImageData.apply(this, args);
    };
  } catch (e) { /* never break the page */ }
})();
