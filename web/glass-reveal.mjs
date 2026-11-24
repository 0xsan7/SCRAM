// Optical shader and spring timeline adapted from the supplied Liquid Glass
// Logo Reveal component, based on Zanwei Guo’s glass-icon-reveal (MIT).
// See assets/glass-icon-reveal-LICENSE.txt for the license.
const TEX = 512;
const BOX = 0.75;
const LIGHT = {
    tileSize: 256,
    logoScale: 0.7,
    finalScale: 0.69,
    logoOffset: [
        0,
        0
    ],
    iconPlate: false,
    keepPlate: false,
    originalColors: false,
    opticalDepth: 1.1,
    dispersion: 1.7,
    colorBleed: 1.25,
    doubleBevel: 1,
    bevelWidth: 0.14,
    corner: 4.8,
    cornerPull: 2.1,
    cornerWidth: 2.2,
    cornerFocus: 0.58,
    edgeSmear: 2.85,
    stretch: 0,
    tilt: 0.35,
    bulge: 1,
    specular: 1,
    halo: 0,
    shadow: 1,
    ripple: 1,
    bounce: 0,
    response: 0.42,
    startSize: 0.2,
    startZoom: 2.6,
    glide: 2.3,
    present: 2.4,
    drift: 0.12,
    swell: 0.5,
    focus: 1,
    sheen: 1,
    lightTurn: 0.9,
    hold: 1,
    background: "#e9e9eb",
    plateColor: "#ffffff",
    logoColor: "#0e1428"
};
function fitToTexture(source, sw, sh) {
    const tmp = document.createElement("canvas");
    tmp.width = tmp.height = TEX;
    const tc = tmp.getContext("2d", {
        willReadFrequently: true
    });
    const s0 = Math.min(TEX / sw, TEX / sh);
    const dx0 = (TEX - sw * s0) / 2;
    const dy0 = (TEX - sh * s0) / 2;
    tc.drawImage(source, dx0, dy0, sw * s0, sh * s0);
    const d = tc.getImageData(0, 0, TEX, TEX).data;
    let opaque = true;
    for(let i = 3; i < d.length; i += 4 * 97)if (d[i] < 250) {
        opaque = false;
        break;
    }
    const key = [
        d[0],
        d[1],
        d[2]
    ];
    const keyAlpha = (r, g, b)=>Math.min(1, Math.max(0, (Math.hypot(r - key[0], g - key[1], b - key[2]) / 441 - 0.08) / 0.2));
    let x0 = TEX, y0 = TEX, x1 = -1, y1 = -1;
    for(let y = 0; y < TEX; y++){
        for(let x = 0; x < TEX; x++){
            const i = (y * TEX + x) * 4;
            const a = opaque ? keyAlpha(d[i], d[i + 1], d[i + 2]) * 255 : d[i + 3];
            if (a > 8) {
                if (x < x0) x0 = x;
                if (x > x1) x1 = x;
                if (y < y0) y0 = y;
                if (y > y1) y1 = y;
            }
        }
    }
    if (x1 < 0) throw new Error("GlassIconReveal: the logo is empty");
    const bw = x1 - x0 + 1;
    const bh = y1 - y0 + 1;
    const s = TEX * BOX / Math.max(bw, bh);
    const out = document.createElement("canvas");
    out.width = out.height = TEX;
    const oc = out.getContext("2d", {
        willReadFrequently: true
    });
    oc.imageSmoothingQuality = "high";
    oc.drawImage(source, TEX / 2 - (x0 + bw / 2 - dx0) * s, TEX / 2 - (y0 + bh / 2 - dy0) * s, sw * s0 * s, sh * s0 * s);
    if (opaque) {
        const im = oc.getImageData(0, 0, TEX, TEX);
        const e = im.data;
        for(let i = 0; i < e.length; i += 4)e[i + 3] = Math.round(e[i + 3] * keyAlpha(e[i], e[i + 1], e[i + 2]));
        oc.putImageData(im, 0, 0);
    }
    return out;
}
function buildSdf(canvas) {
    const n = TEX * TEX;
    const alpha = canvas.getContext("2d", {
        willReadFrequently: true
    }).getImageData(0, 0, TEX, TEX).data;
    const INF = 1e20;
    const outer = new Float64Array(n);
    const inner = new Float64Array(n);
    for(let i = 0; i < n; i++){
        const a = alpha[i * 4 + 3] / 255;
        if (a >= 1) {
            outer[i] = 0;
            inner[i] = INF;
        } else if (a <= 0) {
            outer[i] = INF;
            inner[i] = 0;
        } else {
            const dd = 0.5 - a;
            outer[i] = dd > 0 ? dd * dd : 0;
            inner[i] = dd < 0 ? dd * dd : 0;
        }
    }
    const f = new Float64Array(TEX);
    const z = new Float64Array(TEX + 1);
    const v = new Uint16Array(TEX);
    edt(outer, f, v, z, INF);
    edt(inner, f, v, z, INF);
    const sdf = new Float32Array(n);
    for(let i = 0; i < n; i++)sdf[i] = (Math.sqrt(outer[i]) - Math.sqrt(inner[i])) / TEX;
    return sdf;
}
function edt(grid, f, v, z, INF) {
    for(let x = 0; x < TEX; x++)edt1d(grid, x, TEX, f, v, z, INF);
    for(let y = 0; y < TEX; y++)edt1d(grid, y * TEX, 1, f, v, z, INF);
}
function edt1d(grid, offset, stride, f, v, z, INF) {
    v[0] = 0;
    z[0] = -INF;
    z[1] = INF;
    f[0] = grid[offset];
    for(let q = 1, k = 0, s = 0; q < TEX; q++){
        f[q] = grid[offset + q * stride];
        const q2 = q * q;
        do {
            const r = v[k];
            s = (f[q] - f[r] + q2 - r * r) / (q - r) / 2;
        }while (s <= z[k] && --k > -1)
        k++;
        v[k] = q;
        z[k] = s;
        z[k + 1] = INF;
    }
    for(let q = 0, k = 0; q < TEX; q++){
        while(z[k + 1] < q)k++;
        const r = v[k];
        const qr = q - r;
        grid[offset + q * stride] = f[r] + qr * qr;
    }
}
const VERT = `#version 300 es
in vec2 aPos;
void main() { gl_Position = vec4(aPos, 0.0, 1.0); }`;
const FRAG = `#version 300 es
precision highp float;
out vec4 outColor;

uniform vec2 uCenter;      // device px, GL coords
uniform float uTile;       // tile size, device px
uniform sampler2D uSdf;    // signed distance, texture units, + outside
uniform sampler2D uCol;    // premultiplied colour, mipmapped
uniform float uTexSize;
uniform float uBoxFrac;

uniform float uPlateScale; // plate size relative to the tile
uniform float uShapeN;     // superellipse exponent: 2 = circle
uniform float uCornerN;    // final exponent, used by the ghost
uniform float uOptics;     // 1 = full refraction, 0 = flat
uniform float uPlateAlpha; // 1 = glass shown, 0 = bare logo
uniform float uLogoHalf;   // logo half size in plate units (zoom included)
uniform vec2 uLogoOff;     // logo centre, plate units
uniform float uBold;       // stroke swell, in logo half-size units
uniform float uBlur;       // edge softness, plate units
uniform float uFrost;      // milky lift inside a young bubble
uniform float uDome;       // lens bulge height
uniform float uDrop;       // 1 while the glass is a round droplet, 0 once it has spread into the tile
uniform float uPinch;      // the face's stretch toward its corners, at the rim
uniform float uTilt;       // extra stretch of the rising diagonal's corners (0–1)
uniform float uRim;
uniform float uHalo;
uniform float uShadow;
uniform float uGhost;
uniform float uRipR;       // ripple radius, plate sizes
uniform float uRipA;
uniform float uBare;       // 1 once the logo may show without glass (the ending)
uniform float uReach;      // the rim band's full width, plate units
uniform float uCornerPull; // how much harder the corners pull than the sides
uniform float uStreak;     // how far a corner smears content along the rim, in band widths
uniform float uWiden;      // how much wider the folding band grows toward the corners
uniform float uSlab;       // how far the slab stands above the logo, plate units
uniform float uEtaSpread;  // index spread across the spectrum (red highest)
uniform float uFocus;      // how far in along the diagonal a corner focuses, plate units
uniform float uFocusK;     // how quickly the view slides back from the focus across the band
uniform float uFocusSplit; // how much further in red meets than violet, plate units
uniform float uRimLine;    // how far across the band the sight line takes to turn in to the focus
uniform float uCornerOn;   // 0 while the glass is round, 1 once it has spread into the tile
uniform float uDissolve;   // 0 → 1 as the glass lets go of the logo
uniform float uGlow;       // colour bleed in the rim, plate units on screen
uniform float uFaceDisp;   // lateral colour across the face
uniform float uVivid;      // chroma lift of the dispersed light

uniform float uDisp;
uniform float uDouble;
uniform float uBevelW;
uniform float uSpec;
uniform float uIconPlate;
uniform float uUseColor;
uniform float uLightScene; // 1 = light backdrop, 0 = dark
uniform float uLightGlass; // the same for what the glass sits on (the plate, when there is one)
uniform float uKeep;       // 1 = the glass settles into a flat plate instead of letting go of it
uniform float uSheen;      // strength of the light band crossing the face
uniform float uSweep;      // where that band is, plate sizes along its diagonal
uniform float uLightAng;   // how far the rim light has turned, radians

uniform vec3 uBg;
uniform vec3 uPlateCol;
uniform vec3 uLogoCol;

float px; // one device pixel in plate units

vec2 rot(vec2 v, float a) { float c = cos(a), s = sin(a); return vec2(c * v.x - s * v.y, s * v.x + c * v.y); }

// aa: footprint of one screen pixel at q, plate units.
vec4 logoAt(vec2 q, float blur, float aa) {
  float L = uLogoHalf;
  float k = 0.5 * uBoxFrac / L;
  vec2 uv = vec2(0.5 + (q.x - uLogoOff.x) * k, 0.5 - (q.y - uLogoOff.y) * k);
  float d = texture(uSdf, uv).r / k;
  float w = 0.75 * aa + blur;
  float a = 1.0 - smoothstep(-w, w, d - uBold * L);
  vec3 c = uLogoCol;
  if (uUseColor > 0.5) {
    float lod = log2(max(1.0, w * k * uTexSize));
    vec4 c0 = textureLod(uCol, uv, lod);
    vec4 c1 = textureLod(uCol, uv, lod + 3.0);
    vec4 c2 = textureLod(uCol, uv, 7.0);
    c = c2.rgb / max(c2.a, 1e-4);
    c = mix(c, c1.rgb / max(c1.a, 1e-4), smoothstep(0.0, 0.06, c1.a));
    c = mix(c, c0.rgb / max(c0.a, 1e-4), smoothstep(0.02, 0.3, c0.a));
  }
  return vec4(c, a);
}

// Superellipse field. Returns signed distance (plate units, − inside); g = 1 on the rim.
float shape(vec2 p, float scale, float n, out vec2 nOut, out float g, out vec2 dg) {
  vec2 pp = p / scale;
  vec2 a = max(abs(pp), vec2(1e-6));
  g = pow(pow(a.x, n) + pow(a.y, n), 1.0 / n);
  dg = sign(pp) * pow(a, vec2(n - 1.0)) * pow(max(g, 1e-6), 1.0 - n);
  float dgl = max(length(dg), 1e-6);
  nOut = dg / dgl;
  return (g - 1.0) / dgl * scale;
}

// Curvature radius (plate units) of the shape's contour through p.
float contourRadius(vec2 p, float scale, float n) {
  vec2 a = max(abs(p / scale), vec2(1e-4));
  vec2 a1 = pow(a, vec2(n - 1.0));
  vec2 a2 = pow(a, vec2(n - 2.0));
  float k = (n - 1.0) * (a2.x * a1.y * a1.y + a2.y * a1.x * a1.x) / pow(max(dot(a1, a1), 1e-30), 1.5);
  return scale / max(k, 1e-3);
}

// Where the glass at x = s / bwF across its rounded edge looks: a slab uSlab above the logo with a
// quarter-round edge of radius bwF. A straight-down sight line bends inward by Snell's law, so the
// outer rim looks deepest and the view eases back to the face across the edge.
vec2 refractSample(float x, float bwF, float eta, float R, vec2 dirOut, vec2 p, float dome, float offMul) {
  float u = clamp(1.0 - x, 0.0, 0.995);
  float th = asin(u), thr = asin(u / eta);
  float z = uSlab + bwF * sqrt(1.0 - u * u);
  float off = offMul * z * tan(th - thr);
  off = off / (1.0 + off / (6.0 * R));
  return p - (dirOut * off + p * dome) * uOptics;
}

float gauss(float x, float c, float w) { float d = (x - c) / w; return exp(-0.5 * d * d); }
float band(float x, float a, float b, float w) { return smoothstep(a - w, a, x) * (1.0 - smoothstep(b, b + w, x)); }

// Visible spectrum, red (0) to violet (1).
float bump(float x, float c, float w) { float d = (x - c) / w; return exp(-0.5 * d * d); }
vec3 spectrum(float x) {
  return vec3(bump(x, 0.34, 0.2) + 0.08 * bump(x, 0.93, 0.05), bump(x, 0.58, 0.1), bump(x, 0.8, 0.11));
}

float hash(vec2 p) { return fract(sin(dot(p, vec2(12.9898, 78.233))) * 43758.5453); }

void main() {
  px = 2.0 / uTile;
  vec2 p = (gl_FragCoord.xy - uCenter) * px;

  vec4 lg = logoAt(p, uBlur, px);
  vec3 plain = mix(uBg, lg.rgb, lg.a * uBare);

  vec2 nOut, dg; float g;
  float sd = shape(p, uPlateScale, uShapeN, nOut, g, dg);
  float s = -sd;
  float bw = max(uBevelW, 0.004) * uPlateScale;
  float x = clamp(s / bw, 0.0, 1.0);
  float R = contourRadius(p, uPlateScale, uShapeN);
  vec2 pq = p * p;
  float diag = 4.0 * pq.x * pq.y / max((pq.x + pq.y) * (pq.x + pq.y), 1e-6);
  float tilt = mix(1.0 - uTilt, 1.0, smoothstep(-0.02, 0.02, p.x * p.y));
  float pinchPart = uPinch * min(g * g, 1.0) * diag * diag * tilt;
  float dome = uDome * (1.0 - min(g * g, 1.0)) + pinchPart;
  vec2 dirOut = normalize(mix(nOut, p / max(length(p), 1e-4), 0.2));
  // Rounded corners curve both ways, so they draw content in from deeper than the sides.
  float cornerness = max(smoothstep(0.1, 0.9, 4.0 * nOut.x * nOut.x * nOut.y * nOut.y), smoothstep(0.15, 0.75, diag));
  float offMul = 1.0 + 0.4 * max(uCornerPull - 1.0, 0.0) * tilt * cornerness * uCornerOn;
  // Around a corner every sight line meets at one focus a little way in along the diagonal.
  vec2 focus = sign(p) * (pow(0.5, 1.0 / uShapeN) - uFocus * 0.70710678) * uPlateScale;
  float focusW = tilt * cornerness * uOptics * uCornerOn;
  float bwF = max(uReach, 0.004) * (1.0 + uWiden * tilt * cornerness * uCornerOn);
  float xf = clamp(s / bwF, 0.0, 1.0);
  // Footprint of one pixel after refraction, measured in uniform control flow.
  vec2 qc = refractSample(xf, bwF, 1.5, R, dirOut, p, dome, offMul);
  float foot = max(max(length(dFdx(qc)), length(dFdy(qc))), 0.25 * px);

  // Backdrop: anticipation ghost, ripple, soft lift shadow and glow.
  vec3 bg = uBg;
  vec3 lift = mix(uBg + vec3(0.06), mix(uBg, vec3(1.0), 0.55), uLightScene);
  if (uGhost > 0.001) {
    vec2 gn, gdg; float gg;
    float gsd = shape(p, 1.0, uCornerN, gn, gg, gdg);
    bg = mix(bg, lift, uGhost * 0.12 * (1.0 - smoothstep(-0.16, 0.14, gsd)));
    bg *= 1.0 - uGhost * 0.03 * uLightScene * exp(-max(gsd, 0.0) / 0.12) * step(0.0, gsd);
  }
  float outside = max(sd, 0.0);
  if (uRipA > 0.001) {
    float d0 = (uRipR - 1.0) * uPlateScale;
    float rx = (sd - d0) / 0.022;
    float ring = exp(-rx * rx);
    bg += uRipA * ring * (0.04 * (0.55 + 0.45 * dot(nOut, normalize(vec2(-0.5, 0.8))))) * mix(0.5, 1.0, uLightScene);
    bg -= uRipA * 0.016 * uLightScene * exp(-(rx - 1.6) * (rx - 1.6));
  }
  float shadowFall = max(sd, 0.0) / (0.9 * uPlateScale);
  bg *= 1.0 - uShadow * 0.03 * exp(-shadowFall * shadowFall) * step(0.0, sd);
  vec3 haloCol = mix(vec3(0.62, 0.69, 0.80), vec3(1.0), uLightScene);
  bg = mix(bg, haloCol, clamp(uHalo * (0.30 * exp(-outside / (0.025 * uPlateScale)) + 0.07 * exp(-outside / (0.12 * uPlateScale))), 0.0, 1.0) * step(0.0, sd));

  vec3 col = bg;
  float soft = px + uBlur * 0.8 + 0.06 * uDissolve * (1.0 - uKeep) * uPlateScale;
  if (sd < soft) {
    // Lighting surface: a superellipse quarter, flat toward the face and steep at the rim.
    float y1 = 1.0 - x;
    const float K = 2.6;
    float base1 = max(1.0 - pow(y1, K), 1e-4);
    float db = min(pow(y1, K - 1.0) * pow(base1, 1.0 / K - 1.0), 25.0);
    // A second, lower step just inside the first draws the faint inner line.
    float s1 = bw * 0.62;
    float w2 = bw * 0.22;
    float t2 = clamp((s - s1) / w2, -1.0, 1.0);
    float dh2 = uDouble * bw * 0.16;
    float dd = dh2 * 0.5 * cos(t2 * 1.5707963) * 1.5707963 / w2 * step(abs(t2), 0.999);
    vec2 gDome = -uDome * 2.0 * g * dg * step(g, 1.0);
    vec2 grad = -(db + dd) * nOut + gDome;

    vec3 back = mix(uBg, uPlateCol, uIconPlate);
    vec3 liftG = mix(back + vec3(0.06), mix(back, vec3(1.0), 0.55), uLightGlass);
    float rblur = uBlur + 0.05 * length(qc - p) + min(uGlow * uOptics * (1.0 - xf) * foot / px, 0.04);

    // Each wavelength refracts by its own index, so everything the edge draws in fans into colour
    // while the face stays crisp. Around a corner the samples also smear along the rim.
    float cornerW = smoothstep(0.1, 0.9, 4.0 * nOut.x * nOut.x * nOut.y * nOut.y);
    float streak = 0.35 * uStreak * bw * mix(0.15, 1.0, cornerW) * pow(1.0 - xf, 1.5) * uOptics;
    vec2 tangent = vec2(-nOut.y, nOut.x);
    vec3 acc = vec3(0.0), wsum = vec3(0.0);
    for (int i = 0; i < 20; i++) {
      float lam = (float(i) + 0.5) / 20.0;
      float c = uDisp * (1.0 - 2.0 * lam);
      vec2 along = tangent * (streak * 2.0 * (fract(float(i) * 0.618034 + 0.31) - 0.5));
      float cf = uDisp * (1.0 - 2.0 * lam) * (lam > 0.5 ? 1.0 : 0.5);
      vec2 sp = refractSample(xf, bwF, 1.5 + uEtaSpread * c, R, dirOut, p + along,
                              dome + pinchPart * 0.3 * c, offMul);
      vec2 focusL = focus - sign(p) * (0.70710678 * uFocusSplit * c * uPlateScale);
      float wFocus = pow(1.0 - xf, uFocusK) * smoothstep(0.0, uRimLine * (1.0 + 0.6 * c), xf);
      sp = mix(sp, mix(p + along, focusL, wFocus), focusW);
      float faceOnly = smoothstep(0.7, 1.0, xf) * uOptics;
      sp *= 1.0 + uFaceDisp * cf * faceOnly;
      vec4 l = logoAt(sp, rblur + 0.12 * streak + uFaceDisp * 0.5 * max(c, 0.0) * faceOnly, foot);
      vec3 w = spectrum(lam);
      acc += mix(back, l.rgb, l.a) * w;
      wsum += w;
    }
    vec3 trans = acc / wsum;
    float tl = dot(trans, vec3(0.2126, 0.7152, 0.0722));
    trans = clamp(tl + (trans - tl) * (1.0 + uVivid * uOptics), 0.0, 1.0);
    // A young droplet is milky; the haze only ever lightens.
    float hazeLum = dot(trans, vec3(0.2126, 0.7152, 0.0722));
    float hazeGate = mix(1.0 - smoothstep(0.25, 0.75, hazeLum), smoothstep(0.25, 0.75, hazeLum), uLightGlass);
    trans = mix(trans, liftG, uFrost * 0.45 * hazeGate);

    float glassAmt = pow(1.0 - uDissolve, 1.5);
    float lit = uSpec * glassAmt;
    vec3 rimCol = mix(vec3(0.80, 0.87, 0.97), vec3(1.0), uLightGlass);

    // Light backdrop: the thick edge glows softly white over a clear face, with a hairline that is
    // bright along the top and right and a thin dark silhouette down the left and bottom.
    float sc = uPlateScale;
    float tLum = dot(trans, vec3(0.2126, 0.7152, 0.0722));
    float lightOnly = smoothstep(0.35, 0.85, tLum);
    float hw = smoothstep(-0.85, 0.5, dot(nOut, rot(vec2(0.5, 0.866), uLightAng)));
    float tileBand = band(s, 0.016 * sc, 0.075 * sc, 0.022 * sc);
    float dropBand = (1.0 - smoothstep(0.06 * sc, 0.13 * sc, s)) * smoothstep(0.0, 0.004 * sc, s);
    float glow = mix(0.32 * tileBand, 0.75 * dropBand, uDrop) * lightOnly;
    float edgeLine = gauss(s, 0.005 * sc, 0.0045 * sc);
    float lip = gauss(s, 0.15 * sc, 0.007 * sc) * uDouble * (1.0 - uDrop);
    vec3 lightGlass = mix(trans, vec3(1.0), glow * glassAmt);
    lightGlass += (0.075 * hw * edgeLine + 0.06 * (0.4 + 0.6 * hw) * lip) * lit;
    lightGlass *= 1.0 - 0.05 * (1.0 - hw) * edgeLine * glassAmt * (1.0 - uDrop);
    lightGlass = mix(lightGlass, vec3(1.0), 0.55 * uDrop * glassAmt * edgeLine);

    // Dark backdrop: a cool rim light that grows toward the steep edge, and a small key highlight.
    vec3 Nl = normalize(vec3(-grad, 1.0));
    float edge = 1.0 - Nl.z;
    vec2 ldir = rot(normalize(vec2(-0.62, 0.78)), uLightAng);
    float side = dot(nOut, ldir);
    float fres = pow(edge, 1.5);
    vec3 rim = rimCol * fres * (0.35 + 0.65 * max(side, -side * 0.8)) * uRim * 0.65;
    vec3 Hv = normalize(normalize(vec3(-0.45, 0.6, 0.66)) + vec3(0.0, 0.0, 1.0));
    float spc = pow(max(dot(Nl, Hv), 0.0), 140.0) * 0.8 * smoothstep(0.0, 0.25, y1);
    vec3 darkGlass = trans * (1.0 - 0.25 * fres) + (rim + vec3(spc)) * lit;
    darkGlass = mix(darkGlass, rimCol, uDrop * 0.4 * uSpec * (1.0 - smoothstep(0.0, 0.1 * uPlateScale, s)));
    vec3 glass = mix(darkGlass, lightGlass, uLightGlass);

    // While the glass holds the logo a soft band of light crosses the face, brightest near the rim.
    float sweepD = dot(p / uPlateScale, normalize(vec2(0.8, 0.6))) - uSweep;
    float sheen = uSheen * glassAmt * exp(-sweepD * sweepD / 0.03) * (0.55 + 0.45 * (1.0 - x));
    glass = mix(glass, vec3(1.0), sheen * mix(0.22, 0.42, uLightGlass));

    float cov = clamp(0.5 - sd / soft, 0.0, 1.0);
    col = mix(bg, glass, cov);
  }

  vec3 outc = mix(plain, col, uPlateAlpha);
  outc += (hash(gl_FragCoord.xy) - 0.5) / 255.0;
  outColor = vec4(outc, 1.0);
}`;
function createRenderer(canvas) {
    const gl = canvas.getContext("webgl2", {
        antialias: false,
        premultipliedAlpha: false
    });
    if (!gl) return null;
    const compile = (type, src)=>{
        const sh = gl.createShader(type);
        gl.shaderSource(sh, src);
        gl.compileShader(sh);
        if (!gl.getShaderParameter(sh, gl.COMPILE_STATUS)) throw new Error(gl.getShaderInfoLog(sh) || "shader");
        return sh;
    };
    const prog = gl.createProgram();
    gl.attachShader(prog, compile(gl.VERTEX_SHADER, VERT));
    gl.attachShader(prog, compile(gl.FRAGMENT_SHADER, FRAG));
    gl.linkProgram(prog);
    if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) throw new Error(gl.getProgramInfoLog(prog) || "program");
    gl.useProgram(prog);
    gl.bindBuffer(gl.ARRAY_BUFFER, gl.createBuffer());
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([
        -1,
        -1,
        3,
        -1,
        -1,
        3
    ]), gl.STATIC_DRAW);
    const loc = gl.getAttribLocation(prog, "aPos");
    gl.enableVertexAttribArray(loc);
    gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
    const U = {};
    const count = gl.getProgramParameter(prog, gl.ACTIVE_UNIFORMS);
    for(let i = 0; i < count; i++){
        const info = gl.getActiveUniform(prog, i);
        U[info.name] = gl.getUniformLocation(prog, info.name);
    }
    const sdfTex = gl.createTexture();
    const colTex = gl.createTexture();
    gl.uniform1i(U.uSdf, 0);
    gl.uniform1i(U.uCol, 1);
    let hasLogo = false;
    const params = (filter)=>{
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, filter);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
    };
    function setLogo(logo) {
        gl.activeTexture(gl.TEXTURE0);
        gl.bindTexture(gl.TEXTURE_2D, sdfTex);
        gl.pixelStorei(gl.UNPACK_PREMULTIPLY_ALPHA_WEBGL, false);
        gl.texImage2D(gl.TEXTURE_2D, 0, gl.R16F, TEX, TEX, 0, gl.RED, gl.FLOAT, logo.sdf);
        params(gl.LINEAR);
        gl.activeTexture(gl.TEXTURE1);
        gl.bindTexture(gl.TEXTURE_2D, colTex);
        gl.pixelStorei(gl.UNPACK_PREMULTIPLY_ALPHA_WEBGL, true);
        gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA8, gl.RGBA, gl.UNSIGNED_BYTE, logo.canvas);
        gl.pixelStorei(gl.UNPACK_PREMULTIPLY_ALPHA_WEBGL, false);
        gl.generateMipmap(gl.TEXTURE_2D);
        params(gl.LINEAR_MIPMAP_LINEAR);
        hasLogo = true;
    }
    function render(fr, w, h, tilePx) {
        if (!hasLogo) return;
        gl.viewport(0, 0, w, h);
        gl.uniform2f(U.uCenter, w / 2, h / 2);
        gl.uniform1f(U.uTile, tilePx);
        gl.uniform1f(U.uTexSize, TEX);
        gl.uniform1f(U.uBoxFrac, BOX);
        for(const k in fr){
            const v = fr[k];
            if (typeof v === "number" && U[k]) gl.uniform1f(U[k], v);
        }
        gl.uniform3fv(U.uBg, fr.uBg);
        gl.uniform3fv(U.uPlateCol, fr.uPlateCol);
        gl.uniform3fv(U.uLogoCol, fr.uLogoCol);
        gl.uniform2fv(U.uLogoOff, fr.uLogoOff);
        gl.drawArrays(gl.TRIANGLES, 0, 3);
    }
    function dispose() {
        gl.getExtension("WEBGL_lose_context")?.loseContext();
    }
    return {
        setLogo,
        render,
        dispose
    };
}
const TAIL = 1.1;
const OUTRO = 0.5;
const endOf = (P)=>P.present + TAIL;
const clamp01 = (x)=>x < 0 ? 0 : x > 1 ? 1 : x;
const mix = (a, b, t)=>a + (b - a) * t;
const smooth = (a, b, x)=>{
    const t = clamp01((x - a) / (b - a));
    return t * t * (3 - 2 * t);
};
const smoother = (a, b, x)=>{
    const t = clamp01((x - a) / (b - a));
    return t * t * t * (t * (t * 6 - 15) + 10);
};
function hexToRgb(hex) {
    let h = hex.replace("#", "");
    if (h.length === 3) h = h.replace(/./g, "$&$&");
    const v = parseInt(h.slice(0, 6), 16) || 0;
    return [
        (v >> 16 & 255) / 255,
        (v >> 8 & 255) / 255,
        (v & 255) / 255
    ];
}
const luminance = ([r, g, b])=>0.2126 * r + 0.7152 * g + 0.0722 * b;
function spring(t, response, damping) {
    if (t <= 0) return 0;
    const w = 2 * Math.PI / response;
    if (damping >= 1) return 1 - Math.exp(-w * t) * (1 + w * t);
    const wd = w * Math.sqrt(1 - damping * damping);
    return 1 - Math.exp(-damping * w * t) * (Math.cos(wd * t) + damping * w / wd * Math.sin(wd * t));
}
const reachCache = new Map();
function timeToReach(level, response, damping) {
    const key = `${level}/${response}/${damping}`;
    let t = reachCache.get(key);
    if (t === undefined) {
        let lo = 0;
        let hi = 3;
        for(let i = 0; i < 40; i++){
            const mid = (lo + hi) / 2;
            if (spring(mid, response, damping) < level) lo = mid;
            else hi = mid;
        }
        reachCache.set(key, t = hi);
    }
    return t;
}
function frameAt(T, P, outro = 0) {
    const tx = P.present;
    const keep = P.keepPlate ? 1 : 0;
    const damping = 1 - P.bounce;
    const grow = spring(T + 0.01, P.response, damping);
    const tl = timeToReach(0.85, P.response, damping) - 0.01;
    const tm = timeToReach(0.92, P.response, damping) - 0.01;
    const morph = spring(T - tm, 0.4, 1);
    const drop = 1 - smooth(0.05, 1, morph);
    const appear = smooth(0, 0.08, T);
    const drift = P.drift * spring(T - 0.3, 2.2, 1);
    const zoomIn = 0.25 * spring(T, 0.7, 1) + 0.75 * smoother(0, P.glide, T);
    const settle = spring(T - 0.5, 2.4, 1);
    const exit = spring(T - tx, 0.95, 1);
    const release = spring(T - tx - 0.05, 0.65, 1);
    const dome = 0.15 * P.bulge * (1 - smooth(0.4, 0.95, grow));
    const view = (1 + (P.startZoom - 1) * (1 - zoomIn)) * (1 - 0.045 * settle) * mix(1, P.finalScale, exit) * (1 - 0.06 * outro);
    const bandW = mix(P.bevelWidth, Math.max(P.bevelWidth, 0.4), drop);
    const plateScale = mix(P.startSize, 1, grow) * (1 + drift) * (1 + 0.14 * release * (1 - keep)) * (1 - keep * (0.03 * release + 0.06 * outro));
    const bg = hexToRgb(P.background);
    return {
        uPlateScale: plateScale,
        uShapeN: mix(2, P.corner, morph),
        uCornerN: P.corner,
        uOptics: 1 - smooth(0.55, 1, release),
        uPlateAlpha: keep ? appear * (1 - outro) : appear * (1 - smooth(0.45, 1, release)),
        uLogoHalf: P.logoScale * view,
        uLogoOff: [
            P.logoOffset[0] * view,
            P.logoOffset[1] * view
        ],
        uKeep: keep,
        uSheen: P.sheen,
        uSweep: mix(-1.6, 1.6, smoother(0.9, tx - 0.1, T)),
        uLightAng: P.lightTurn * smoother(0.4, tx + 0.4, T),
        uBold: P.swell * 0.03 * (1 - zoomIn),
        uBlur: P.focus * 0.05 * (1 - smooth(0.3, 0.95, grow)) + 0.03 * outro,
        uFrost: P.focus * (1 - smooth(0.5, 0.95, grow)),
        uPinch: 0.38 * P.stretch * smooth(0.1, 0.9, morph) * smooth(0.75, 0.97, zoomIn),
        uTilt: P.tilt,
        uDome: dome,
        uDrop: drop,
        uRim: 1 + 0.8 * drop,
        uHalo: P.halo * (0.5 + 0.5 * drop) * (1 - keep * release),
        uShadow: Math.max(P.shadow * smooth(0.45, 0.8, grow) * (1 - smooth(0, 0.6, morph)), 0.8 * P.shadow * keep * release),
        uGhost: smooth(0, 0.03, T) * (1 - smooth(0.04, 0.08, T)),
        uRipR: 1 + 0.9 * Math.max(0, T - tl),
        uRipA: P.ripple * smooth(tl, tl + 0.06, T) * Math.exp(-Math.max(0, T - tl) / 0.6),
        uBare: (1 - keep) * smooth(tx - 0.25, tx, T) * (1 - outro),
        uReach: bandW * plateScale,
        uCornerPull: P.cornerPull,
        uStreak: P.edgeSmear,
        uWiden: P.cornerWidth,
        uSlab: 0.3 * P.opticalDepth,
        uEtaSpread: 0.06,
        uFocus: P.cornerFocus,
        uFocusK: 1.0,
        uFocusSplit: 0.056 * P.colorBleed,
        uRimLine: 0.09,
        uCornerOn: smooth(0.35, 1, morph),
        uGlow: 0.012 * P.colorBleed,
        uFaceDisp: 0.012 * P.dispersion,
        uVivid: 0.85,
        uDissolve: release,
        uDisp: P.dispersion,
        uDouble: P.doubleBevel,
        uBevelW: bandW * (1 - release),
        uSpec: P.specular,
        uIconPlate: P.iconPlate ? 1 : 0,
        uUseColor: P.originalColors ? 1 : 0,
        uLightScene: luminance(bg) > 0.5 ? 1 : 0,
        uLightGlass: luminance(P.iconPlate ? hexToRgb(P.plateColor) : bg) > 0.5 ? 1 : 0,
        uBg: bg,
        uPlateCol: hexToRgb(P.plateColor),
        uLogoCol: hexToRgb(P.logoColor)
    };
}

// The page supplies one local SVG and one canvas. The SVG remains visible
// whenever rendering is unavailable, paused or finished.
export async function setupGlassReveal(stage) {
  const canvas = stage.querySelector('canvas');
  const img = stage.querySelector('img');
  const replay = stage.querySelector('button');
  const motion = matchMedia('(prefers-reduced-motion: reduce)');
  if (motion.matches) return;

  await img.decode();
  if (motion.matches) return;
  const renderer = createRenderer(canvas);
  if (!renderer) return;

  const texture = fitToTexture(img, img.naturalWidth, img.naturalHeight);
  renderer.setLogo({ canvas: texture, sdf: buildSdf(texture) });
  const settings = {
    ...LIGHT,
    logoScale: 0.6,
    finalScale: 0.8,
    startZoom: 2.3,
    background: '#f5efff',
    logoColor: '#593099',
  };
  let frame = 0;
  let lost = false;
  let start;
  let size;
  const stop = () => {
    cancelAnimationFrame(frame);
    frame = 0;
    stage.classList.remove('is-revealing');
  };
  const tick = now => {
    start ??= now;
    const elapsed = (now - start) / 1000;
    if (lost || motion.matches || elapsed >= endOf(settings)) {
      stop();
      return;
    }
    if (!size) {
      const dpr = Math.min(devicePixelRatio || 1, 2);
      canvas.width = canvas.height = Math.round(stage.clientWidth * dpr);
      size = canvas.width;
    }
    renderer.render(frameAt(elapsed, settings), size, size, size / 1.75);
    stage.classList.add('is-revealing');
    frame = requestAnimationFrame(tick);
  };
  const play = () => {
    if (lost || motion.matches || document.hidden) return;
    stop();
    start = undefined;
    size = 0;
    frame = requestAnimationFrame(tick);
  };

  replay.hidden = false;
  replay.addEventListener('click', play);
  motion.addEventListener('change', () => {
    replay.hidden = motion.matches || lost;
    stop();
  });
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) stop();
  });
  canvas.addEventListener('webglcontextlost', () => {
    lost = true;
    replay.hidden = true;
    stop();
  });
  play();
}
