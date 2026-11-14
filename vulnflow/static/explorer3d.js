// Three.js renderer for VulnScope Explorer: the cinematic 3D view.
//
// explorer.js keeps the data, layout, panels and interaction; this file only draws. Each frame it
// hands over glowing node billboards, ribbon lines (Bezier curves and rings) and sparks as flat
// buffers, so one draw call covers each kind however many hosts there are. Everything is in the
// Explorer's world coordinates (y points down, as on the 2D canvas); depth is the third axis.
(function () {
'use strict';
const THREE = window.THREE;

function supported() {
  if (!THREE) return false;
  try {
    const c = document.createElement('canvas');
    return !!(window.WebGLRenderingContext && (c.getContext('webgl2') || c.getContext('webgl')));
  } catch (_) { return false; }
}

const hexCache = new Map();
function rgb(hex) {
  let v = hexCache.get(hex);
  if (!v) {
    const c = new THREE.Color(hex);
    v = [c.r, c.g, c.b];
    hexCache.set(hex, v);
  }
  return v;
}

// ---------------------------------------------------------------- growable float buffers
class Pool {
  constructor(geom, specs, instanced) {
    this.geom = geom; this.specs = specs; this.instanced = instanced; this.cap = 0; this.n = 0; this.arrays = {};
    this.grow(1024);
  }
  grow(cap) {
    const A = THREE.InstancedBufferAttribute, B = THREE.BufferAttribute;
    for (const [name, size] of this.specs) {
      const old = this.arrays[name], arr = new Float32Array(cap * size);
      if (old) arr.set(old);
      this.arrays[name] = arr;
      const attr = this.instanced ? new A(arr, size) : new B(arr, size);
      attr.setUsage(THREE.DynamicDrawUsage);
      this.geom.setAttribute(name, attr);
    }
    this.cap = cap;
    // three.js remembers how many instances the buffers held when the geometry was first drawn and never
    // draws more than that; forget it so a grown pool (e.g. more than 1024 hosts) draws every instance
    if (this.instanced) this.geom._maxInstanceCount = undefined;
  }
  reserve(extra) { if (this.n + extra > this.cap) { let c = this.cap; while (c < this.n + extra) c *= 2; this.grow(c); } }
  flush() {
    for (const [name] of this.specs) {
      const a = this.geom.getAttribute(name);
      a.needsUpdate = true;
      if (a.updateRange) { a.updateRange.offset = 0; a.updateRange.count = this.n * a.itemSize; }
    }
  }
}

// ---------------------------------------------------------------- shaders
const BILLBOARD_VS = `
attribute vec2 corner;
attribute vec3 iPos;
attribute vec4 iColor;      // rgb, alpha
attribute vec4 iStyle;      // shape, hollow, glow, minimum radius in CSS px
attribute float iSize;      // radius in world units
uniform vec2 uViewport;     // drawing buffer size in device px
uniform float uPx;          // device px per CSS px
uniform float uExpand;
uniform float uFade;        // depth where atmospheric fade starts
varying vec2 vCorner; varying vec4 vColor; varying vec4 vStyle;
void main() {
  vec4 mv = modelViewMatrix * vec4(iPos, 1.0);
  vec4 clip = projectionMatrix * mv;
  float ppu = projectionMatrix[1][1] * uViewport.y * 0.5 / max(clip.w, 1e-3);
  float rpx = max(iSize * ppu, iStyle.w * uPx);
  clip.xy += corner * uExpand * rpx / (uViewport * 0.5) * clip.w;
  gl_Position = clip;
  float depth = -mv.z;
  float fade = clamp(1.0 - (depth - uFade) / (uFade * 2.5), 0.12, 1.0);
  vCorner = corner * uExpand; vColor = vec4(iColor.rgb, iColor.a * fade); vStyle = iStyle;
}`;

// uMode 0: solid body (sphere, diamond, hollow ring, domain); 1: soft glow halo; 2: spark
const BILLBOARD_FS = `
uniform float uMode; uniform float uTime; uniform float uLight;
varying vec2 vCorner; varying vec4 vColor; varying vec4 vStyle;
void main() {
  vec2 p = vCorner; float r = length(p); vec3 col = vColor.rgb; float a = vColor.a;
  if (a < 0.004) discard;
  if (uMode > 1.5) {                        // spark: white-hot core in the edge colour
    float g = exp(-r * r * 3.2);
    if (g < 0.01) discard;
    gl_FragColor = vec4(mix(col, vec3(1.0), smoothstep(0.35, 0.0, r) * (1.0 - uLight)), a * g);
    return;
  }
  if (uMode > 0.5) {                        // halo
    float g = exp(-r * r * 1.1) * vStyle.z;
    if (g < 0.004) discard;
    gl_FragColor = vec4(col, a * g);
    return;
  }
  float shape = vStyle.x, hollow = vStyle.y;
  float aa = 0.06;
  if (shape > 2.5) {                        // domain IOC: dark teal disc, bright rim
    if (r > 1.0) discard;
    float rim = smoothstep(0.72, 0.8, r);
    gl_FragColor = vec4(mix(mix(vec3(0.03, 0.16, 0.19), vec3(1.0), uLight), col, rim), a);
  } else if (shape > 1.5) {                 // not observed: dark disc, dashed grey rim
    if (r > 1.0) discard;
    float ang = atan(p.y, p.x);
    float dash = step(0.0, sin(ang * 10.0));
    float rim = smoothstep(0.74, 0.82, r) * dash;
    gl_FragColor = vec4(mix(mix(vec3(0.055, 0.086, 0.14), vec3(1.0), uLight), col, rim), a * mix(0.9, 1.0, rim));
  } else if (shape > 0.5) {                 // outside address: diamond
    float d = (abs(p.x) + abs(p.y)) / 1.25;
    if (d > 1.0) discard;
    float edge = smoothstep(0.78, 0.86, d);
    vec3 fill = hollow > 0.5 ? mix(vec3(0.08, 0.12, 0.18), vec3(1.0), uLight) : col * (0.75 + 0.35 * (1.0 - d));
    gl_FragColor = vec4(mix(fill, col * 1.1, edge), a * (1.0 - smoothstep(1.0 - aa, 1.0, d)));
  } else {                                  // host: lit sphere
    if (r > 1.0) discard;
    vec3 n = vec3(p.x, p.y, sqrt(max(0.0, 1.0 - r * r)));
    vec3 L = normalize(vec3(-0.45, 0.55, 0.7));
    float diff = max(0.0, dot(n, L));
    float spec = pow(max(0.0, dot(reflect(-L, n), vec3(0.0, 0.0, 1.0))), 28.0);
    float rimL = pow(1.0 - n.z, 2.5);
    vec3 c = col * (0.28 + 0.9 * diff) + vec3(1.0) * spec * 0.85 + col * rimL * 0.7;
    gl_FragColor = vec4(c, a * (1.0 - smoothstep(1.0 - aa, 1.0, r)));
  }
}`;

const RIBBON_VS = `
attribute vec3 tangent;
attribute vec4 color;       // rgb, alpha
attribute vec4 params;      // side (-1/1), core width CSS px, arc length (world), dashed
uniform vec2 uViewport; uniform float uPx; uniform float uFade;
varying vec4 vColor; varying float vSide; varying float vHalf; varying float vCore; varying float vU; varying float vDash;
void main() {
  vec4 mv = modelViewMatrix * vec4(position, 1.0);
  vec4 c0 = projectionMatrix * mv;
  vec4 c1 = projectionMatrix * (modelViewMatrix * vec4(position + tangent, 1.0));
  vec2 s0 = c0.xy / max(c0.w, 1e-3) * uViewport * 0.5, s1 = c1.xy / max(c1.w, 1e-3) * uViewport * 0.5;
  vec2 dir = s1 - s0; float l = length(dir); dir = l > 1e-5 ? dir / l : vec2(1.0, 0.0);
  vec2 nrm = vec2(-dir.y, dir.x);
  float core = params.y * uPx * 0.5;
  float half_ = core * 3.0 + 2.0 * uPx;
  c0.xy += nrm * params.x * half_ / (uViewport * 0.5) * c0.w;
  gl_Position = c0;
  float depth = -mv.z;
  float fade = clamp(1.0 - (depth - uFade) / (uFade * 2.5), 0.12, 1.0);
  vColor = vec4(color.rgb, color.a * fade); vSide = params.x; vHalf = half_; vCore = core; vU = params.z; vDash = params.w;
}`;

const RIBBON_FS = `
uniform float uDashPeriod;
varying vec4 vColor; varying float vSide; varying float vHalf; varying float vCore; varying float vU; varying float vDash;
void main() {
  float d = abs(vSide) * vHalf;
  float core = 1.0 - smoothstep(vCore - 0.6, vCore + 0.6, d);
  float glow = exp(-pow(d / max(vCore * 2.2, 1.5), 2.0)) * 0.4;
  float a = (core + glow) * vColor.a;
  if (vDash > 0.5) a *= step(0.45, fract(vU / uDashPeriod));
  if (a < 0.003) discard;
  gl_FragColor = vec4(vColor.rgb * (1.0 + core * 0.35), a);
}`;

// ---------------------------------------------------------------- systems
function billboards(scene, mode, expand, blending, depthWrite, order, uniforms) {
  const geom = new THREE.InstancedBufferGeometry();
  geom.setAttribute('corner', new THREE.BufferAttribute(new Float32Array([-1, -1, 1, -1, 1, 1, -1, 1]), 2));
  geom.setIndex([0, 1, 2, 0, 2, 3]);
  const pool = new Pool(geom, [['iPos', 3], ['iColor', 4], ['iStyle', 4], ['iSize', 1]], true);
  const mat = new THREE.ShaderMaterial({
    vertexShader: BILLBOARD_VS, fragmentShader: BILLBOARD_FS, transparent: true, depthWrite, depthTest: true,
    blending, uniforms: Object.assign({uMode: {value: mode}, uExpand: {value: expand}}, uniforms)});
  const mesh = new THREE.Mesh(geom, mat);
  mesh.frustumCulled = false; mesh.renderOrder = order;
  scene.add(mesh);
  return {pool, geom, mesh};
}

function ribbons(scene, uniforms, order) {
  const geom = new THREE.BufferGeometry();
  const pool = new Pool(geom, [['position', 3], ['tangent', 3], ['color', 4], ['params', 4]], false);
  let index = new Uint32Array(4096), ni = 0;
  const setIndex = () => geom.setIndex(new THREE.BufferAttribute(index, 1));
  setIndex();
  const mat = new THREE.ShaderMaterial({vertexShader: RIBBON_VS, fragmentShader: RIBBON_FS, transparent: true,
    depthWrite: false, depthTest: true, blending: THREE.NormalBlending, side: THREE.DoubleSide,
    uniforms: Object.assign({uDashPeriod: {value: 12}}, uniforms)});
  const mesh = new THREE.Mesh(geom, mat);
  mesh.frustumCulled = false; mesh.renderOrder = order;
  scene.add(mesh);
  const api = {
    gain: 1,   // brightness of traffic curves (quad); restrained themes turn it down
    begin() { pool.n = 0; ni = 0; },
    // a polyline from k points given by `at(i)` -> [x, y, z] in Explorer coordinates
    strip(k, at, width, col, alpha, dashed) {
      if (k < 2 || alpha < 0.003) return;
      pool.reserve(k * 2);
      if (ni + (k - 1) * 6 > index.length) {
        let c = index.length; while (c < ni + (k - 1) * 6) c *= 2;
        const nx = new Uint32Array(c); nx.set(index); index = nx; setIndex();
      }
      const P = pool.arrays.position, T = pool.arrays.tangent, C = pool.arrays.color, Q = pool.arrays.params;
      const base = pool.n;
      let px = 0, py = 0, pz = 0, u = 0, prev = null;
      const pts = api._pts || (api._pts = []);
      for (let i = 0; i < k; i++) pts[i] = at(i);
      for (let i = 0; i < k; i++) {
        const p = pts[i], x = p[0], y = -p[1], z = p[2];
        const q = pts[Math.min(k - 1, i + 1)], o = pts[Math.max(0, i - 1)];
        let tx = q[0] - o[0], ty = -(q[1] - o[1]), tz = q[2] - o[2];
        const tl = Math.hypot(tx, ty, tz) || 1; tx /= tl; ty /= tl; tz /= tl;
        if (prev) u += Math.hypot(x - px, y - py, z - pz);
        px = x; py = y; pz = z; prev = true;
        for (let s = 0; s < 2; s++) {
          const v = pool.n++;
          P[v * 3] = x; P[v * 3 + 1] = y; P[v * 3 + 2] = z;
          T[v * 3] = tx; T[v * 3 + 1] = ty; T[v * 3 + 2] = tz;
          C[v * 4] = col[0]; C[v * 4 + 1] = col[1]; C[v * 4 + 2] = col[2]; C[v * 4 + 3] = alpha;
          Q[v * 4] = s ? 1 : -1; Q[v * 4 + 1] = width; Q[v * 4 + 2] = u; Q[v * 4 + 3] = dashed ? 1 : 0;
        }
      }
      for (let i = 0; i < k - 1; i++) {
        const a = base + i * 2;
        index[ni++] = a; index[ni++] = a + 1; index[ni++] = a + 2;
        index[ni++] = a + 1; index[ni++] = a + 3; index[ni++] = a + 2;
      }
    },
    // quadratic Bezier a -> c (control) -> b
    quad(ax, ay, az, cx, cy, cz, bx, by, bz, segs, width, col, alpha, dashed) {
      const pt = [0, 0, 0];
      api.strip(segs + 1, i => {
        const t = i / segs, s = 1 - t, A = s * s, B = 2 * s * t, Cc = t * t;
        return [A * ax + B * cx + Cc * bx, A * ay + B * cy + Cc * by, A * az + B * cz + Cc * bz];
      }, width, col, alpha * api.gain, dashed);
      return pt;
    },
    circle(x, y, z, r, segs, width, col, alpha, dashed) {
      api.strip(segs + 1, i => { const t = i / segs * Math.PI * 2; return [x + r * Math.cos(t), y + r * Math.sin(t), z]; },
        width, col, alpha, dashed);
    },
    end() {
      pool.flush();
      const ia = geom.getIndex(); ia.needsUpdate = true;
      geom.setDrawRange(0, ni);
    },
    material: mat,
  };
  return api;
}

function nodeApi(sys) {
  const {pool, geom} = sys;
  const api = {
    gain: 1,
    begin() { pool.n = 0; },
    add(x, y, z, size, col, alpha, shape, hollow, glow, minPx) {
      alpha *= api.gain;
      if (alpha < 0.004) return;
      pool.reserve(1);
      const i = pool.n++, A = pool.arrays;
      A.iPos[i * 3] = x; A.iPos[i * 3 + 1] = -y; A.iPos[i * 3 + 2] = z;
      A.iColor[i * 4] = col[0]; A.iColor[i * 4 + 1] = col[1]; A.iColor[i * 4 + 2] = col[2]; A.iColor[i * 4 + 3] = alpha;
      A.iStyle[i * 4] = shape; A.iStyle[i * 4 + 1] = hollow; A.iStyle[i * 4 + 2] = glow; A.iStyle[i * 4 + 3] = minPx;
      A.iSize[i] = size;
    },
    end() { pool.flush(); geom.instanceCount = pool.n; },
    get count() { return pool.n; },
  };
  return api;
}

// ---------------------------------------------------------------- environment
function backdrop(scene, inner, outer) {
  const mat = new THREE.ShaderMaterial({
    depthWrite: false, depthTest: false,
    uniforms: {uIn: {value: new THREE.Color(inner)}, uOut: {value: new THREE.Color(outer)}, uAspect: {value: 1}},
    vertexShader: 'varying vec2 vP; void main(){ vP = position.xy; gl_Position = vec4(position.xy, 0.9999, 1.0); }',
    fragmentShader: `uniform vec3 uIn; uniform vec3 uOut; uniform float uAspect; varying vec2 vP;
      void main(){ vec2 q = vP * vec2(uAspect, 1.0); float d = clamp(length(q) / (1.25 * max(uAspect, 1.0)), 0.0, 1.0);
      gl_FragColor = vec4(mix(uIn, uOut, smoothstep(0.0, 1.0, d)), 1.0); }`});
  const m = new THREE.Mesh(new THREE.PlaneGeometry(2, 2), mat);
  m.frustumCulled = false; m.renderOrder = -10;
  scene.add(m);
  return mat;
}

function starfield(scene, count) {
  const pos = new Float32Array(count * 3), seed = new Float32Array(count);
  for (let i = 0; i < count; i++) {
    const u = Math.random() * 2 - 1, t = Math.random() * Math.PI * 2, s = Math.sqrt(1 - u * u);
    pos[i * 3] = s * Math.cos(t); pos[i * 3 + 1] = u; pos[i * 3 + 2] = s * Math.sin(t);
    seed[i] = Math.random();
  }
  const g = new THREE.BufferGeometry();
  g.setAttribute('position', new THREE.BufferAttribute(pos, 3));
  g.setAttribute('seed', new THREE.BufferAttribute(seed, 1));
  const mat = new THREE.ShaderMaterial({
    transparent: true, depthWrite: false, depthTest: false, blending: THREE.AdditiveBlending,
    uniforms: {uTime: {value: 0}, uPx: {value: 1}},
    vertexShader: `attribute float seed; uniform float uTime; uniform float uPx; varying float vA; varying float vS;
      void main(){ vec4 mv = modelViewMatrix * vec4(position, 1.0); gl_Position = projectionMatrix * mv;
        gl_Position.z = gl_Position.w * 0.9998;
        vS = seed; vA = (0.25 + 0.55 * seed) * (0.6 + 0.4 * sin(uTime * (0.6 + seed * 1.4) + seed * 40.0));
        gl_PointSize = (0.8 + 2.2 * seed * seed) * uPx; }`,
    fragmentShader: `varying float vA; varying float vS; void main(){ vec2 c = gl_PointCoord - 0.5; float d = dot(c, c);
      if (d > 0.25) discard; vec3 col = mix(vec3(0.62, 0.78, 1.0), vec3(1.0, 0.86, 0.7), step(0.93, vS));
      gl_FragColor = vec4(col, vA * (1.0 - d * 4.0)); }`});
  const p = new THREE.Points(g, mat);
  p.frustumCulled = false; p.renderOrder = -9;
  scene.add(p);
  return {points: p, mat};
}

function nebulaTexture(c1, c2) {
  const cv = document.createElement('canvas'); cv.width = cv.height = 256;
  const x = cv.getContext('2d');
  for (let i = 0; i < 14; i++) {
    const cx = 64 + Math.random() * 128, cy = 64 + Math.random() * 128, r = 40 + Math.random() * 90;
    const g = x.createRadialGradient(cx, cy, 0, cx, cy, r);
    g.addColorStop(0, i % 2 ? c1 : c2); g.addColorStop(1, 'rgba(0,0,0,0)');
    x.globalAlpha = 0.11; x.fillStyle = g; x.fillRect(0, 0, 256, 256);
  }
  const t = new THREE.CanvasTexture(cv);
  return t;
}

function nebulae(scene) {
  const group = new THREE.Group();
  const specs = [['#2b6cff', '#7a3cff', -0.6, 0.15, 1.2], ['#13b5a8', '#2b6cff', 0.7, -0.25, 1.0],
    ['#ff2e88', '#7a3cff', 0.15, 0.55, 0.8], ['#2ee6d6', '#16223a', -0.25, -0.6, 1.1]];
  specs.forEach(([a, b, dx, dy, s]) => {
    const m = new THREE.SpriteMaterial({map: nebulaTexture(a, b), transparent: true, depthWrite: false, depthTest: false,
      blending: THREE.AdditiveBlending, opacity: 0.55});
    const sp = new THREE.Sprite(m);
    sp.position.set(dx, dy, -1).normalize();
    sp.userData.scale = s; sp.renderOrder = -8;
    group.add(sp);
  });
  scene.add(group);
  return group;
}

function floorGrid(scene) {
  const mat = new THREE.ShaderMaterial({
    transparent: true, depthWrite: false, blending: THREE.AdditiveBlending,
    uniforms: {uCenter: {value: new THREE.Vector2()}, uRadius: {value: 3000}, uCell: {value: 120}, uTime: {value: 0}, uCol: {value: new THREE.Color(0.31, 0.55, 1.0)}},
    vertexShader: 'varying vec2 vW; void main(){ vec4 w = modelMatrix * vec4(position, 1.0); vW = w.xy; gl_Position = projectionMatrix * viewMatrix * w; }',
    fragmentShader: `uniform vec2 uCenter; uniform float uRadius; uniform float uCell; uniform float uTime; uniform vec3 uCol; varying vec2 vW;
      float line(vec2 p, float cell){ vec2 g = abs(fract(p / cell - 0.5) - 0.5) / fwidth(p / cell); return 1.0 - min(min(g.x, g.y), 1.0); }
      void main(){ float d = length(vW - uCenter) / uRadius; float fade = exp(-d * d * 2.2);
        float l = line(vW, uCell) * 0.55 + line(vW, uCell * 5.0) * 0.6;
        float pulse = 0.5 + 0.5 * sin(d * 18.0 - uTime * 0.8);
        float a = l * fade * (0.05 + 0.04 * pulse);
        if (a < 0.002) discard; gl_FragColor = vec4(uCol, a); }`,
    extensions: {derivatives: true}});
  const m = new THREE.Mesh(new THREE.PlaneGeometry(1, 1), mat);
  m.frustumCulled = false; m.renderOrder = -5;
  scene.add(m);
  return {mesh: m, mat};
}

// ---------------------------------------------------------------- renderer
function create(canvas, opts) {
  const renderer = new THREE.WebGLRenderer({canvas, antialias: true, alpha: false, powerPreference: 'high-performance'});
  renderer.setClearColor(new THREE.Color(opts.bgOut), 1);
  renderer.sortObjects = true;
  const gl = renderer.getContext();
  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(40, 1, 1, 100000);
  const viewport = new THREE.Vector2(1, 1);
  const shared = {uViewport: {value: viewport}, uPx: {value: 1}, uFade: {value: 2000}, uTime: {value: 0}, uLight: {value: opts.light ? 1 : 0}};
  const bg = backdrop(scene, opts.bgIn, opts.bgOut);
  const stars = starfield(scene, 3200);
  const neb = nebulae(scene);
  const grid = floorGrid(scene);
  // restrained themes: plain backdrop, no stars or nebula haze
  if (opts.calm) { stars.points.visible = false; neb.visible = false; }
  if (opts.calm) grid.mat.uniforms.uCol.value.setRGB(0.5, 0.51, 0.53);
  const halos = billboards(scene, 1, 3.4, THREE.AdditiveBlending, false, 1, shared);
  if (opts.calm) halos.mesh.visible = false;
  const bodiesSys = billboards(scene, 0, 1.3, THREE.NormalBlending, true, 2, shared);
  // halos and bodies share instance buffers so each node is written once
  for (const name of ['iPos', 'iColor', 'iStyle', 'iSize']) halos.geom.setAttribute(name, bodiesSys.geom.getAttribute(name));
  bodiesSys.pool.geom = bodiesSys.geom;
  const origGrow = bodiesSys.pool.grow.bind(bodiesSys.pool);
  bodiesSys.pool.grow = cap => { origGrow(cap); for (const name of ['iPos', 'iColor', 'iStyle', 'iSize']) halos.geom.setAttribute(name, bodiesSys.geom.getAttribute(name)); halos.geom._maxInstanceCount = undefined; };
  const lines = ribbons(scene, shared, 0);
  const sparksSys = billboards(scene, 2, 1.0, THREE.AdditiveBlending, false, 4, shared);
  const nodesApi = nodeApi(bodiesSys), sparksApi = nodeApi(sparksSys);
  if (opts.calm) { lines.gain = 0.55; sparksApi.gain = 0.4; }   // quieter traffic in the restrained themes
  if (opts.light) {   // white canvas: additive light would vanish, so blend normally and keep lines strong enough to read
    lines.gain = 1; sparksApi.gain = 0.8;
    sparksSys.mesh.material.blending = THREE.NormalBlending;
    grid.mat.blending = THREE.NormalBlending; grid.mat.uniforms.uCol.value.setRGB(0.25, 0.26, 0.28);
  }
  const nodesEnd = nodesApi.end;
  nodesApi.end = () => { nodesEnd(); halos.geom.instanceCount = bodiesSys.pool.n; };

  let W = 1, H = 1, DPR = 1;
  const M = new THREE.Matrix4(), e = M.elements;
  const ray = new THREE.Raycaster(), plane = new THREE.Plane(new THREE.Vector3(0, 0, 1), 0), hit = new THREE.Vector3();
  const tmp = new THREE.Vector2();

  function setSize(w, h, dpr) {
    W = w; H = h; DPR = dpr;
    renderer.setPixelRatio(dpr); renderer.setSize(w, h, false);
    camera.aspect = w / h; camera.updateProjectionMatrix();
    viewport.set(w * dpr, h * dpr); shared.uPx.value = dpr;
    bg.uniforms.uAspect.value = w / h;
    stars.mat.uniforms.uPx.value = dpr;
  }
  // Point the camera: target (x, y) in Explorer coordinates, zoom as on the 2D canvas
  // (CSS px per world unit at the target), then yaw / pitch around the target.
  // orbit: yaw turns the camera around the network plane's normal and pitch is the angle from
  // straight above (0 = top-down); otherwise yaw / pitch tilt a mostly front-on view (host focus)
  // (sx, sy): shift the picture on screen in CSS px, so the camera can orbit the network's centre
  // while the network sits in the space beside the side panels
  function setCamera(x, y, zoom, yaw, pitch, distMul, orbit, shiftX, shiftY) {
    const d0 = (H / 2) / Math.tan(camera.fov * Math.PI / 360);
    const dist = d0 / zoom * (distMul || 1);
    const cp = Math.cos(pitch), sp = Math.sin(pitch), cy = Math.cos(yaw), sy = Math.sin(yaw);
    if (orbit) {
      camera.position.set(x + dist * sp * sy, -y - dist * sp * cy, dist * cp);
      camera.up.set(-cp * sy, cp * cy, sp);
    } else {
      camera.position.set(x + dist * sy * cp, -y - dist * sp, dist * cy * cp);
      camera.up.set(0, 1, 0);
    }
    camera.lookAt(x, -y, 0);
    if (shiftX || shiftY) camera.setViewOffset(W, H, -(shiftX || 0), -(shiftY || 0), W, H); else camera.clearViewOffset();
    camera.near = Math.max(1, dist * 0.02); camera.far = dist * 40 + 20000;
    camera.updateProjectionMatrix(); camera.updateMatrixWorld();
    M.multiplyMatrices(camera.projectionMatrix, camera.matrixWorldInverse);
    shared.uFade.value = dist * 1.25;
    // environment follows the camera so it reads as infinitely far away
    stars.points.position.copy(camera.position); stars.points.scale.setScalar(camera.far * 0.6);
    neb.position.copy(camera.position);
    neb.children.forEach(s => {
      const r = camera.far * 0.5;
      s.position.normalize().multiplyScalar(r); s.scale.setScalar(r * s.userData.scale);
    });
    grid.mesh.position.set(x, -y, -260);
    grid.mesh.scale.set(dist * 12, dist * 12, 1);
    grid.mat.uniforms.uCenter.value.set(x, -y);
    grid.mat.uniforms.uRadius.value = dist * 2.2;
    grid.mat.uniforms.uCell.value = 120;
    lines.material.uniforms.uDashPeriod.value = 11 / zoom;
    return dist;
  }
  // world (Explorer coordinates) -> [screen x, screen y, CSS px per world unit]; NaN when behind the camera
  function project(x, y, z) {
    const Y = -y;
    const w = e[3] * x + e[7] * Y + e[11] * z + e[15];
    if (w <= 1e-3) return [NaN, NaN, 0];
    const cx = (e[0] * x + e[4] * Y + e[8] * z + e[12]) / w, cy = (e[1] * x + e[5] * Y + e[9] * z + e[13]) / w;
    const ppu = camera.projectionMatrix.elements[5] * H * 0.5 / w;
    return [(cx + 1) * 0.5 * W, (1 - cy) * 0.5 * H, ppu];
  }
  // screen -> Explorer coordinates on the z = 0 plane
  function unproject(sx, sy) {
    tmp.set(sx / W * 2 - 1, 1 - sy / H * 2);
    ray.setFromCamera(tmp, camera);
    if (!ray.ray.intersectPlane(plane, hit)) return null;
    return [hit.x, -hit.y];
  }
  function render(T) {
    shared.uTime.value = T; stars.mat.uniforms.uTime.value = T; grid.mat.uniforms.uTime.value = T;
    stars.points.rotation.y = T * 0.004; stars.points.rotation.x = T * 0.0017;
    renderer.render(scene, camera);
  }
  function setTheme(inner, outer) {
    bg.uniforms.uIn.value.set(inner); bg.uniforms.uOut.value.set(outer); renderer.setClearColor(new THREE.Color(outer), 1);
  }
  canvas.addEventListener('webglcontextlost', ev => { ev.preventDefault(); if (opts.onLost) opts.onLost(); });
  return {setSize, setCamera, project, unproject, render, setTheme, lines, nodes: nodesApi, sparks: sparksApi, rgb,
    get maxTexture() { return gl.getParameter(gl.MAX_TEXTURE_SIZE); }};
}

window.VF3D = {supported, create, rgb};
})();
