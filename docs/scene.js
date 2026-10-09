// Kaappu's world: a cobalt vault-sphere that splits into five shares and rebuilds from three,
// inside a dial of thirty ticks that follows the real 30-second TOTP step.
import { createWorld, THREE, smooth, textTexture } from "./world.js";

const outerGhost = new THREE.MeshStandardMaterial({ color: "#c9c0ae", roughness: 0.9, transparent: true, opacity: 0.35 });
const ACC = new THREE.Color("#2a3cf2");
const INK = new THREE.Color("#15120e");
const PAPER = new THREE.Color("#efe7d7");

// Keyframes per stage: [x, y, z, scale, explode, rebuild, dialTilt, camX, camY, camZ]
const K = [
  /* 0 hero    */ [2.75, 0.3, -0.6, 0.95, 0.0, 0, 0.0, 0, 0.55, 9.6],
  /* 1 problem */ [-3.55, -0.3, -1, 0.6, 0.22, 0, 0.35, 0, 0.7, 10.0],
  /* 2 how     */ [3.1, 1.15, -2, 0.6, 0.0, 0, 1.0, 0, 0.9, 10.2],
  /* 3 try     */ [2.35, 0.1, -1.6, 0.85, 0.08, 0, 0.6, 0, 0.7, 10.0],
  /* 4 shares  */ [2.7, 0.75, -1.2, 0.8, 1.0, 0, 0.25, 0, 0.9, 10.0],
  /* 5 vault   */ [2.4, 0.3, -1.2, 0.85, 1.0, 1, 0.25, 0, 0.9, 10.0],
  /* 6 proof   */ [2.45, 0.0, -1.6, 0.85, 0.0, 0, 0.8, 0, 1.2, 10.4],
  /* 7 run     */ [3.0, 1.55, -3.0, 0.55, 0.35, 0, 0.4, 0, 1.4, 11.0],
  /* end       */ [2.6, 0.35, -1.5, 0.95, 0.0, 0, 0.9, 0, 0.8, 10.0],
];
const MOBILE = (k, i) => i === 0 ? [1.2, 3.35, -1.5, 0.5, k[4], k[5], k[6], 0, 0.6, 12.5] : [1.3, 3.4, -2.5, 0.42, k[4], k[5], k[6], 0, 0.6, 12.5];

function frame(stage, mobile) {
  const i = Math.max(0, Math.min(K.length - 2, Math.floor(stage)));
  const f = smooth(0.15, 0.85, stage - i);
  const a = mobile ? MOBILE(K[i], i) : K[i], b = mobile ? MOBILE(K[i + 1], i + 1) : K[i + 1];
  return a.map((v, j) => v + (b[j] - v) * f);
}

createWorld(document.getElementById("world"), async ({ scene, camera, mobile }) => {
  await document.fonts?.load("500 64px 'Geist Mono'").catch(() => {});

  /* ---------- the vault: five wedge-shaped shares of one sphere ---------- */
  const R = 1.25, N = 5, L = (Math.PI * 2) / N;
  const outer = new THREE.MeshPhysicalMaterial({ color: ACC, roughness: 0.22, metalness: 0.05, clearcoat: 1, clearcoatRoughness: 0.12, sheen: 0.4, sheenColor: new THREE.Color("#8d97ff") });
  const inner = new THREE.MeshStandardMaterial({ color: PAPER, roughness: 0.92, side: THREE.DoubleSide });
  const vault = new THREE.Group();
  scene.add(vault);
  const shards = [];
  for (let i = 0; i < N; i++) {
    const g = new THREE.Group();
    const p0 = i * L;
    const shell = new THREE.Mesh(new THREE.SphereGeometry(R, 72, 48, p0, L), outer);
    const half = () => new THREE.CircleGeometry(R * 0.999, 48, -Math.PI / 2, Math.PI);
    const f0 = new THREE.Mesh(half(), inner); f0.rotation.y = Math.PI + p0;
    const f1 = new THREE.Mesh(half(), inner); f1.rotation.y = Math.PI + p0 + L;
    [shell, f0, f1].forEach((m) => { m.castShadow = true; m.receiveShadow = true; g.add(m); });
    const mid = p0 + L / 2;
    const dir = new THREE.Vector3(-Math.cos(mid), 0, Math.sin(mid));
    // share number, floating just outside the wedge
    const tex = textTexture(String(i + 1).padStart(2, "0"), { font: "600 56px 'Geist Mono'", color: "#f4efe6", bg: "#15120e", pad: 22, radius: 40 });
    const tag = new THREE.Sprite(new THREE.SpriteMaterial({ map: tex, transparent: true, depthWrite: false, opacity: 0 }));
    tag.scale.set(0.42 * tex.userData.aspect * 0.5, 0.21, 1);
    tag.position.copy(dir).multiplyScalar(R * 1.25).setY(0.55);
    g.add(tag);
    vault.add(g);
    shards.push({ g, dir, tag, shell, spin: (i % 2 ? 1 : -1) * (0.4 + i * 0.13), keep: [1, 3, 4].includes(i) });
  }

  /* ---------- the dial: thirty ticks, one per second of the TOTP step ---------- */
  const dial = new THREE.Group();
  scene.add(dial);
  const tickGeo = new THREE.BoxGeometry(0.035, 0.26, 0.035);
  const tickMat = new THREE.MeshStandardMaterial({ color: 0xffffff, roughness: 0.6 });
  const ticks = new THREE.InstancedMesh(tickGeo, tickMat, 30);
  ticks.castShadow = true;
  const m4 = new THREE.Matrix4(), q = new THREE.Quaternion(), s3 = new THREE.Vector3(), v3 = new THREE.Vector3(), zAxis = new THREE.Vector3(0, 0, 1);
  const RD = 1.85;
  const tickColor = new THREE.Color();
  dial.add(ticks);
  const ringMat = new THREE.MeshStandardMaterial({ color: INK, roughness: 0.5 });
  const ring = new THREE.Mesh(new THREE.TorusGeometry(RD + 0.28, 0.006, 8, 220), ringMat);
  const ring2 = new THREE.Mesh(new THREE.TorusGeometry(RD - 0.26, 0.004, 8, 220), ringMat);
  dial.add(ring, ring2);
  const hand = new THREE.Mesh(new THREE.BoxGeometry(0.02, 0.5, 0.02), new THREE.MeshStandardMaterial({ color: ACC, roughness: 0.3 }));
  dial.add(hand);

  /* ---------- digits drifting through the air ---------- */
  const digitMats = [];
  for (let d = 0; d < 10; d++) {
    const t = textTexture(String(d), { font: "400 96px 'Geist Mono'", color: "#15120e", pad: 10 });
    const ta = textTexture(String(d), { font: "500 96px 'Geist Mono'", color: "#2a3cf2", pad: 10 });
    digitMats.push([new THREE.SpriteMaterial({ map: t, transparent: true, depthWrite: false, opacity: 0.5 }), new THREE.SpriteMaterial({ map: ta, transparent: true, depthWrite: false, opacity: 0.85 }), t.userData.aspect]);
  }
  const glyphs = [];
  const rand = (() => { let s = 11; return () => ((s = (s * 16807) % 2147483647) / 2147483647); })();
  const GN = mobile ? 40 : 90;
  for (let i = 0; i < GN; i++) {
    const d = Math.floor(rand() * 10), acc = rand() < 0.16;
    const [mi, ma, asp] = digitMats[d];
    const sp = new THREE.Sprite(acc ? ma : mi);
    const sz = 0.12 + rand() * 0.22;
    sp.scale.set(sz * asp, sz, 1);
    sp.position.set((rand() - 0.5) * 22, -1.4 + rand() * 7, -9 + rand() * 12);
    sp.userData = { v: 0.08 + rand() * 0.18, w: rand() * 6.28, base: sp.position.x };
    scene.add(sp); glyphs.push(sp);
  }

  const look = new THREE.Vector3();
  let explodeS = 0;

  return (st) => {
    const k = frame(st.stage, st.mobile);
    const [x, y, z, sc, ex, rb, tilt, cx, cy, cz] = k;
    const t = st.t;

    // vault
    vault.position.set(x, y + Math.sin(t * 0.8) * 0.06, z);
    vault.scale.setScalar(sc);
    vault.rotation.y = t * 0.18 + st.px * 0.35;
    vault.rotation.x = 0.18 + st.py * 0.12;
    explodeS = ex;
    shards.forEach((s, i) => {
      const away = s.keep ? ex * (1 - rb) : ex + rb * 1.4;
      s.g.position.copy(s.dir).multiplyScalar(away * 1.15);
      s.g.position.y = Math.sin(t * 0.9 + i) * 0.08 * away;
      s.g.rotation.y = away * s.spin * 0.35;
      s.g.rotation.z = away * s.spin * 0.18;
      const ghost = !s.keep ? rb : 0;
      s.shell.material = ghost > 0.5 ? outerGhost : outer;
      s.tag.material.opacity = Math.min(1, Math.max(0, (ex - 0.35) * 2.2)) * (1 - ghost * 0.6);
    });

    // dial follows the real clock
    const now = Date.now() / 1000, sec = now % 30;
    dial.position.set(x, y, z);
    dial.scale.setScalar(sc);
    dial.rotation.set(-Math.PI / 2 + 0.42 + tilt * 1.0, 0, 0);
    for (let i = 0; i < 30; i++) {
      const a = Math.PI / 2 - (i / 30) * Math.PI * 2;
      v3.set(Math.cos(a) * RD, Math.sin(a) * RD, 0);
      q.setFromAxisAngle(zAxis, a - Math.PI / 2);
      const isNow = i === Math.floor(sec), past = i < sec;
      s3.set(1, isNow ? 1.9 : past ? 1.15 : 0.75, 1);
      m4.compose(v3, q, s3); ticks.setMatrixAt(i, m4);
      ticks.setColorAt(i, tickColor.copy(isNow ? ACC : past ? INK : PAPER));
    }
    ticks.instanceMatrix.needsUpdate = true; ticks.instanceColor.needsUpdate = true;
    const ha = Math.PI / 2 - (sec / 30) * Math.PI * 2;
    hand.position.set(Math.cos(ha) * (RD - 0.62), Math.sin(ha) * (RD - 0.62), 0);
    hand.rotation.z = ha - Math.PI / 2;
    ring.rotation.z = t * 0.05;

    // drifting digits
    glyphs.forEach((g) => {
      g.position.y += g.userData.v * st.dt;
      g.position.x = g.userData.base + Math.sin(t * 0.3 + g.userData.w) * 0.25;
      if (g.position.y > 6) g.position.y = -1.4;
    });

    // camera
    camera.position.set(cx + st.px * 0.35, cy - st.py * 0.2, cz);
    look.set(cx * 0.6, 0.2 + (cy - 0.5) * 0.15, -2);
    camera.lookAt(look);
  };
}, { bg: "#e8e1d3", fog: [10, 40] });

