/**
 * Cyber3DBackground — global, fixed-position Three.js scene.
 *
 * Mounted once at the App-shell level so every route inherits the same
 * 3D ambience without each page knowing about it. Z-indexed BEHIND
 * everything (`zIndex: -1`); pages with solid backgrounds will cover it,
 * pages with transparent backgrounds reveal it.
 *
 * Scene contents:
 *   - rotating wireframe icosahedron ("neural sphere") with glowing
 *     vertex points
 *   - magenta torus-knot data ring
 *   - drifting particle cloud
 *   - infinite-feel grid floor + exponential fog
 *
 * Interactions:
 *   - mouse-move parallax on the inner group
 *   - scroll position smoothly tilts the camera and shifts particle hue
 *     from cyan → magenta
 *
 * Performance:
 *   - DPR clamped at 1.75
 *   - lower particle count on small screens
 *   - single rAF loop; tears down cleanly on unmount
 */
import { useEffect, useRef } from 'react';
import * as THREE from 'three';

const CYAN = new THREE.Color(0x00d4ff);
const MAGENTA = new THREE.Color(0xff3df0);

const Cyber3DBackground = ({ opacity = 0.85, core = true }) => {
  const containerRef = useRef(null);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const isSmall = window.innerWidth < 720;
    const PARTICLE_COUNT = isSmall ? 450 : 900;

    // -------- renderer / scene / camera --------
    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 1.75));
    renderer.setSize(window.innerWidth, window.innerHeight);
    renderer.setClearColor(0x000000, 0);
    container.appendChild(renderer.domElement);

    const scene = new THREE.Scene();
    scene.fog = new THREE.FogExp2(0x05070f, 0.025);

    const camera = new THREE.PerspectiveCamera(
      55, window.innerWidth / window.innerHeight, 0.1, 200
    );
    camera.position.set(0, 0.4, 7);

    // -------- lights --------
    scene.add(new THREE.AmbientLight(0x6090ff, 0.4));
    const lightCyan = new THREE.PointLight(0x00d4ff, 1.8, 30);
    lightCyan.position.set(4, 3, 5); scene.add(lightCyan);
    const lightMagenta = new THREE.PointLight(0xff3df0, 1.4, 30);
    lightMagenta.position.set(-5, -2, 4); scene.add(lightMagenta);

    // -------- neural icosahedron sphere + magenta torus knot --------
    // Optional "core" centrepiece. Disabled (core=false) on pages that have
    // their own central graphic (e.g. the Learn scrollytelling) so it doesn't
    // overlap and compete. Particles + grid floor always remain.
    let neural = null, icoGeo = null, ico = null, nodesGeo = null, nodes = null;
    let knotGeo = null, knotMat = null, knot = null;
    if (core) {
      neural = new THREE.Group();
      scene.add(neural);

      icoGeo = new THREE.IcosahedronGeometry(1.6, 2);
      ico = new THREE.Mesh(
        icoGeo,
        new THREE.MeshBasicMaterial({
          color: 0x00d4ff, wireframe: true, transparent: true, opacity: 0.5,
        })
      );
      neural.add(ico);

      nodesGeo = new THREE.BufferGeometry();
      nodesGeo.setAttribute('position', icoGeo.attributes.position.clone());
      nodes = new THREE.Points(
        nodesGeo,
        new THREE.PointsMaterial({
          color: 0x9ff7ff, size: 0.08, transparent: true, opacity: 0.95,
          blending: THREE.AdditiveBlending, depthWrite: false,
        })
      );
      neural.add(nodes);

      knotGeo = new THREE.TorusKnotGeometry(2.6, 0.06, 220, 16);
      knotMat = new THREE.MeshBasicMaterial({
        color: 0xff3df0, transparent: true, opacity: 0.55,
      });
      knot = new THREE.Mesh(knotGeo, knotMat);
      knot.position.set(0, 0, -1.5);
      scene.add(knot);
    }

    // -------- particle cloud --------
    const particlesGeo = new THREE.BufferGeometry();
    const positions = new Float32Array(PARTICLE_COUNT * 3);
    const speeds = new Float32Array(PARTICLE_COUNT);
    for (let i = 0; i < PARTICLE_COUNT; i++) {
      positions[3 * i + 0] = (Math.random() - 0.5) * 30;
      positions[3 * i + 1] = (Math.random() - 0.5) * 18;
      positions[3 * i + 2] = (Math.random() - 0.5) * 30;
      speeds[i] = 0.002 + Math.random() * 0.006;
    }
    particlesGeo.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    const particleColor = CYAN.clone();
    const particlesMat = new THREE.PointsMaterial({
      color: particleColor, size: 0.045, transparent: true, opacity: 0.85,
      blending: THREE.AdditiveBlending, depthWrite: false,
    });
    const particles = new THREE.Points(particlesGeo, particlesMat);
    scene.add(particles);

    // -------- grid floor --------
    const grid = new THREE.GridHelper(80, 60, 0x00d4ff, 0x093a59);
    grid.position.y = -3.4;
    grid.material.transparent = true;
    grid.material.opacity = 0.35;
    scene.add(grid);

    // -------- interactions: mouse parallax + scroll choreography --------
    const state = {
      mx: 0, my: 0, tmx: 0, tmy: 0,
      scroll: 0,        // 0..1 across the page
      camY: 0.4, camZ: 7, camRotX: 0,
    };

    const onMouseMove = (e) => {
      state.tmx = (e.clientX / window.innerWidth - 0.5) * 0.6;
      state.tmy = (e.clientY / window.innerHeight - 0.5) * 0.4;
    };
    const onScroll = () => {
      const max = Math.max(1, document.body.scrollHeight - window.innerHeight);
      state.scroll = Math.min(1, Math.max(0, window.scrollY / max));
    };
    const onResize = () => {
      camera.aspect = window.innerWidth / window.innerHeight;
      camera.updateProjectionMatrix();
      renderer.setSize(window.innerWidth, window.innerHeight);
    };

    window.addEventListener('mousemove', onMouseMove, { passive: true });
    window.addEventListener('scroll', onScroll, { passive: true });
    window.addEventListener('resize', onResize);
    onScroll();

    // -------- animation loop --------
    const clock = new THREE.Clock();
    let rafId = 0;
    const tmpColor = new THREE.Color();

    const animate = () => {
      const t = clock.getElapsedTime();

      // smooth mouse parallax
      state.mx += (state.tmx - state.mx) * 0.06;
      state.my += (state.tmy - state.my) * 0.06;

      if (neural) {
        neural.rotation.y = t * 0.18 + state.mx * 0.6;
        neural.rotation.x = Math.sin(t * 0.3) * 0.15 + state.my * 0.4;
      }
      if (knot) {
        knot.rotation.x = t * 0.22;
        knot.rotation.y = t * 0.15;
        knot.scale.setScalar(Math.max(0.5, 1 - state.scroll * 0.4));
      }

      particles.rotation.y = t * 0.02;

      // particle hue cyan → magenta as page scrolls
      tmpColor.copy(CYAN).lerp(MAGENTA, state.scroll);
      particlesMat.color.copy(tmpColor);

      // gentle camera dolly with scroll
      const tgtY = 0.4 + state.scroll * 2.2;
      const tgtZ = 7 - state.scroll * 0.6;
      const tgtRotX = -state.scroll * 0.35;
      state.camY += (tgtY - state.camY) * 0.04;
      state.camZ += (tgtZ - state.camZ) * 0.04;
      state.camRotX += (tgtRotX - state.camRotX) * 0.04;
      camera.position.y = state.camY;
      camera.position.z = state.camZ;
      camera.rotation.x = state.camRotX;

      // drift particles upward, wrap around
      const pos = particlesGeo.attributes.position.array;
      for (let i = 0; i < PARTICLE_COUNT; i++) {
        pos[3 * i + 1] += speeds[i];
        if (pos[3 * i + 1] > 9) pos[3 * i + 1] = -9;
      }
      particlesGeo.attributes.position.needsUpdate = true;

      renderer.render(scene, camera);
      rafId = requestAnimationFrame(animate);
    };
    animate();

    // -------- cleanup --------
    return () => {
      cancelAnimationFrame(rafId);
      window.removeEventListener('mousemove', onMouseMove);
      window.removeEventListener('scroll', onScroll);
      window.removeEventListener('resize', onResize);
      // dispose geometries + materials
      if (icoGeo) {
        icoGeo.dispose(); ico.material.dispose();
        nodesGeo.dispose(); nodes.material.dispose();
        knotGeo.dispose(); knotMat.dispose();
      }
      particlesGeo.dispose(); particlesMat.dispose();
      grid.geometry.dispose(); grid.material.dispose();
      renderer.dispose();
      if (renderer.domElement.parentNode === container) {
        container.removeChild(renderer.domElement);
      }
    };
  }, [core]);

  return (
    <div
      ref={containerRef}
      aria-hidden="true"
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: -1,
        pointerEvents: 'none',
        opacity,
      }}
    />
  );
};

export default Cyber3DBackground;
