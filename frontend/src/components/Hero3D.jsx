/**
 * Hero3D — full-page Three.js scene used as the landing-page background.
 *
 * Scene composition
 *   - A central wireframe globe (the "network core")
 *   - Two orbiting rings of nodes (the "endpoints")
 *   - Continuous packet streams between the core and the orbiting nodes
 *   - Random "attack pulses" that expand from a node and get neutralised
 *     by an inner ring (visualises the IDS doing its job)
 *   - A particle starfield for depth
 *   - Subtle camera parallax driven by the mouse cursor
 *
 * The scene is rendered fixed-position behind the regular landing-page
 * content so the existing copy / CTA / feature cards float over it.
 *
 * Notes
 *   - Uses @react-three/fiber v8 (React 18 compatible).
 *   - All animation is frame-time driven via useFrame so the scene stays
 *     smooth regardless of refresh rate.
 *   - Performance budget: ~80-120 nodes / 200 particles. Tested fine on
 *     low-end laptops.
 */
import React, { useRef, useMemo, Suspense } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';
import { OrbitControls, Stars } from '@react-three/drei';
import * as THREE from 'three';


// ---------------------------------------------------------------------------
// Wireframe central globe — represents the network being monitored.
// ---------------------------------------------------------------------------
function NetworkCore() {
  const meshRef = useRef();
  const innerRef = useRef();

  useFrame((state, delta) => {
    if (meshRef.current) {
      meshRef.current.rotation.y += delta * 0.12;
      meshRef.current.rotation.x += delta * 0.04;
    }
    if (innerRef.current) {
      innerRef.current.rotation.y -= delta * 0.18;
    }
  });

  return (
    <group>
      {/* Outer wireframe sphere */}
      <mesh ref={meshRef}>
        <icosahedronGeometry args={[1.6, 1]} />
        <meshBasicMaterial color="#00d4ff" wireframe transparent opacity={0.45} />
      </mesh>
      {/* Inner solid-ish sphere */}
      <mesh ref={innerRef}>
        <sphereGeometry args={[1.2, 24, 24]} />
        <meshBasicMaterial color="#003311" wireframe transparent opacity={0.25} />
      </mesh>
      {/* Glowing core */}
      <mesh>
        <sphereGeometry args={[0.5, 16, 16]} />
        <meshBasicMaterial color="#00d4ff" transparent opacity={0.35} />
      </mesh>
    </group>
  );
}


// ---------------------------------------------------------------------------
// Orbiting endpoint nodes — the things being protected.
// ---------------------------------------------------------------------------
function OrbitRing({ count = 18, radius = 3.2, speed = 0.15, color = '#00d4ff', y = 0, tilt = 0 }) {
  const groupRef = useRef();
  const nodes = useMemo(() => {
    return Array.from({ length: count }).map((_, i) => {
      const angle = (i / count) * Math.PI * 2;
      return {
        x: Math.cos(angle) * radius,
        z: Math.sin(angle) * radius,
        // Slight per-node phase so the pulse animation isn't synchronous.
        phase: Math.random() * Math.PI * 2,
      };
    });
  }, [count, radius]);

  useFrame((state, delta) => {
    if (groupRef.current) {
      groupRef.current.rotation.y += delta * speed;
    }
  });

  return (
    <group ref={groupRef} position={[0, y, 0]} rotation={[tilt, 0, 0]}>
      {nodes.map((n, i) => (
        <PulseNode key={i} position={[n.x, 0, n.z]} color={color} phase={n.phase} />
      ))}
      {/* Visible orbit ring */}
      <mesh rotation={[Math.PI / 2, 0, 0]}>
        <torusGeometry args={[radius, 0.005, 8, 96]} />
        <meshBasicMaterial color={color} transparent opacity={0.18} />
      </mesh>
    </group>
  );
}


/**
 * One node on an orbit ring. Pulses gently and emits a packet stream
 * back toward the central core.
 */
function PulseNode({ position, color, phase }) {
  const meshRef = useRef();
  const lineRef = useRef();
  const positionVec = useMemo(() => new THREE.Vector3(...position), [position]);

  useFrame((state) => {
    const t = state.clock.elapsedTime + phase;
    const pulse = 1 + Math.sin(t * 2) * 0.18;
    if (meshRef.current) {
      meshRef.current.scale.setScalar(pulse);
    }
    // Pulse the connecting line opacity.
    if (lineRef.current) {
      const op = 0.05 + Math.abs(Math.sin(t * 1.2)) * 0.45;
      lineRef.current.material.opacity = op;
    }
  });

  // Line geometry from node back to centre — built once.
  const lineGeom = useMemo(() => {
    const points = [
      positionVec,
      new THREE.Vector3(0, 0, 0),
    ];
    return new THREE.BufferGeometry().setFromPoints(points);
  }, [positionVec]);

  return (
    <group>
      <mesh ref={meshRef} position={position}>
        <octahedronGeometry args={[0.08, 0]} />
        <meshBasicMaterial color={color} />
      </mesh>
      <line ref={lineRef} geometry={lineGeom}>
        <lineBasicMaterial color={color} transparent opacity={0.2} />
      </line>
    </group>
  );
}


// ---------------------------------------------------------------------------
// Packet particles — animated dots flowing from outer nodes inward.
// ---------------------------------------------------------------------------
function PacketStream({ count = 80, radius = 3.6, color = '#00d4ff' }) {
  const pointsRef = useRef();
  const data = useMemo(() => {
    return Array.from({ length: count }).map(() => {
      const angle = Math.random() * Math.PI * 2;
      const r = radius * (0.7 + Math.random() * 0.4);
      const yJitter = (Math.random() - 0.5) * 1.2;
      return {
        x0: Math.cos(angle) * r, z0: Math.sin(angle) * r, y0: yJitter,
        speed: 0.15 + Math.random() * 0.4,
        offset: Math.random(),
      };
    });
  }, [count, radius]);

  useFrame((state) => {
    if (!pointsRef.current) return;
    const t = state.clock.elapsedTime;
    const positions = pointsRef.current.geometry.attributes.position.array;
    data.forEach((p, i) => {
      // 0..1 animation cycle from outer to centre
      const cycle = ((t * p.speed + p.offset) % 1);
      const inv = 1 - cycle; // 1 at start (outside), 0 at centre
      positions[i * 3]     = p.x0 * inv;
      positions[i * 3 + 1] = p.y0 * inv;
      positions[i * 3 + 2] = p.z0 * inv;
    });
    pointsRef.current.geometry.attributes.position.needsUpdate = true;
  });

  // Initial buffer
  const initial = useMemo(() => {
    const a = new Float32Array(count * 3);
    data.forEach((p, i) => {
      a[i * 3] = p.x0; a[i * 3 + 1] = p.y0; a[i * 3 + 2] = p.z0;
    });
    return a;
  }, [count, data]);

  return (
    <points ref={pointsRef}>
      <bufferGeometry>
        <bufferAttribute
          attach="attributes-position"
          count={count}
          array={initial}
          itemSize={3}
        />
      </bufferGeometry>
      <pointsMaterial color={color} size={0.06} transparent opacity={0.85}
                      sizeAttenuation={true} />
    </points>
  );
}


// ---------------------------------------------------------------------------
// Attack pulses — random red rings that expand from a random orbit node
// then get caught and faded out (the "intrusion detection" visual story).
// ---------------------------------------------------------------------------
function AttackPulses({ count = 4, radius = 3.2 }) {
  const refs = useRef([]);
  const data = useMemo(() => Array.from({ length: count }).map(() => ({
    angle: Math.random() * Math.PI * 2,
    delay: Math.random() * 4,
    duration: 2.4 + Math.random() * 1.5,
  })), [count]);

  useFrame((state) => {
    const t = state.clock.elapsedTime;
    data.forEach((p, i) => {
      const ref = refs.current[i];
      if (!ref) return;
      // Cycle: invisible for `delay` then expand from 0 → outer over `duration`.
      const cycleLen = p.duration + p.delay;
      const localT = (t % cycleLen);
      if (localT < p.delay) {
        ref.scale.setScalar(0);
        ref.material.opacity = 0;
        return;
      }
      const u = (localT - p.delay) / p.duration; // 0..1
      const scale = 0.05 + u * 0.6;
      ref.scale.setScalar(scale);
      // Bright at start, fades fast — visualises detection + neutralisation.
      ref.material.opacity = (1 - u) * 0.85;
    });
  });

  return data.map((p, i) => {
    const x = Math.cos(p.angle) * radius;
    const z = Math.sin(p.angle) * radius;
    return (
      <mesh
        key={i}
        ref={(el) => (refs.current[i] = el)}
        position={[x, 0, z]}
        rotation={[Math.PI / 2, 0, 0]}
      >
        <torusGeometry args={[1, 0.04, 8, 48]} />
        <meshBasicMaterial color="#ff3b3b" transparent opacity={0} />
      </mesh>
    );
  });
}


// ---------------------------------------------------------------------------
// Subtle mouse-driven camera parallax.
// ---------------------------------------------------------------------------
function CameraRig() {
  useFrame((state) => {
    // Gently drift camera based on mouse — at most ±0.6 units in x/y.
    const targetX = state.mouse.x * 0.6;
    const targetY = state.mouse.y * 0.4;
    state.camera.position.x += (targetX - state.camera.position.x) * 0.04;
    state.camera.position.y += (targetY - state.camera.position.y) * 0.04;
    state.camera.lookAt(0, 0, 0);
  });
  return null;
}


// ---------------------------------------------------------------------------
// Top-level scene
// ---------------------------------------------------------------------------
const Hero3D = ({ height = '100vh', interactive = false }) => {
  return (
    <Canvas
      style={{
        position: 'fixed', top: 0, left: 0, width: '100%', height,
        zIndex: 0, pointerEvents: interactive ? 'auto' : 'none',
      }}
      dpr={[1, 1.5]}             // cap pixel ratio for perf on retina
      gl={{ antialias: true, alpha: true }}
      camera={{ position: [0, 0, 6.5], fov: 55 }}
    >
      {/* Background gradient handled by CSS underneath; transparent canvas. */}
      <Suspense fallback={null}>
        <Stars
          radius={60} depth={40} count={2200} factor={2.2}
          saturation={0} fade speed={0.4}
        />
        <NetworkCore />
        <OrbitRing count={14} radius={2.6} speed={0.18}  color="#00d4ff" y={ 0.4} tilt={ 0.15} />
        <OrbitRing count={18} radius={3.4} speed={-0.12} color="#aa66ff" y={-0.3} tilt={-0.20} />
        <PacketStream count={120} radius={3.6} color="#00d4ff" />
        <AttackPulses count={4} radius={3.2} />
        {!interactive && <CameraRig />}
        {interactive && <OrbitControls enableZoom={false} enablePan={false} autoRotate />}
      </Suspense>
    </Canvas>
  );
};

export default Hero3D;
