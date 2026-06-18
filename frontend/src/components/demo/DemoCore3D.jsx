/**
 * DemoCore3D — compact react-three-fiber "network core" used inside the
 * MotionDemo hero panel. It fills its parent container (the parallax mask
 * sets the size) and renders a wireframe core with two orbiting node rings
 * and inward-flowing packet particles.
 *
 * Kept deliberately lightweight (small node / particle counts) because it
 * lives inside a scroll-parallax card rather than as a full-page background.
 * Pointer events are disabled so it never intercepts clicks on the hero CTAs.
 */
import React, { useRef, useMemo, Suspense } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';
import * as THREE from 'three';

function Core() {
  const outer = useRef();
  const inner = useRef();
  useFrame((_, delta) => {
    if (outer.current) {
      outer.current.rotation.y += delta * 0.14;
      outer.current.rotation.x += delta * 0.05;
    }
    if (inner.current) inner.current.rotation.y -= delta * 0.2;
  });
  return (
    <group>
      <mesh ref={outer}>
        <icosahedronGeometry args={[1.5, 1]} />
        <meshBasicMaterial color="#89ceff" wireframe transparent opacity={0.5} />
      </mesh>
      <mesh ref={inner}>
        <sphereGeometry args={[1.1, 24, 24]} />
        <meshBasicMaterial color="#00ff88" wireframe transparent opacity={0.18} />
      </mesh>
      <mesh>
        <sphereGeometry args={[0.45, 16, 16]} />
        <meshBasicMaterial color="#89ceff" transparent opacity={0.35} />
      </mesh>
    </group>
  );
}

function OrbitRing({ count = 12, radius = 2.6, speed = 0.16, color = '#89ceff', tilt = 0 }) {
  const group = useRef();
  const nodes = useMemo(
    () =>
      Array.from({ length: count }).map((_, i) => {
        const a = (i / count) * Math.PI * 2;
        return [Math.cos(a) * radius, 0, Math.sin(a) * radius];
      }),
    [count, radius]
  );
  useFrame((_, delta) => {
    if (group.current) group.current.rotation.y += delta * speed;
  });
  return (
    <group ref={group} rotation={[tilt, 0, 0]}>
      {nodes.map((p, i) => (
        <mesh key={i} position={p}>
          <octahedronGeometry args={[0.08, 0]} />
          <meshBasicMaterial color={color} />
        </mesh>
      ))}
      <mesh rotation={[Math.PI / 2, 0, 0]}>
        <torusGeometry args={[radius, 0.004, 8, 96]} />
        <meshBasicMaterial color={color} transparent opacity={0.2} />
      </mesh>
    </group>
  );
}

function Packets({ count = 60, radius = 3 }) {
  const ref = useRef();
  const data = useMemo(
    () =>
      Array.from({ length: count }).map(() => {
        const a = Math.random() * Math.PI * 2;
        const r = radius * (0.7 + Math.random() * 0.4);
        return {
          x0: Math.cos(a) * r,
          z0: Math.sin(a) * r,
          y0: (Math.random() - 0.5) * 1,
          speed: 0.15 + Math.random() * 0.35,
          offset: Math.random(),
        };
      }),
    [count, radius]
  );
  const initial = useMemo(() => {
    const arr = new Float32Array(count * 3);
    data.forEach((p, i) => {
      arr[i * 3] = p.x0;
      arr[i * 3 + 1] = p.y0;
      arr[i * 3 + 2] = p.z0;
    });
    return arr;
  }, [count, data]);
  useFrame((state) => {
    if (!ref.current) return;
    const t = state.clock.elapsedTime;
    const pos = ref.current.geometry.attributes.position.array;
    data.forEach((p, i) => {
      const inv = 1 - ((t * p.speed + p.offset) % 1);
      pos[i * 3] = p.x0 * inv;
      pos[i * 3 + 1] = p.y0 * inv;
      pos[i * 3 + 2] = p.z0 * inv;
    });
    ref.current.geometry.attributes.position.needsUpdate = true;
  });
  return (
    <points ref={ref}>
      <bufferGeometry>
        <bufferAttribute attach="attributes-position" count={count} array={initial} itemSize={3} />
      </bufferGeometry>
      <pointsMaterial color="#89ceff" size={0.06} transparent opacity={0.85} sizeAttenuation />
    </points>
  );
}

export default function DemoCore3D() {
  return (
    <Canvas
      style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', pointerEvents: 'none' }}
      dpr={[1, 1.5]}
      gl={{ antialias: true, alpha: true }}
      camera={{ position: [0, 0, 6], fov: 52 }}
    >
      <Suspense fallback={null}>
        <Core />
        <OrbitRing count={12} radius={2.4} speed={0.18} color="#89ceff" tilt={0.18} />
        <OrbitRing count={16} radius={3.1} speed={-0.13} color="#00ff88" tilt={-0.22} />
        <Packets count={70} radius={3.2} />
      </Suspense>
    </Canvas>
  );
}
