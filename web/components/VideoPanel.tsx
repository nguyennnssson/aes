"use client";

import { useEffect, useRef, useState } from "react";
import type { DeviceStatus } from "@/lib/types";
import { statusMeta, cx } from "@/lib/format";

interface VideoPanelProps {
  status: DeviceStatus;
  label: string;
  model: string;
  big?: boolean;
  autoOn?: boolean;
}

function rgba(hex: string, a: number): string {
  const h = hex.replace("#", "");
  const r = parseInt(h.slice(0, 2), 16);
  const g = parseInt(h.slice(2, 4), 16);
  const b = parseInt(h.slice(4, 6), 16);
  return `rgba(${r}, ${g}, ${b}, ${a})`;
}

export default function VideoPanel({ status, label, model, big = false, autoOn = false }: VideoPanelProps) {
  const meta = statusMeta(status);
  const isAttack = status === "attack";
  const isElevated = status === "elevated";
  const isOffline = status === "offline";

  const videoRef = useRef<HTMLVideoElement>(null);
  const [camOn, setCamOn] = useState(autoOn);
  const [camError, setCamError] = useState<string | null>(null);

  // Starts the laptop's webcam when the toggle flips on, and always releases
  // it again — on toggle-off, on error, and on unmount — so the camera light
  // never stays on after this panel stops showing it.
  useEffect(() => {
    if (!camOn) return;
    if (!navigator.mediaDevices?.getUserMedia) {
      setCamError("Camera not supported in this browser");
      setCamOn(false);
      return;
    }
    let cancelled = false;
    let stream: MediaStream | null = null;
    navigator.mediaDevices
      .getUserMedia({ video: true, audio: false })
      .then((s) => {
        if (cancelled) {
          s.getTracks().forEach((t) => t.stop());
          return;
        }
        stream = s;
        if (videoRef.current) videoRef.current.srcObject = s;
      })
      .catch((err) => {
        if (!cancelled) {
          setCamError(err?.name === "NotAllowedError" ? "Camera permission denied" : "Camera unavailable");
          setCamOn(false);
        }
      });
    return () => {
      cancelled = true;
      stream?.getTracks().forEach((t) => t.stop());
    };
  }, [camOn]);

  // LIGHT camera scene — soft daylight gradient so it fits the white theme.
  const scene: React.CSSProperties = {
    backgroundImage:
      "linear-gradient(168deg, #ffffff 0%, #eef3f9 44%, #d8e3f0 100%), radial-gradient(120% 70% at 24% 16%, rgba(255,255,255,0.95) 0%, rgba(255,255,255,0) 55%)",
    borderColor: rgba(meta.hex, isOffline ? 0.4 : 0.85),
    boxShadow: isAttack
      ? `inset 0 0 0 2px ${rgba(meta.hex, 0.5)}, 0 0 22px ${rgba(meta.hex, 0.28)}`
      : `inset 0 0 0 1px ${rgba(meta.hex, 0.4)}`,
  };

  return (
    <div className="space-y-2">
      <div
        className={cx("cam-scan relative w-full overflow-hidden rounded-xl border", big ? "aspect-video" : "h-32")}
        style={scene}
      >
        {camOn ? (
          <video
            ref={videoRef}
            autoPlay
            playsInline
            muted
            className="absolute inset-0 h-full w-full object-cover bg-black"
          />
        ) : (
          <>
            {/* faint floor band + horizon for camera realism */}
            <div
              className="pointer-events-none absolute inset-0 opacity-60"
              style={{ backgroundImage: "linear-gradient(0deg, rgba(148,163,184,0.20) 0%, transparent 32%)" }}
            />
            <div
              className="pointer-events-none absolute left-0 right-0"
              style={{ top: "62%", borderTop: "1px solid rgba(148,163,184,0.28)" }}
            />
          </>
        )}

        {/* status wash */}
        {isAttack && <div className="pointer-events-none absolute inset-0" style={{ background: rgba(meta.hex, 0.12) }} />}
        {isElevated && <div className="pointer-events-none absolute inset-0" style={{ background: rgba(meta.hex, 0.1) }} />}

        {/* centered banner */}
        {isAttack && (
          <div className="pointer-events-none absolute inset-0 flex items-center justify-center">
            <span className="anim-pulse-red rounded-md border border-attack bg-attack-soft px-3 py-1 font-mono text-xs font-bold uppercase tracking-[0.18em] text-attack sm:text-sm">
              Signal Anomaly
            </span>
          </div>
        )}
        {isOffline && !camOn && (
          <div className="pointer-events-none absolute inset-0 flex items-center justify-center">
            <span className="font-mono text-xs uppercase tracking-[0.18em] text-ink-muted">No Signal</span>
          </div>
        )}

        {/* top-left REC row */}
        <div className="absolute left-2.5 top-2.5 flex flex-col gap-0.5">
          <div className="flex items-center gap-1.5">
            <span className="dot-pulse-red h-2 w-2 rounded-full bg-attack" />
            <span className="font-mono text-[11px] font-semibold leading-none text-ink">{label}</span>
          </div>
          <span className="text-[10px] leading-none text-ink-muted">{model}</span>
        </div>

        {/* top-right LIVE */}
        <div className="absolute right-2.5 top-2.5 flex items-center gap-1.5">
          <span className="h-1.5 w-1.5 rounded-full bg-data" />
          <span className="font-mono text-[10px] font-semibold uppercase tracking-wider text-ink-2">
            {isOffline ? "Lost" : "Live"}
          </span>
        </div>

        {/* bottom-left resolution */}
        <div className="absolute bottom-2 left-2.5">
          <span className="font-mono text-[10px] text-ink-muted">1920x1080 &middot; 24 fps</span>
        </div>

        {/* bottom-right status */}
        <div className="absolute bottom-2 right-2.5">
          <span className="font-mono text-[10px] font-semibold uppercase tracking-wider" style={{ color: meta.hex }}>
            {meta.label}
          </span>
        </div>
      </div>

      <div className="flex items-center gap-2">
        <button
          type="button"
          onClick={() => {
            setCamError(null);
            setCamOn((v) => !v);
          }}
          className={cx(
            "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 font-mono text-[10px] font-semibold uppercase tracking-wide transition-colors",
            camOn ? "border-clean bg-clean-soft text-clean" : "border-line bg-surface-2 text-ink-2"
          )}
        >
          <span className={cx("h-1.5 w-1.5 rounded-full", camOn ? "bg-clean anim-breathe-green" : "bg-ink-muted")} />
          {camOn ? "Cam on" : "Cam off"}
        </button>
        {camError && <span className="font-mono text-[10px] text-attack">{camError}</span>}
      </div>
    </div>
  );
}
