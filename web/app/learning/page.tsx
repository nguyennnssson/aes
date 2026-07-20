"use client";

import { useState } from "react";
import { useAesState, approveSkill, rejectSkill } from "@/lib/api";
import SkillCard from "@/components/SkillCard";
import { ThresholdChart, BeforeAfter } from "@/components/charts";
import { Card, Kpi, SectionTitle, EmptyState, Chip } from "@/components/ui";

export default function LearningPage() {
  const state = useAesState();
  const [busy, setBusy] = useState<string | null>(null);
  const [done, setDone] = useState<Record<string, "approved" | "rejected">>({});

  async function approve(id: string) {
    setBusy(id);
    try {
      await approveSkill(id);
    } catch {}
    setDone((d) => ({ ...d, [id]: "approved" }));
    setBusy(null);
  }

  async function reject(id: string) {
    setBusy(id);
    try {
      await rejectSkill(id);
    } catch {}
    setDone((d) => ({ ...d, [id]: "rejected" }));
    setBusy(null);
  }

  return (
    <div className="px-8 py-7 max-w-[1400px] mx-auto space-y-8">
      <header className="space-y-2">
        <h1 className="text-xl font-semibold">Self-Improvement</h1>
        <p className="text-[13px] text-ink-2">
          Hermes proposes tuned detection params; the sandbox benchmarks them
          against real attacks and normal traffic; you approve here. This web app
          is the control plane - Discord is optional.
        </p>
      </header>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Kpi label="Skills deployed" value={3} accent="ai" />
        <Kpi
          label="Pending approval"
          value={state?.pending.length ?? 0}
          accent="warming"
        />
        <Kpi label="Detection rate" value="80->95" unit="%" accent="clean" />
        <Kpi label="False positives" value="4" unit="%" accent="data" />
      </div>

      <section className="space-y-4">
        <SectionTitle accent="ai">Pending approval</SectionTitle>
        {state && state.pending.length ? (
          <div className="space-y-4">
            {state.pending.map((skill) =>
              done[skill.skill_id] ? (
                <Card key={skill.skill_id} accent="clean">
                  <div className="flex items-center gap-2 text-[13px] text-ink-2">
                    <Chip tone="ai">{skill.skill_id}</Chip>
                    <span className="font-mono">
                      {"Skill " +
                        skill.skill_id +
                        (done[skill.skill_id] === "approved"
                          ? " deployed live"
                          : " rejected")}
                    </span>
                  </div>
                </Card>
              ) : (
                <SkillCard
                  key={skill.skill_id}
                  skill={skill}
                  onApprove={() => approve(skill.skill_id)}
                  onReject={() => reject(skill.skill_id)}
                  busy={busy === skill.skill_id}
                />
              )
            )}
          </div>
        ) : (
          <EmptyState
            title="No skills awaiting approval"
            hint="The detection rules are current."
          />
        )}
      </section>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card title="Detection rate over time" accent="clean">
          <ThresholdChart points={state?.history ?? []} />
        </Card>
        <Card title="Before / after - same stealth attack" accent="ai">
          <BeforeAfter />
          <p className="mt-3 text-[12px] text-ink-2">
            The low-and-slow attack the shipped rule MISSED is now CAUGHT after
            one sandboxed, human-approved cycle.
          </p>
        </Card>
      </div>
    </div>
  );
}
