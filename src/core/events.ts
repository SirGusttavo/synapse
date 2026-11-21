import type { AuditEventRecord, TaskRecord } from "./types.js";

export interface SynapseEventMap {
  "task:created": TaskRecord;
  "task:updated": TaskRecord;
  "audit:recorded": AuditEventRecord;
}

type EventListener<T> = (payload: T) => void;

export class SynapseEventBus {
  private readonly listeners = new Map<keyof SynapseEventMap, Set<EventListener<unknown>>>();

  public on<K extends keyof SynapseEventMap>(
    event: K,
    listener: EventListener<SynapseEventMap[K]>,
  ): () => void {
    let set = this.listeners.get(event);
    if (!set) {
      set = new Set();
      this.listeners.set(event, set);
    }
    const wrapped = listener as EventListener<unknown>;
    set.add(wrapped);

    return () => {
      set?.delete(wrapped);
    };
  }

  public emit<K extends keyof SynapseEventMap>(event: K, payload: SynapseEventMap[K]): void {
    const set = this.listeners.get(event);
    if (!set) {
      return;
    }
    for (const listener of set) {
      listener(payload);
    }
  }
}
