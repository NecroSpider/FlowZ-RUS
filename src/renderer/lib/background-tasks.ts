// Requests outlive pages. Identical work joins the existing promise; unrelated keys run independently.
export function createBackgroundTasks() {
  const tasks = new Map<string, Promise<unknown>>();
  const listeners = new Set<() => void>();
  let snapshot: ReadonlySet<string> = new Set();
  const notify = () => {
    snapshot = new Set(tasks.keys());
    listeners.forEach((listener) => listener());
  };
  return {
    subscribe(listener: () => void) {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
    getSnapshot: () => snapshot,
    run<T>(key: string, work: () => Promise<T>): Promise<T> {
      const existing = tasks.get(key);
      if (existing) return existing as Promise<T>;
      const task = Promise.resolve()
        .then(work)
        .finally(() => {
          tasks.delete(key);
          notify();
        });
      tasks.set(key, task);
      notify();
      return task;
    },
  };
}
export const backgroundTasks = createBackgroundTasks();
