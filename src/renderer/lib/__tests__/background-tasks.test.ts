import { createBackgroundTasks } from '../background-tasks';

it('keeps unrelated requests responsive and deduplicates a pending request', async () => {
  const tasks = createBackgroundTasks();
  let finish!: () => void;
  const first = tasks.run(
    'subscription:a',
    () =>
      new Promise<void>((resolve) => {
        finish = resolve;
      })
  );
  const duplicate = jest.fn(async () => {});
  expect(tasks.run('subscription:a', duplicate)).toBe(first);
  await expect(tasks.run('subscription:b', async () => 42)).resolves.toBe(42);
  expect(tasks.getSnapshot().has('subscription:a')).toBe(true);
  expect(duplicate).not.toHaveBeenCalled();
  finish();
  await first;
  expect(tasks.getSnapshot().size).toBe(0);
});

it('state survives view unsubscribe/remount and failures allow retry', async () => {
  const tasks = createBackgroundTasks();
  const listener = jest.fn();
  const off = tasks.subscribe(listener);
  let fail!: (e: Error) => void;
  const run = tasks.run(
    'app-update-check',
    () =>
      new Promise<void>((_, reject) => {
        fail = reject;
      })
  );
  const rejected = expect(run).rejects.toThrow('offline');
  off();
  await Promise.resolve();
  expect(tasks.getSnapshot().has('app-update-check')).toBe(true);
  const onRemount = jest.fn();
  tasks.subscribe(onRemount);
  fail(new Error('offline'));
  await rejected;
  expect(onRemount).toHaveBeenCalled();
  await expect(tasks.run('app-update-check', async () => 'ok')).resolves.toBe('ok');
});
