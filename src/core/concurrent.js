const CONCURRENT_LIMIT = 5;

export async function runConcurrently(tasks, name, spinner) {
  let completed = 0;
  let failed = 0;
  const total = tasks.length;

  const results = [];
  const queue = [...tasks];

  async function worker() {
    while (queue.length > 0) {
      const task = queue.shift();
      if (!task) return;

      try {
        spinner.text = `[${name}] ${completed + 1}/${total}`;
        await task.fn();
        completed++;
      } catch {
        failed++;
      }
    }
  }

  const workers = Array.from({ length: CONCURRENT_LIMIT }, () => worker());
  await Promise.all(workers);

  spinner.text = `[${name}] done (${completed} pass, ${failed} fail)`;
  return { completed, failed };
}

export function splitIntoFifoGroups(modules, groupSize) {
  const groups = [];
  for (let i = 0; i < modules.length; i += groupSize) {
    groups.push(modules.slice(i, i + groupSize));
  }
  return groups;
}
