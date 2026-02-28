const queue = [];
let active = 0;

const concurrency = Number.parseInt(process.env.API_SCANNER_CONCURRENCY || '2', 10);

export function enqueue(task) {
  queue.push(task);
  pump();
}

function pump() {
  while (active < concurrency && queue.length > 0) {
    const task = queue.shift();
    active += 1;

    Promise.resolve()
      .then(task)
      .catch(() => {})
      .finally(() => {
        active -= 1;
        pump();
      });
  }
}
