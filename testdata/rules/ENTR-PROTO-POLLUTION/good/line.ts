export function first(raw: string, arr: number[]) {
  const data = JSON.parse(raw); arr[0] = data.count;
  return arr;
}
