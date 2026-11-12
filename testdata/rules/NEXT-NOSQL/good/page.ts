export function pick(routes: { id: string }[], params: { id: string }) {
  return routes.find(params.id ? (r) => r.id === params.id : () => false);
}
