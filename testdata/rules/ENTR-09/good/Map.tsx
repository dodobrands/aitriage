"use client";

export default function Map() {
  const token = process.env.NEXT_PUBLIC_MAPBOX_TOKEN;
  return <div data-token-present={Boolean(token)} />;
}
