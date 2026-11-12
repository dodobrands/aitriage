'use client'
import { useEffect } from "react";

export function Widget() {
  useEffect(() => {
    // ruleid: ENTR-09
    fetch("/api/x", { headers: { Authorization: `Bearer ${process.env.API_TOKEN}` } });
  }, []);
  return null;
}
