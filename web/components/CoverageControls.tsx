"use client";

import { useEffect } from "react";

/**
 * The catalog's sections are native <details>, so the page reads and folds
 * without JavaScript. This adds the two things <details> cannot do alone:
 * open the section a shared link points at, and expand or collapse the lot.
 */
export default function CoverageControls() {
  useEffect(() => {
    const openFromHash = () => {
      const id = decodeURIComponent(window.location.hash.slice(1));
      if (!id) return;
      const target = document.getElementById(id);
      if (target instanceof HTMLDetailsElement) target.open = true;
    };
    openFromHash();
    window.addEventListener("hashchange", openFromHash);
    return () => window.removeEventListener("hashchange", openFromHash);
  }, []);

  const setAll = (open: boolean) => {
    for (const el of document.querySelectorAll<HTMLDetailsElement>("details[data-category]")) el.open = open;
  };

  const button =
    "rounded-lg border border-slate-200 px-3 py-1.5 text-xs font-medium text-slate-600 transition hover:bg-slate-50 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800";

  return (
    <div className="flex items-center gap-2">
      <button type="button" onClick={() => setAll(true)} className={button}>
        Expand all
      </button>
      <button type="button" onClick={() => setAll(false)} className={button}>
        Collapse all
      </button>
    </div>
  );
}
