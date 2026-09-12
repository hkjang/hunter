import { useEffect, useRef, type RefObject } from "react";

// The heading gives a screen reader the new page name and places the next Tab
// inside its content. Loading/permission states can use the named main region.
export function focusMainContent(main: HTMLElement | null) {
  if (!main || main.closest("[inert]")) return;
  const target = main.querySelector<HTMLElement>("h1") || main;
  if (!target.hasAttribute("tabindex")) target.setAttribute("tabindex", "-1");
  target.dataset.mainFocus = "true";
  target.focus({ preventScroll: true });
  target.scrollIntoView({ block: "start", behavior: "instant" });
}

export function useRouteFocus(
  pathname: string,
  main: RefObject<HTMLElement | null>,
) {
  const previous = useRef(pathname);
  useEffect(() => {
    if (previous.current === pathname) return;
    previous.current = pathname;
    // Let closing menus finish their focus restoration first. A fresh user
    // interaction wins over this route announcement, as does a newly open form.
    // Search, sorting, pagination and detail tabs never enter this effect.
    let attempts = 0;
    let timer = window.setTimeout(announce, 50);
    function announce() {
      // The mobile sidebar closes in a separate state update after navigation.
      // Wait for its inert background to become available, even on a busy tab.
      if (main.current?.closest("[inert]") && attempts++ < 10) {
        timer = window.setTimeout(announce, 25);
        return;
      }
      const dialog = document.activeElement?.closest('[role="dialog"]');
      if (dialog && !dialog.closest(".hunter-quick-navigation")) return;
      focusMainContent(main.current);
    }
    const cancel = () => window.clearTimeout(timer);
    document.addEventListener("keydown", cancel, true);
    document.addEventListener("pointerdown", cancel, true);
    return () => {
      cancel();
      document.removeEventListener("keydown", cancel, true);
      document.removeEventListener("pointerdown", cancel, true);
    };
  }, [pathname, main]);
}
