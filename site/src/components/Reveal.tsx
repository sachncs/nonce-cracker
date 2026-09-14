import {
  useEffect,
  useRef,
  useState,
  type CSSProperties,
  type ReactNode,
} from "react";

const EASE = "cubic-bezier(0.16, 1, 0.3, 1)";

function useRevealed(rootMargin = "0px 0px 80px 0px") {
  const ref = useRef<HTMLDivElement | null>(null);
  const [shown, setShown] = useState(false);

  useEffect(() => {
    const el = ref.current;
    if (!el) {
      setShown(true);
      return;
    }

    if (typeof IntersectionObserver === "undefined") {
      setShown(true);
      return;
    }

    let io: IntersectionObserver | undefined;
    let cancelled = false;
    const show = () => {
      if (!cancelled) setShown(true);
    };

    io = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          if (e.isIntersecting) {
            show();
            io?.disconnect();
          }
        });
      },
      { threshold: 0, rootMargin }
    );
    io.observe(el);

    // Robust fallback: force reveal if IO never fires
    // (headless renderers, hidden tabs, prerendered DOMs, etc.).
    const timer = window.setTimeout(show, 800);

    return () => {
      cancelled = true;
      if (io) io.disconnect();
      window.clearTimeout(timer);
    };
  }, [rootMargin]);

  return { ref, shown };
}

type RevealProps = {
  children: ReactNode;
  className?: string;
  delay?: number;
};

export function Reveal({ children, className, delay = 0 }: RevealProps) {
  const { ref, shown } = useRevealed();
  const style: CSSProperties = {
    opacity: shown ? 1 : 0,
    transform: shown ? "translateY(0)" : "translateY(20px)",
    transition: `opacity 700ms ${EASE} ${delay * 1000}ms, transform 700ms ${EASE} ${delay * 1000}ms`,
    willChange: shown ? "auto" : "opacity, transform",
  };
  return (
    <div ref={ref} className={className} style={style}>
      {children}
    </div>
  );
}

export function Stagger({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  const { ref, shown } = useRevealed();
  const style: CSSProperties = {
    opacity: shown ? 1 : 0,
    transform: shown ? "translateY(0)" : "translateY(8px)",
    transition: `opacity 500ms ${EASE}, transform 500ms ${EASE}`,
    willChange: shown ? "auto" : "opacity, transform",
  };
  return (
    <div ref={ref} className={className} style={style}>
      {children}
    </div>
  );
}

export function StaggerItem({
  children,
  className,
  index = 0,
}: {
  children: ReactNode;
  className?: string;
  index?: number;
}) {
  const { ref, shown } = useRevealed();
  const style: CSSProperties = {
    opacity: shown ? 1 : 0,
    transform: shown ? "translateY(0)" : "translateY(16px)",
    transition: `opacity 600ms ${EASE} ${index * 60}ms, transform 600ms ${EASE} ${index * 60}ms`,
    willChange: shown ? "auto" : "opacity, transform",
  };
  return (
    <div ref={ref} className={className} style={style}>
      {children}
    </div>
  );
}