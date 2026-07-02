/**
 * Theme-aware diagram. The committed SVGs are dark-palette and `<img>`-embedded,
 * so page CSS variables can't reach inside them. We ship a recolored `-light.svg`
 * beside each and show the right one per theme with a no-JS `.dark` CSS rule
 * (see .diagram-frame in globals.css).
 */
export function ThemedDiagram({ src, alt }: { src: string; alt?: string }) {
  const light = src.replace(/\.svg$/, '-light.svg');
  return (
    <span className="diagram-frame not-prose">
      {/* eslint-disable-next-line @next/next/no-img-element */}
      <img className="diagram-light" src={light} alt={alt ?? ''} loading="lazy" />
      {/* eslint-disable-next-line @next/next/no-img-element */}
      <img className="diagram-dark" src={src} alt="" aria-hidden="true" loading="lazy" />
    </span>
  );
}
