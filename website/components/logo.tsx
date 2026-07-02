/**
 * Confidential AI wordmark. Uses `currentColor` so it inherits the text color of
 * its container — readable in both light and dark themes.
 */
export function Logo({ height = 22 }: { height?: number }) {
  return (
    <svg
      viewBox="0 0 459 130"
      height={height}
      style={{ height, width: "auto" }}
      fill="currentColor"
      aria-hidden="true"
    >
      <path d="M1.49012e-06 0H42V21.9966H27V106.997L42 106.997V128.997H0L1.49012e-06 0Z" />
      <path d="M459 0L416 0.00340271V21.838H431.944V106.695H416V129.522H459V0Z" />
      <path d="M388 4H70V125H388V4Z" />
    </svg>
  );
}
