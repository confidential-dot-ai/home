import { defineConfig, defineDocs } from 'fumadocs-mdx/config';

export const docs = defineDocs({
  dir: 'content/docs',
});

export default defineConfig({
  mdxOptions: {
    // Keep image `src` as the literal public path (e.g. /diagrams/x.svg) instead
    // of statically importing it into a hashed asset. Our themed `img` component
    // (components/mdx.tsx) swaps in the light/dark diagram variant by path.
    remarkImageOptions: false,
  },
});
