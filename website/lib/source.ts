import { docs } from 'collections/server';
import { loader } from 'fumadocs-core/source';

// See https://fumadocs.dev/docs/headless/source-api
export const source = loader({
  baseUrl: '/docs',
  source: docs.toFumadocsSource(),
});
