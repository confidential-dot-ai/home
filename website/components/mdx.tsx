import defaultMdxComponents from 'fumadocs-ui/mdx';
import type { MDXComponents } from 'mdx/types';
import { Card, Cards } from 'fumadocs-ui/components/card';
import { Tab, Tabs } from 'fumadocs-ui/components/tabs';
import { Step, Steps } from 'fumadocs-ui/components/steps';
import { Accordion, Accordions } from 'fumadocs-ui/components/accordion';
import { Callout } from 'fumadocs-ui/components/callout';
import { JourneyNav } from '@/components/journey-nav';
import { FourSteps } from '@/components/four-steps';
import { ThemedDiagram } from '@/components/diagram';

export function getMDXComponents(components?: MDXComponents): MDXComponents {
  return {
    ...defaultMdxComponents,
    // Swap committed dark SVG diagrams for their light variant per theme.
    img: (props) => {
      const src = typeof props.src === 'string' ? props.src : '';
      if (src.startsWith('/diagrams/') && src.endsWith('.svg')) {
        return (
          <ThemedDiagram src={src} alt={typeof props.alt === 'string' ? props.alt : ''} />
        );
      }
      const DefaultImg = defaultMdxComponents.img;
      // eslint-disable-next-line @next/next/no-img-element
      return DefaultImg ? <DefaultImg {...props} /> : <img {...props} alt={props.alt ?? ''} />;
    },
    Card,
    Cards,
    Tab,
    Tabs,
    Step,
    Steps,
    Accordion,
    Accordions,
    Callout,
    JourneyNav,
    FourSteps,
    ...components,
  };
}

export const useMDXComponents = getMDXComponents;

declare global {
  type MDXProvidedComponents = ReturnType<typeof getMDXComponents>;
}
