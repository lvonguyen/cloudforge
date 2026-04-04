import Layout from '@theme/Layout';
import Link from '@docusaurus/Link';
import styles from './index.module.css';

const highlights = [
  {value: '89', label: 'OpenAPI operations'},
  {value: '17', label: 'Remediation handlers'},
  {value: '300K', label: 'Public demo corpus'},
  {value: '4', label: 'Ticket providers incl. mock'},
];

const entryPoints = [
  {
    title: 'Architecture',
    description: 'Start with HLD, DDD, DR/BC, and the ADR trail behind the current platform shape.',
    to: '/docs/core/architecture/HLD',
  },
  {
    title: 'API And Schema',
    description: 'Use the OpenAPI YAML plus the markdown endpoint reference while the interactive explorer stays deferred.',
    to: '/docs/api',
  },
  {
    title: 'Operations',
    description: 'Deployment, identity, remediation, and teardown runbooks for the live Fly.io plus Cloudflare Pages topology.',
    to: '/docs/core/runbooks/deployment',
  },
  {
    title: 'Auth Decision',
    description: 'See why CloudForge keeps SPA PKCE today and what would be required before moving to a BFF.',
    to: '/docs/core/architecture/adr/ADR-021-spa-pkce-vs-bff',
  },
];

export default function Home(): JSX.Element {
  return (
    <Layout
      title="CloudForge Docs"
      description="CloudForge platform documentation, operational runbooks, ADRs, and API reference."
    >
      <main className={styles.page}>
        <section className={styles.hero}>
          <div className={styles.heroCopy}>
            <p className={styles.eyebrow}>CloudForge standardized docs</p>
            <h1>Platform docs for the current CloudForge deployment model.</h1>
            <p className={styles.summary}>
              This site is the operational and architectural source of truth for CloudForge:
              Cloudflare Pages frontend, Fly.io API, frontend-owned Okta SPA PKCE, backend JWT validation,
              and the current 300K-finding public demo footprint.
            </p>
            <div className={styles.actions}>
              <Link className="button button--primary button--lg" to="/docs/intro">
                Open Docs
              </Link>
              <Link className="button button--secondary button--lg" to="/docs/api">
                API Schema
              </Link>
            </div>
          </div>
          <div className={styles.heroPanel}>
            <p className={styles.panelTitle}>Standardization notes</p>
            <ul className={styles.notes}>
              <li>CloudForge branding is the active public name across docs-site and current docs.</li>
              <li>Legacy `AEGIS_*`, `aegis-*`, and `/icons/aegis-logo.svg` references remain only where compatibility matters.</li>
              <li>Interactive OpenAPI explorer is still deferred; the YAML spec and markdown reference are the supported path today.</li>
            </ul>
          </div>
        </section>

        <section className={styles.metrics}>
          {highlights.map((item) => (
            <article key={item.label} className={styles.metricCard}>
              <strong>{item.value}</strong>
              <span>{item.label}</span>
            </article>
          ))}
        </section>

        <section className={styles.section}>
          <div className={styles.sectionHeader}>
            <p className={styles.eyebrow}>Start here</p>
            <h2>Entry points by job to be done.</h2>
          </div>
          <div className={styles.cardGrid}>
            {entryPoints.map((item) => (
              <Link key={item.title} className={styles.card} to={item.to}>
                <h3>{item.title}</h3>
                <p>{item.description}</p>
                <span>Open section</span>
              </Link>
            ))}
          </div>
        </section>

        <section className={styles.section}>
          <div className={styles.sectionHeader}>
            <p className={styles.eyebrow}>Quickstart</p>
            <h2>Work on the docs locally.</h2>
          </div>
          <div className={styles.quickstart}>
            <pre>
              <code>{`cd docs-site
npm install
npm run start

# production build
npm run build`}</code>
            </pre>
            <div className={styles.quickstartNotes}>
              <p>The docs source lives in `../docs`.</p>
              <p>Diagram rendering and visual QA are handled separately from this docs-content pass.</p>
              <p>Use the sidebar for current platform docs; treat archive and research content as historical context.</p>
            </div>
          </div>
        </section>
      </main>
    </Layout>
  );
}
