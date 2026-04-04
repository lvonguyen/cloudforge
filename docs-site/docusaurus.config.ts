import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

const config: Config = {
  title: 'CloudForge Docs',
  tagline: 'Cloud security operations and governance reference docs',
  favicon: 'img/favicon.svg',

  url: 'https://docs.cloudforge.lvonguyen.com',
  baseUrl: '/',

  organizationName: 'lvonguyen',
  projectName: 'cloudforge',

  onBrokenLinks: 'warn',
  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  markdown: {
    mermaid: true,
    format: 'detect',
    hooks: {
      onBrokenMarkdownLinks: 'warn',
    },
    mdx1Compat: {
      comments: true,
      admonitions: true,
      headingIds: true,
    },
  },

  themes: ['@docusaurus/theme-mermaid'],

  staticDirectories: ['static', '../docs/core/diagrams'],

  presets: [
    [
      'classic',
      {
        docs: {
          path: '../docs',
          sidebarPath: './sidebars.ts',
          editUrl: 'https://github.com/lvonguyen/cloudforge/tree/main/',
          exclude: [
            'archive/**',
            'qa/**',
            'research/INDUSTRY_LANDSCAPE.md',
            'cspm/archive/**',
            '**/README.md',
            'cspm/STANDARDS.md',
            'STANDARDS.md',
            'research/whitelabel-exploration.md',
            'research/puppygraph-poc.md',
          ],
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      } satisfies Preset.Options,
    ],
  ],

  themeConfig: {
    colorMode: {
      defaultMode: 'dark',
      disableSwitch: false,
      respectPrefersColorScheme: true,
    },

    navbar: {
      title: 'CloudForge',
      items: [
        {
          type: 'docSidebar',
          sidebarId: 'docsSidebar',
          position: 'left',
          label: 'Docs',
        },
        {
          to: '/docs/api',
          label: 'API Schema',
          position: 'left',
        },
        {
          to: '/docs/diagrams',
          label: 'Diagrams',
          position: 'left',
        },
        {
          href: 'https://github.com/lvonguyen/cloudforge',
          label: 'GitHub',
          position: 'right',
        },
      ],
    },

    footer: {
      style: 'dark',
      links: [
        {
          title: 'Documentation',
          items: [
            {label: 'Architecture', to: '/docs/core/architecture/HLD'},
            {label: 'API Schema', to: '/docs/api'},
            {label: 'Runbooks', to: '/docs/core/runbooks/deployment'},
          ],
        },
        {
          title: 'Project',
          items: [
            {label: 'GitHub', href: 'https://github.com/lvonguyen/cloudforge'},
            {label: 'Live Demo', href: 'https://cloudforge.lvonguyen.com'},
          ],
        },
      ],
      copyright: `Copyright ${new Date().getFullYear()} Liem Vo-Nguyen`,
    },

    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
      additionalLanguages: ['bash', 'go', 'hcl', 'json', 'yaml', 'sql', 'rego'],
    },

    mermaid: {
      theme: {light: 'neutral', dark: 'dark'},
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
