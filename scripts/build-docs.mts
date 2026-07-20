import fs from 'node:fs';
import path from 'node:path';

type Page = {
  group: string;
  source: string;
  slug: string;
  title: string;
};

type TocItem = {
  depth: number;
  id: string;
  title: string;
};

const projectRoot = path.resolve(import.meta.dirname, '..');
const outputRoot = path.join(projectRoot, 'docs', 'book');
const productBrandRoot = path.join(projectRoot, 'assets', 'jeth');
const packageManifest = JSON.parse(fs.readFileSync(path.join(projectRoot, 'package.json'), 'utf8')) as {
  version: string;
};
const projectVersion = packageManifest.version;

const pages: Page[] = [
  { group: 'Guides', source: 'docs/guide/README.md', slug: '', title: 'JETH Documentation' },
  {
    group: 'Guides',
    source: 'docs/guide/getting-started.md',
    slug: 'guides/getting-started',
    title: 'Getting started',
  },
  { group: 'Guides', source: 'docs/guide/language-tour.md', slug: 'guides/language-tour', title: 'Language tour' },
  { group: 'Guides', source: 'docs/guide/examples.md', slug: 'guides/examples', title: 'Examples' },

  {
    group: 'Language',
    source: 'docs/guide/language/source-units.md',
    slug: 'language/source-units',
    title: 'Source units and imports',
  },
  {
    group: 'Language',
    source: 'docs/guide/language/contract-structure.md',
    slug: 'language/contract-structure',
    title: 'Contract structure',
  },
  { group: 'Language', source: 'docs/guide/language-reference.md', slug: 'language/types', title: 'Types' },
  {
    group: 'Language',
    source: 'docs/guide/language/value-types.md',
    slug: 'language/value-types',
    title: 'Value types',
  },
  {
    group: 'Language',
    source: 'docs/guide/language/reference-types.md',
    slug: 'language/reference-types',
    title: 'Reference and composite types',
  },
  {
    group: 'Language',
    source: 'docs/guide/language/data-locations.md',
    slug: 'language/data-locations',
    title: 'Data locations and copying',
  },
  {
    group: 'Language',
    source: 'docs/guide/language/expressions.md',
    slug: 'language/expressions',
    title: 'Expressions and operators',
  },
  {
    group: 'Language',
    source: 'docs/guide/language/control-flow.md',
    slug: 'language/control-flow',
    title: 'Statements and control flow',
  },
  { group: 'Language', source: 'docs/guide/language/functions.md', slug: 'language/functions', title: 'Functions' },
  {
    group: 'Language',
    source: 'docs/guide/language/globals-and-builtins.md',
    slug: 'language/globals-and-builtins',
    title: 'Units, globals, and builtins',
  },
  {
    group: 'Language',
    source: 'docs/guide/language/jeth-features.md',
    slug: 'language/jeth-features',
    title: 'JETH-specific features',
  },

  {
    group: 'Contracts',
    source: 'docs/guide/language/inheritance.md',
    slug: 'contracts/inheritance',
    title: 'Constructors and inheritance',
  },
  {
    group: 'Contracts',
    source: 'docs/guide/language/modifiers.md',
    slug: 'contracts/modifiers',
    title: 'Function modifiers',
  },
  {
    group: 'Contracts',
    source: 'docs/guide/language/interfaces-and-calls.md',
    slug: 'contracts/interfaces-and-calls',
    title: 'Interfaces and external calls',
  },
  {
    group: 'Contracts',
    source: 'docs/guide/language/libraries.md',
    slug: 'contracts/libraries',
    title: 'Libraries and using',
  },
  {
    group: 'Contracts',
    source: 'docs/guide/language/events-and-errors.md',
    slug: 'contracts/events-and-errors',
    title: 'Events, errors, and panics',
  },

  {
    group: 'Internals',
    source: 'docs/guide/internals/abi.md',
    slug: 'internals/abi',
    title: 'Contract ABI specification',
  },
  {
    group: 'Internals',
    source: 'docs/guide/internals/storage-layout.md',
    slug: 'internals/storage-layout',
    title: 'Storage layout',
  },
  {
    group: 'Internals',
    source: 'docs/guide/compiler-and-tooling.md',
    slug: 'internals/compiler-and-tooling',
    title: 'Compiler, CLI, and tooling',
  },
  {
    group: 'Internals',
    source: 'docs/guide/contracts-and-abi.md',
    slug: 'internals/artifacts',
    title: 'Contracts and artifacts',
  },

  {
    group: 'Advanced',
    source: 'docs/guide/advanced/contract-creation-and-clones.md',
    slug: 'advanced/contract-creation-and-clones',
    title: 'Contract creation and clones',
  },
  {
    group: 'Advanced',
    source: 'docs/guide/advanced/proxies-and-diamonds.md',
    slug: 'advanced/proxies-and-diamonds',
    title: 'Proxies, beacons, and diamonds',
  },

  {
    group: 'Security',
    source: 'docs/guide/security/considerations.md',
    slug: 'security/considerations',
    title: 'Security considerations',
  },
  {
    group: 'Security',
    source: 'docs/guide/security/compiler-correctness.md',
    slug: 'security/compiler-correctness',
    title: 'Compiler correctness model',
  },

  {
    group: 'Reference',
    source: 'docs/guide/reference/cheatsheet.md',
    slug: 'reference/cheatsheet',
    title: 'Syntax cheatsheet',
  },
  {
    group: 'Reference',
    source: 'docs/guide/reference/differences.md',
    slug: 'reference/differences',
    title: 'Differences from TypeScript and Solidity',
  },
  {
    group: 'Reference',
    source: 'docs/guide/reference/diagnostics.md',
    slug: 'reference/diagnostics',
    title: 'Compiler diagnostics',
  },
  {
    group: 'Reference',
    source: 'docs/guide/reference/known-limitations.md',
    slug: 'reference/known-limitations',
    title: 'Supported features and limitations',
  },
  { group: 'Reference', source: 'SUPPORTED.md', slug: 'reference/feature-matrix', title: 'Complete feature matrix' },

  { group: 'Project', source: 'docs/guide/roadmap.md', slug: 'project/roadmap', title: 'Product roadmap' },
  { group: 'Project', source: 'docs/guide/releasing.md', slug: 'project/releases', title: 'Versioning and releases' },
  { group: 'Project', source: 'README.md', slug: 'project/overview', title: 'Repository overview' },
];

const sourceToPage = new Map(pages.map((page) => [path.resolve(projectRoot, page.source), page]));

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function slugify(value: string): string {
  return (
    value
      .toLowerCase()
      .replace(/<[^>]+>/g, '')
      .replace(/[`*_]/g, '')
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '') || 'section'
  );
}

function outputFile(page: Page): string {
  return page.slug ? path.join(outputRoot, page.slug, 'index.html') : path.join(outputRoot, 'index.html');
}

function relativeUrl(fromPage: Page, toPage: Page, fragment = ''): string {
  const fromDir = path.dirname(outputFile(fromPage));
  const target = outputFile(toPage);
  let relative = path.relative(fromDir, target).split(path.sep).join('/');
  if (!relative.startsWith('.')) relative = './' + relative;
  return relative + fragment;
}

function assetUrl(page: Page, asset: string): string {
  const relative = path.relative(path.dirname(outputFile(page)), path.join(outputRoot, 'assets', asset));
  return relative.split(path.sep).join('/');
}

function resolveLink(page: Page, href: string): string {
  if (/^(https?:|mailto:|tel:|#)/.test(href)) return href;
  const hashIndex = href.indexOf('#');
  const filePart = hashIndex >= 0 ? href.slice(0, hashIndex) : href;
  const fragment = hashIndex >= 0 ? href.slice(hashIndex) : '';
  const sourcePath = path.resolve(projectRoot, path.dirname(page.source), filePart);
  const targetPage = sourceToPage.get(sourcePath);
  if (targetPage) return relativeUrl(page, targetPage, fragment);

  const repositoryRelative = path.relative(projectRoot, sourcePath).split(path.sep).join('/');
  if (!repositoryRelative.startsWith('..')) {
    return `https://github.com/a16k-lab/jeth/blob/main/${repositoryRelative}${fragment}`;
  }
  return href;
}

function resolveImage(page: Page, source: string): string {
  if (/^(?:https?:|data:)/.test(source)) return source;
  const sourcePath = path.resolve(projectRoot, path.dirname(page.source), source);
  const organizationLogo = path.join(projectRoot, 'docs', 'assets', 'a16k-avatar-logo.png');
  if (sourcePath === organizationLogo) return assetUrl(page, 'a16k-avatar-logo.png');
  if (path.dirname(sourcePath) === productBrandRoot) return assetUrl(page, path.basename(sourcePath));
  const repositoryRelative = path.relative(projectRoot, sourcePath).split(path.sep).join('/');
  if (!repositoryRelative.startsWith('..')) {
    return `https://raw.githubusercontent.com/a16k-lab/jeth/main/${repositoryRelative}`;
  }
  return source;
}

function organizationLockup(page: Page): string {
  const logo = assetUrl(page, 'a16k-avatar-logo.png');
  return `<a class="organization-lockup" href="https://github.com/a16k-lab" target="_blank" rel="noreferrer" aria-label="Built by a16k-lab"><img src="${escapeHtml(logo)}" alt="" width="28" height="28"><span>Built by <strong>@a16k-lab</strong></span></a>`;
}

const keywords = new Set([
  'abstract',
  'break',
  'case',
  'catch',
  'class',
  'const',
  'continue',
  'default',
  'delete',
  'do',
  'else',
  'enum',
  'export',
  'extends',
  'false',
  'finally',
  'for',
  'from',
  'get',
  'if',
  'import',
  'interface',
  'let',
  'new',
  'of',
  'return',
  'static',
  'super',
  'switch',
  'this',
  'throw',
  'true',
  'try',
  'type',
  'unchecked',
  'while',
  'void',
]);

const typeNames = new Set([
  'address',
  'Arr',
  'bool',
  'Brand',
  'bytes',
  'error',
  'event',
  'External',
  'indexed',
  'mapping',
  'Payable',
  'Pure',
  'string',
  'View',
  'Visible',
]);

const builtins = new Set([
  'abi',
  'addmod',
  'assert',
  'blobhash',
  'block',
  'blockhash',
  'bytes.concat',
  'ecrecover',
  'gasleft',
  'isContract',
  'keccak256',
  'clone',
  'cloneArgs',
  'cloneDeterministic',
  'cloneDeterministicWithArgs',
  'cloneWithArgs',
  'msg',
  'mulmod',
  'payable',
  'predictClone',
  'predictCloneWithArgs',
  'recover',
  'require',
  'revert',
  'revertWith',
  'ripemd160',
  'sha256',
  'string.concat',
  'tryRecover',
  'tx',
  'type',
]);

function tokenClass(identifier: string): string | undefined {
  if (keywords.has(identifier)) return 'tok-keyword';
  if (
    typeNames.has(identifier) ||
    /^(?:u|i)(?:8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)$/.test(
      identifier,
    ) ||
    /^bytes(?:[1-9]|[12][0-9]|3[0-2])$/.test(identifier)
  )
    return 'tok-type';
  if (builtins.has(identifier)) return 'tok-builtin';
  return undefined;
}

function highlightJeth(code: string): string {
  let output = '';
  let index = 0;
  while (index < code.length) {
    const rest = code.slice(index);

    const lineComment = rest.match(/^\/\/[^\n]*/);
    if (lineComment) {
      output += `<span class="tok-comment">${escapeHtml(lineComment[0])}</span>`;
      index += lineComment[0].length;
      continue;
    }

    const blockComment = rest.match(/^\/\*[\s\S]*?\*\//);
    if (blockComment) {
      output += `<span class="tok-comment">${escapeHtml(blockComment[0])}</span>`;
      index += blockComment[0].length;
      continue;
    }

    const stringValue = rest.match(/^(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`)/);
    if (stringValue) {
      output += `<span class="tok-string">${escapeHtml(stringValue[0])}</span>`;
      index += stringValue[0].length;
      continue;
    }

    const decorator = rest.match(/^@[A-Za-z_$][A-Za-z0-9_$]*/);
    if (decorator) {
      output += `<span class="tok-decorator">${escapeHtml(decorator[0])}</span>`;
      index += decorator[0].length;
      continue;
    }

    const privateName = rest.match(/^#[A-Za-z_$][A-Za-z0-9_$]*/);
    if (privateName) {
      output += `<span class="tok-private">${escapeHtml(privateName[0])}</span>`;
      index += privateName[0].length;
      continue;
    }

    const numberValue = rest.match(/^(?:0x[0-9a-fA-F_]+|[0-9][0-9_]*)(?:n)?/);
    if (numberValue) {
      output += `<span class="tok-number">${escapeHtml(numberValue[0])}</span>`;
      index += numberValue[0].length;
      continue;
    }

    const identifier = rest.match(/^[A-Za-z_$][A-Za-z0-9_$]*/);
    if (identifier) {
      const cssClass = tokenClass(identifier[0]);
      output += cssClass ? `<span class="${cssClass}">${escapeHtml(identifier[0])}</span>` : escapeHtml(identifier[0]);
      index += identifier[0].length;
      continue;
    }

    const operator = rest.match(
      /^(?:=>|\*\*=?|===?|!==?|<=|>=|&&|\|\||<<=?|>>=?|\+\+|--|\+=|-=|\*=|\/=|%=|&=|\|=|\^=)/,
    );
    if (operator) {
      output += `<span class="tok-operator">${escapeHtml(operator[0])}</span>`;
      index += operator[0].length;
      continue;
    }

    output += escapeHtml(code[index] ?? '');
    index += 1;
  }
  return output;
}

function inlineMarkdown(page: Page, value: string): string {
  const codeValues: string[] = [];
  const imageValues: string[] = [];
  let working = value.replace(/`([^`]+)`/g, (_match, code: string) => {
    const marker = `\u0000CODE${codeValues.length}\u0000`;
    codeValues.push(`<code>${escapeHtml(code)}</code>`);
    return marker;
  });
  working = working.replace(/!\[([^\]]*)]\(([^)]+)\)/g, (_match, alt: string, source: string) => {
    const marker = `\u0000IMAGE${imageValues.length}\u0000`;
    imageValues.push(
      `<img class="markdown-image" src="${escapeHtml(resolveImage(page, source))}" alt="${escapeHtml(alt)}" loading="lazy">`,
    );
    return marker;
  });

  working = escapeHtml(working);
  working = working.replace(/\[([^\]]+)]\(([^)]+)\)/g, (_match, label: string, href: string) => {
    const resolved = resolveLink(page, href.replaceAll('&amp;', '&'));
    const external = /^https?:/.test(resolved) ? ' target="_blank" rel="noreferrer"' : '';
    return `<a href="${escapeHtml(resolved)}"${external}>${label}</a>`;
  });
  working = working.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  working = working.replace(/(?<!\*)\*([^*]+)\*(?!\*)/g, '<em>$1</em>');
  working = working.replace(/\u0000CODE(\d+)\u0000/g, (_match, rawIndex: string) => codeValues[Number(rawIndex)] ?? '');
  working = working.replace(
    /\u0000IMAGE(\d+)\u0000/g,
    (_match, rawIndex: string) => imageValues[Number(rawIndex)] ?? '',
  );
  return working;
}

function isBlockStart(lines: string[], index: number): boolean {
  const line = lines[index] ?? '';
  if (!line.trim()) return true;
  if (/^<p class="a16k-lockup">\s*$/.test(line.trim())) return true;
  if (/^```/.test(line) || /^#{1,6}\s/.test(line) || /^>/.test(line) || /^\s*(?:[-*]|\d+\.)\s+/.test(line)) return true;
  const next = lines[index + 1] ?? '';
  return line.includes('|') && /^\s*\|?\s*:?-{3,}/.test(next);
}

function splitTableRow(line: string): string[] {
  return line
    .trim()
    .replace(/^\||\|$/g, '')
    .split('|')
    .map((cell) => cell.trim());
}

function renderMarkdown(page: Page, markdown: string): { html: string; toc: TocItem[]; text: string } {
  const lines = markdown.replace(/\r\n/g, '\n').split('\n');
  const html: string[] = [];
  const toc: TocItem[] = [];
  const usedIds = new Map<string, number>();
  let index = 0;

  const uniqueId = (title: string): string => {
    const base = slugify(title);
    const seen = usedIds.get(base) ?? 0;
    usedIds.set(base, seen + 1);
    return seen === 0 ? base : `${base}-${seen + 1}`;
  };

  while (index < lines.length) {
    const line = lines[index] ?? '';
    if (!line.trim()) {
      index += 1;
      continue;
    }

    if (/^<p class="a16k-lockup">\s*$/.test(line.trim())) {
      index += 1;
      while (index < lines.length && !/^<\/p>\s*$/.test((lines[index] ?? '').trim())) index += 1;
      if (index < lines.length) index += 1;
      html.push(`<div class="organization-lockup-wrap">${organizationLockup(page)}</div>`);
      continue;
    }

    const fence = line.match(/^```([^\s]*)\s*$/);
    if (fence) {
      const language = fence[1] || 'text';
      const codeLines: string[] = [];
      index += 1;
      while (index < lines.length && !/^```\s*$/.test(lines[index] ?? '')) {
        codeLines.push(lines[index] ?? '');
        index += 1;
      }
      index += 1;
      const code = codeLines.join('\n');
      const isJeth = language === 'jeth' || language === 'typescript' || language === 'ts';
      const highlighted = isJeth ? highlightJeth(code) : escapeHtml(code);
      const label = isJeth ? 'example.jeth' : language;
      html.push(
        `<div class="code-block"><div class="code-toolbar"><span class="code-file"><span class="jeth-dot"></span>${escapeHtml(label)}</span><button class="copy-code" type="button" aria-label="Copy code">Copy</button></div><pre data-language="${escapeHtml(isJeth ? 'jeth' : language)}"><code>${highlighted}</code></pre></div>`,
      );
      continue;
    }

    const heading = line.match(/^(#{1,6})\s+(.+)$/);
    if (heading) {
      const depth = heading[1].length;
      const title = heading[2].replace(/\s+#+$/, '');
      const id = uniqueId(title);
      if (depth === 1) {
        html.push(`<div class="article-kicker">${escapeHtml(page.group)}</div>`);
      }
      html.push(
        `<h${depth} id="${id}">${inlineMarkdown(page, title)}${depth > 1 ? `<a class="heading-anchor" href="#${id}" aria-label="Link to ${escapeHtml(title)}">#</a>` : ''}</h${depth}>`,
      );
      if (depth >= 2 && depth <= 3) toc.push({ depth, id, title: title.replace(/[`*_]/g, '') });
      index += 1;
      continue;
    }

    if (line.includes('|') && /^\s*\|?\s*:?-{3,}/.test(lines[index + 1] ?? '')) {
      const headers = splitTableRow(line);
      index += 2;
      const rows: string[][] = [];
      while (index < lines.length && (lines[index] ?? '').includes('|') && (lines[index] ?? '').trim()) {
        rows.push(splitTableRow(lines[index] ?? ''));
        index += 1;
      }
      html.push(
        '<div class="table-wrap"><table><thead><tr>' +
          headers.map((cell) => `<th>${inlineMarkdown(page, cell)}</th>`).join('') +
          '</tr></thead><tbody>' +
          rows
            .map((row) => '<tr>' + row.map((cell) => `<td>${inlineMarkdown(page, cell)}</td>`).join('') + '</tr>')
            .join('') +
          '</tbody></table></div>',
      );
      continue;
    }

    if (/^>/.test(line)) {
      const quoteLines: string[] = [];
      while (index < lines.length && /^>/.test(lines[index] ?? '')) {
        quoteLines.push((lines[index] ?? '').replace(/^>\s?/, ''));
        index += 1;
      }
      const raw = quoteLines.join(' ').trim();
      const calloutMatch = raw.match(/^\[!(NOTE|TIP|IMPORTANT|WARNING|DANGER)]\s*(.*)$/i);
      if (calloutMatch) {
        const kind = calloutMatch[1].toLowerCase();
        html.push(
          `<aside class="callout callout-${kind}"><div class="callout-label">${escapeHtml(calloutMatch[1])}</div><p>${inlineMarkdown(page, calloutMatch[2])}</p></aside>`,
        );
      } else {
        html.push(`<blockquote><p>${inlineMarkdown(page, raw)}</p></blockquote>`);
      }
      continue;
    }

    const listMatch = line.match(/^\s*([-*]|\d+\.)\s+(.+)$/);
    if (listMatch) {
      const ordered = /\d+\./.test(listMatch[1]);
      const items: string[] = [];
      while (index < lines.length) {
        const current = lines[index] ?? '';
        const match = current.match(/^\s*([-*]|\d+\.)\s+(.+)$/);
        if (!match || /\d+\./.test(match[1]) !== ordered) break;
        let item = match[2];
        index += 1;
        while (index < lines.length && (lines[index] ?? '').trim() && !isBlockStart(lines, index)) {
          item += ' ' + (lines[index] ?? '').trim();
          index += 1;
        }
        items.push(`<li>${inlineMarkdown(page, item)}</li>`);
        while (index < lines.length && !(lines[index] ?? '').trim()) index += 1;
      }
      const tag = ordered ? 'ol' : 'ul';
      html.push(`<${tag}>${items.join('')}</${tag}>`);
      continue;
    }

    if (/^---+$/.test(line.trim())) {
      html.push('<hr>');
      index += 1;
      continue;
    }

    const paragraph: string[] = [line.trim()];
    index += 1;
    while (index < lines.length && !isBlockStart(lines, index)) {
      paragraph.push((lines[index] ?? '').trim());
      index += 1;
    }
    html.push(`<p>${inlineMarkdown(page, paragraph.join(' '))}</p>`);
  }

  const plainText = markdown
    .replace(/```[\s\S]*?```/g, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/[#>*_`\[\]()|]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  return { html: html.join('\n'), toc, text: plainText };
}

function enhanceRoadmap(content: string): string {
  const stagePattern = /<h2 id="(r([0-6])-[^"]+)">([\s\S]*?)<\/h2>\n([\s\S]*?)(?=\n<h2 id=|$)/g;
  const stages: Array<{ id: string; phase: string; title: string }> = [];
  let enhanced = content.replace(stagePattern, (_match, id: string, digit: string, heading: string, body: string) => {
    const phase = `R${digit}`;
    const displayHeading = heading.replace(/<a[\s\S]*?<\/a>/g, '').trim();
    const title = heading
      .replace(/<a[\s\S]*?<\/a>/g, '')
      .replace(/<[^>]+>/g, '')
      .replace(/^R\d:\s*/, '')
      .trim();
    stages.push({ id, phase, title });
    const stageBody = body
      .replace(/<p>Goal:\s*([\s\S]*?)<\/p>/, '<div class="roadmap-goal"><span>Goal</span><p>$1</p></div>')
      .replace(
        /<p>Exit criteria:\s*([\s\S]*?)<\/p>/,
        '<div class="roadmap-exit"><span>Exit gate</span><p>$1</p></div>',
      );
    return `<section class="roadmap-stage" data-phase="${phase}"><div class="roadmap-marker" aria-hidden="true"><span>${phase}</span></div><div class="roadmap-stage-content"><h2 id="${id}">${displayHeading}</h2>\n${stageBody}</div></section>`;
  });

  if (stages.length === 0) return enhanced;
  const overview = `<nav class="roadmap-overview" aria-label="Roadmap stages">${stages
    .map(
      (stage) =>
        `<a class="roadmap-overview-card" href="#${stage.id}"><span>${stage.phase}</span><strong>${escapeHtml(stage.title)}</strong></a>`,
    )
    .join('')}</nav>`;
  const firstStage = enhanced.indexOf('<section class="roadmap-stage"');
  enhanced = enhanced.slice(0, firstStage) + overview + enhanced.slice(firstStage);
  return enhanced.replace(
    /(<h2 id="release-principles">[\s\S]*?<\/h2>\n<ol>[\s\S]*?<\/ol>)/,
    '<section class="roadmap-principles">$1</section>',
  );
}

function sidebar(page: Page): string {
  const groups = [...new Set(pages.map((item) => item.group))];
  return groups
    .map((group) => {
      const links = pages
        .filter((item) => item.group === group)
        .map((item) => {
          const current = item.source === page.source;
          return `<a class="sidebar-link${current ? ' is-active' : ''}" href="${escapeHtml(relativeUrl(page, item))}"${current ? ' aria-current="page"' : ''}>${escapeHtml(item.title)}</a>`;
        })
        .join('');
      return `<section class="sidebar-group"><h2>${escapeHtml(group)}</h2>${links}</section>`;
    })
    .join('');
}

function tableOfContents(items: TocItem[]): string {
  if (items.length === 0) return '';
  return `<nav class="page-toc" aria-label="On this page"><div class="toc-title">On this page</div>${items.map((item) => `<a class="toc-link depth-${item.depth}" href="#${item.id}">${escapeHtml(item.title)}</a>`).join('')}</nav>`;
}

function pagination(page: Page): string {
  const pageIndex = pages.findIndex((item) => item.source === page.source);
  const previous = pages[pageIndex - 1];
  const next = pages[pageIndex + 1];
  return `<nav class="pagination" aria-label="Documentation pages">${previous ? `<a class="pagination-link previous" href="${escapeHtml(relativeUrl(page, previous))}"><span>Previous</span><strong>${escapeHtml(previous.title)}</strong></a>` : '<span></span>'}${next ? `<a class="pagination-link next" href="${escapeHtml(relativeUrl(page, next))}"><span>Next</span><strong>${escapeHtml(next.title)}</strong></a>` : '<span></span>'}</nav>`;
}

function pageHtml(page: Page, content: string, toc: TocItem[]): string {
  const stylesheet = assetUrl(page, 'book.css');
  const script = assetUrl(page, 'book.js');
  const search = assetUrl(page, 'search-index.js');
  const icon = assetUrl(page, 'jeth-orange-icon-32.png');
  const productLogo = assetUrl(page, 'jeth-orange-icon-128.png');
  const socialImage = assetUrl(page, 'jeth-orange-icon-1024.png');
  const home = relativeUrl(page, pages[0]);
  const pageContent = page.slug === 'project/roadmap' ? enhanceRoadmap(content) : content;
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="${escapeHtml(page.title)} in the JETH language documentation.">
  <meta name="theme-color" content="#11131a">
  <meta property="og:image" content="${escapeHtml(socialImage)}">
  <title>${escapeHtml(page.title)} | JETH</title>
  <link rel="icon" href="${escapeHtml(icon)}" type="image/png">
  <link rel="stylesheet" href="${escapeHtml(stylesheet)}">
</head>
<body>
  <header class="site-header">
    <a class="brand" href="${escapeHtml(home)}" aria-label="JETH documentation home"><img class="brand-mark" src="${escapeHtml(productLogo)}" alt="" width="30" height="30"><span class="brand-name">JETH</span><span class="brand-section">Docs</span><span class="brand-version">v${escapeHtml(projectVersion)}</span></a>
    <nav class="top-nav" aria-label="Primary"><a class="is-active" href="${escapeHtml(home)}">Guides</a><a href="${escapeHtml(relativeUrl(page, pages.find((item) => item.slug === 'internals/compiler-and-tooling')!))}">Compiler</a><a href="https://github.com/a16k-lab/jeth" target="_blank" rel="noreferrer">GitHub</a></nav>
    <div class="header-actions"><button class="search-trigger" type="button" aria-label="Search documentation"><span>Search guides</span><kbd>⌘ K</kbd></button><button class="theme-toggle" type="button" aria-label="Toggle color theme">◐</button><button class="menu-toggle" type="button" aria-label="Open navigation">Menu</button></div>
  </header>
  <div class="pre-release"><span>Pre-release</span> JETH is under active compiler and security review.</div>
  <div class="book-shell">
    <aside class="sidebar"><div class="sidebar-title">Guides</div>${sidebar(page)}<div class="sidebar-attribution">${organizationLockup(page)}</div></aside>
    <main class="content-shell">
      <article class="article">${pageContent}<div class="article-footer"><span>JETH language documentation</span>${organizationLockup(page)}</div>${pagination(page)}</article>
      ${tableOfContents(toc)}
    </main>
  </div>
  <div class="search-modal" hidden><button class="search-backdrop" type="button" aria-label="Close search"></button><div class="search-panel" role="dialog" aria-modal="true" aria-label="Search documentation"><div class="search-box"><span>⌕</span><input class="search-input" type="search" placeholder="Search JETH guides..." autocomplete="off"><button class="search-close" type="button">Esc</button></div><div class="search-results"><div class="search-empty">Start typing to search the book.</div></div></div></div>
  <script src="${escapeHtml(search)}"></script>
  <script src="${escapeHtml(script)}"></script>
</body>
</html>`;
}

const style = `
:root {
  color-scheme: light;
  --bg: #fbfaf8;
  --panel: #ffffff;
  --panel-soft: #f3f1ec;
  --text: #191b22;
  --muted: #686b75;
  --border: #e2dfd8;
  --accent: #e4512f;
  --accent-soft: #fff0ea;
  --accent-strong: #a72d17;
  --code-bg: #11131a;
  --code-panel: #191c26;
  --code-text: #e8eaf0;
  --shadow: 0 18px 50px rgba(31, 28, 23, .08);
  --header-height: 64px;
  --notice-height: 34px;
  font-family: Inter, ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}

:root[data-theme="dark"] {
  color-scheme: dark;
  --bg: #101116;
  --panel: #17191f;
  --panel-soft: #1f222a;
  --text: #f2f0eb;
  --muted: #a6a8b1;
  --border: #2e313b;
  --accent: #ff7957;
  --accent-soft: #321d19;
  --accent-strong: #ff9a80;
  --shadow: 0 18px 50px rgba(0, 0, 0, .28);
}

* { box-sizing: border-box; }
html { scroll-behavior: smooth; scroll-padding-top: 120px; }
body { margin: 0; background: var(--bg); color: var(--text); font-size: 16px; line-height: 1.72; }
a { color: var(--accent-strong); text-decoration-thickness: 1px; text-underline-offset: 3px; }
button, input { font: inherit; }

.site-header { position: fixed; z-index: 50; inset: 0 0 auto 0; height: var(--header-height); display: grid; grid-template-columns: 280px 1fr auto; align-items: center; border-bottom: 1px solid var(--border); background: color-mix(in srgb, var(--bg) 92%, transparent); backdrop-filter: blur(18px); padding: 0 24px; }
.brand { display: inline-flex; align-items: center; gap: 9px; color: var(--text); text-decoration: none; font-weight: 800; letter-spacing: -.02em; }
.brand-mark { width: 30px; height: 30px; display: block; border-radius: 9px; object-fit: cover; }
.brand-section { color: var(--muted); font-weight: 550; padding-left: 8px; border-left: 1px solid var(--border); }
.brand-version { color: var(--muted); font: 650 10px/1 ui-monospace, SFMono-Regular, Menlo, monospace; letter-spacing: 0; }
.top-nav { display: flex; align-items: center; gap: 26px; }
.top-nav a { color: var(--muted); text-decoration: none; font-size: 14px; font-weight: 650; }
.top-nav a:hover, .top-nav a.is-active { color: var(--text); }
.header-actions { display: flex; align-items: center; gap: 8px; }
.search-trigger, .theme-toggle, .menu-toggle { border: 1px solid var(--border); background: var(--panel); color: var(--muted); border-radius: 10px; min-height: 38px; cursor: pointer; }
.search-trigger { min-width: 220px; display: flex; justify-content: space-between; align-items: center; gap: 20px; padding: 0 10px 0 13px; text-align: left; font-size: 13px; }
kbd { border: 1px solid var(--border); background: var(--panel-soft); border-radius: 5px; padding: 1px 6px; font-size: 11px; }
.theme-toggle { width: 38px; }
.menu-toggle { display: none; padding: 0 12px; }

.pre-release { position: fixed; z-index: 45; top: var(--header-height); left: 0; right: 0; height: var(--notice-height); display: flex; align-items: center; justify-content: center; gap: 8px; background: #191b22; color: #dfe1e7; font-size: 12px; letter-spacing: .01em; }
.pre-release span { color: #ff9477; font-weight: 800; text-transform: uppercase; font-size: 10px; letter-spacing: .09em; }

.book-shell { padding-top: calc(var(--header-height) + var(--notice-height)); }
.sidebar { position: fixed; z-index: 30; top: calc(var(--header-height) + var(--notice-height)); bottom: 0; left: 0; width: 280px; overflow-y: auto; border-right: 1px solid var(--border); padding: 28px 22px 32px; background: var(--bg); }
.sidebar-title { font-size: 11px; font-weight: 850; letter-spacing: .12em; text-transform: uppercase; color: var(--accent); margin: 0 10px 22px; }
.sidebar-group { margin-bottom: 24px; }
.sidebar-group h2 { margin: 0 10px 7px; color: var(--muted); text-transform: uppercase; letter-spacing: .09em; font-size: 10px; font-weight: 800; }
.sidebar-link { display: block; padding: 6px 10px; border-radius: 7px; color: var(--muted); text-decoration: none; font-size: 13px; line-height: 1.35; }
.sidebar-link:hover { color: var(--text); background: var(--panel-soft); }
.sidebar-link.is-active { color: var(--accent-strong); background: var(--accent-soft); font-weight: 720; }
.sidebar-attribution { margin: 34px 10px 0; padding-top: 18px; border-top: 1px solid var(--border); }
.organization-lockup { display: inline-flex; align-items: center; gap: 9px; color: var(--muted); text-decoration: none; font-size: 12px; line-height: 1.2; }
.organization-lockup:hover { color: var(--text); }
.organization-lockup img { flex: 0 0 auto; border-radius: 50%; border: 1px solid var(--border); object-fit: cover; background: #050505; }
.organization-lockup strong { color: inherit; font-weight: 720; }
.organization-lockup-wrap { margin: 4px 0 30px; }

.content-shell { margin-left: 280px; display: grid; grid-template-columns: minmax(0, 860px) 220px; justify-content: center; gap: 70px; padding: 62px 52px 90px; }
.article { min-width: 0; }
.article-kicker { color: var(--accent); font-weight: 800; font-size: 11px; letter-spacing: .12em; text-transform: uppercase; margin-bottom: 12px; }
.article h1 { font-size: clamp(38px, 5vw, 58px); line-height: 1.04; letter-spacing: -.045em; margin: 0 0 28px; max-width: 760px; }
.article h2 { margin: 64px 0 18px; font-size: 28px; line-height: 1.2; letter-spacing: -.025em; border-top: 1px solid var(--border); padding-top: 28px; }
.article h3 { margin: 38px 0 13px; font-size: 20px; line-height: 1.3; letter-spacing: -.015em; }
.article h4 { margin: 28px 0 10px; font-size: 16px; }
.heading-anchor { opacity: 0; margin-left: 8px; text-decoration: none; font-weight: 500; }
.article h2:hover .heading-anchor, .article h3:hover .heading-anchor { opacity: .55; }
.article p { margin: 0 0 20px; max-width: 790px; }
.article > p:first-of-type { font-size: 19px; color: var(--muted); line-height: 1.65; }
.article ul, .article ol { margin: 0 0 24px; padding-left: 24px; }
.article li { margin: 7px 0; padding-left: 5px; }
.article code:not(pre code) { background: var(--panel-soft); border: 1px solid var(--border); border-radius: 5px; padding: .12em .35em; font-family: "SFMono-Regular", Consolas, monospace; font-size: .86em; color: var(--accent-strong); overflow-wrap: anywhere; word-break: break-word; }
.markdown-image { display: block; width: 128px; height: 128px; object-fit: cover; border-radius: 24px; border: 1px solid var(--border); box-shadow: var(--shadow); }
.article blockquote { margin: 28px 0; padding: 18px 22px; border-left: 3px solid var(--accent); background: var(--panel); box-shadow: var(--shadow); border-radius: 0 10px 10px 0; }
.article blockquote p { margin: 0; }
.callout { border: 1px solid var(--border); border-left: 4px solid #6476e8; background: var(--panel); padding: 18px 20px; margin: 28px 0; border-radius: 9px; }
.callout-important, .callout-warning, .callout-danger { border-left-color: var(--accent); background: var(--accent-soft); }
.callout-label { font-size: 10px; font-weight: 850; letter-spacing: .1em; text-transform: uppercase; margin-bottom: 5px; }
.callout p { margin: 0; }
.table-wrap { overflow-x: auto; margin: 26px 0 32px; border: 1px solid var(--border); border-radius: 10px; }
table { width: 100%; border-collapse: collapse; background: var(--panel); font-size: 14px; }
th, td { text-align: left; vertical-align: top; padding: 12px 14px; border-bottom: 1px solid var(--border); }
th { background: var(--panel-soft); font-size: 11px; text-transform: uppercase; letter-spacing: .06em; }
tr:last-child td { border-bottom: 0; }
hr { border: 0; border-top: 1px solid var(--border); margin: 46px 0; }

.roadmap-principles { margin: 38px 0 46px; padding: 4px 26px 24px; border: 1px solid var(--border); border-radius: 16px; background: linear-gradient(145deg, var(--panel), var(--panel-soft)); box-shadow: var(--shadow); }
.roadmap-principles h2 { margin-top: 0; border-top: 0; }
.roadmap-principles ol { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px 28px; padding-left: 22px; margin-bottom: 0; }
.roadmap-principles li { margin: 0; }
.roadmap-overview { position: relative; display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 10px; margin: 38px 0 42px; padding-top: 18px; }
.roadmap-overview::before { content: ""; position: absolute; top: 0; left: 0; right: 0; height: 2px; background: linear-gradient(90deg, var(--accent), color-mix(in srgb, var(--accent) 25%, var(--border))); }
.roadmap-overview-card { min-width: 0; padding: 13px 10px 12px; border: 1px solid var(--border); border-radius: 11px; background: var(--panel); color: var(--text); text-decoration: none; transition: transform .16s ease, border-color .16s ease, background .16s ease; }
.roadmap-overview-card:hover { transform: translateY(-3px); border-color: var(--accent); background: var(--accent-soft); }
.roadmap-overview-card span { display: block; color: var(--accent); font-size: 11px; font-weight: 850; letter-spacing: .08em; }
.roadmap-overview-card strong { display: block; margin-top: 6px; color: var(--text); font-size: 11px; line-height: 1.25; }
.roadmap-stage { position: relative; display: grid; grid-template-columns: 66px minmax(0, 1fr); gap: 22px; margin: 22px 0; padding: 28px 30px 30px 24px; border: 1px solid var(--border); border-radius: 17px; background: var(--panel); box-shadow: var(--shadow); overflow: hidden; }
.roadmap-stage::after { content: ""; position: absolute; inset: 0 auto 0 0; width: 4px; background: var(--accent); }
.roadmap-marker { position: relative; z-index: 1; width: 58px; height: 58px; display: grid; place-items: center; border-radius: 16px; background: var(--code-bg); color: #ffffff; box-shadow: 0 10px 24px rgba(0, 0, 0, .18); }
.roadmap-marker span { font: 850 15px/1 ui-monospace, SFMono-Regular, Menlo, monospace; letter-spacing: .04em; }
.roadmap-stage-content h2 { margin: 2px 0 16px; padding: 0; border: 0; font-size: 25px; }
.roadmap-stage-content h3 { margin-top: 30px; }
.roadmap-goal { display: grid; grid-template-columns: 68px minmax(0, 1fr); gap: 12px; margin: 0 0 22px; padding: 13px 15px; border-radius: 10px; background: var(--panel-soft); }
.roadmap-goal > span, .roadmap-exit > span { color: var(--accent); font-size: 10px; font-weight: 850; letter-spacing: .1em; text-transform: uppercase; }
.roadmap-goal p, .roadmap-exit p { margin: 0; font-size: 14px; }
.roadmap-exit { margin-top: 28px; padding: 17px 18px; border: 1px solid color-mix(in srgb, var(--accent) 42%, var(--border)); border-radius: 11px; background: var(--accent-soft); }
.roadmap-exit > span { display: block; margin-bottom: 5px; }

.code-block { margin: 26px 0 32px; border: 1px solid #292d39; border-radius: 12px; overflow: hidden; background: var(--code-bg); box-shadow: 0 18px 35px rgba(0, 0, 0, .16); }
.code-toolbar { height: 42px; display: flex; align-items: center; justify-content: space-between; padding: 0 12px 0 15px; background: var(--code-panel); border-bottom: 1px solid #292d39; color: #9ca2b2; font: 12px/1 ui-monospace, SFMono-Regular, Menlo, monospace; }
.code-file { display: inline-flex; align-items: center; gap: 8px; }
.jeth-dot { width: 8px; height: 8px; border-radius: 2px; background: #ff6e4a; box-shadow: 0 0 0 3px rgba(255, 110, 74, .12); }
.copy-code { border: 0; background: transparent; color: #9ca2b2; cursor: pointer; font: inherit; }
.copy-code:hover { color: #ffffff; }
pre { margin: 0; overflow-x: auto; padding: 21px 23px 24px; background: var(--code-bg); color: var(--code-text); font: 13.5px/1.7 "SFMono-Regular", Consolas, "Liberation Mono", monospace; tab-size: 2; }
.tok-comment { color: #747b8e; font-style: italic; }
.tok-keyword { color: #d99cff; }
.tok-type { color: #68d8c7; }
.tok-builtin { color: #76b7ff; }
.tok-string { color: #f4be79; }
.tok-number { color: #a5df86; }
.tok-decorator { color: #ff9c66; }
.tok-private { color: #ff79a9; }
.tok-operator { color: #c6cad5; }

.page-toc { position: sticky; top: 130px; align-self: start; max-height: calc(100vh - 160px); overflow-y: auto; padding-left: 18px; border-left: 1px solid var(--border); }
.toc-title { font-size: 11px; font-weight: 800; text-transform: uppercase; letter-spacing: .08em; margin-bottom: 10px; }
.toc-link { display: block; color: var(--muted); text-decoration: none; font-size: 12px; line-height: 1.45; padding: 4px 0; }
.toc-link:hover { color: var(--text); }
.toc-link.depth-3 { padding-left: 12px; }
.article-footer { display: flex; align-items: center; justify-content: space-between; margin-top: 72px; padding: 20px 0; border-top: 1px solid var(--border); color: var(--muted); font-size: 12px; }
.article-footer a { color: var(--muted); text-decoration: none; }
.pagination { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-top: 22px; }
.pagination-link { display: flex; flex-direction: column; padding: 16px 18px; border: 1px solid var(--border); border-radius: 10px; background: var(--panel); text-decoration: none; }
.pagination-link.next { text-align: right; align-items: flex-end; }
.pagination-link span { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .07em; }
.pagination-link strong { color: var(--text); font-size: 14px; }
.pagination-link:hover { border-color: var(--accent); }

.search-modal[hidden] { display: none; }
.search-modal { position: fixed; z-index: 100; inset: 0; display: grid; place-items: start center; padding-top: 12vh; }
.search-backdrop { position: absolute; inset: 0; border: 0; background: rgba(10, 11, 15, .62); backdrop-filter: blur(5px); }
.search-panel { position: relative; width: min(680px, calc(100vw - 30px)); max-height: 72vh; overflow: hidden; background: var(--panel); border: 1px solid var(--border); border-radius: 14px; box-shadow: 0 30px 100px rgba(0, 0, 0, .35); }
.search-box { display: grid; grid-template-columns: auto 1fr auto; gap: 10px; align-items: center; padding: 12px 14px; border-bottom: 1px solid var(--border); }
.search-input { width: 100%; border: 0; outline: 0; background: transparent; color: var(--text); font-size: 16px; }
.search-close { border: 1px solid var(--border); border-radius: 6px; background: var(--panel-soft); color: var(--muted); cursor: pointer; font-size: 11px; }
.search-results { max-height: calc(72vh - 60px); overflow-y: auto; padding: 8px; }
.search-result { display: block; padding: 12px 14px; border-radius: 8px; text-decoration: none; }
.search-result:hover, .search-result.is-selected { background: var(--panel-soft); }
.search-result strong { display: block; color: var(--text); }
.search-result span { display: block; color: var(--muted); font-size: 12px; margin-top: 3px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.search-empty { padding: 28px 18px; text-align: center; color: var(--muted); font-size: 13px; }

@media (max-width: 1180px) {
  .content-shell { grid-template-columns: minmax(0, 820px); }
  .page-toc { display: none; }
}

@media (max-width: 860px) {
  .site-header { grid-template-columns: 1fr auto; padding: 0 15px; }
  .top-nav, .search-trigger span, .search-trigger kbd { display: none; }
  .search-trigger { min-width: 38px; width: 38px; padding: 0; justify-content: center; }
  .search-trigger::after { content: "⌕"; font-size: 18px; }
  .menu-toggle { display: block; }
  .sidebar { transform: translateX(-100%); transition: transform .22s ease; box-shadow: var(--shadow); }
  body.nav-open .sidebar { transform: translateX(0); }
  .content-shell { margin-left: 0; padding: 48px 24px 72px; }
  .article h1 { font-size: 40px; }
  .roadmap-overview { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .roadmap-overview::before { display: none; }
}

@media (max-width: 560px) {
  .brand-section, .brand-version { display: none; }
  .pre-release { justify-content: flex-start; padding: 0 15px; overflow: hidden; white-space: nowrap; }
  .content-shell { padding: 40px 18px 60px; }
  .article h1 { font-size: 35px; }
  .article h2 { font-size: 24px; margin-top: 52px; }
  .roadmap-principles { padding: 2px 18px 20px; }
  .roadmap-principles ol { grid-template-columns: 1fr; }
  .roadmap-overview { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .roadmap-stage { grid-template-columns: 1fr; gap: 17px; padding: 23px 19px 24px; }
  .roadmap-marker { width: 48px; height: 48px; border-radius: 13px; }
  .roadmap-stage-content h2 { margin-top: 0; font-size: 23px; }
  .roadmap-goal { grid-template-columns: 1fr; gap: 4px; }
  pre { font-size: 12px; padding: 18px 16px 20px; }
  .pagination { grid-template-columns: 1fr; }
  .article-footer { align-items: flex-start; flex-direction: column; gap: 5px; }
}
`;

const clientScript = `
(() => {
  const root = document.documentElement;
  const siteRoot = new URL('../', document.currentScript.src);
  const storedTheme = localStorage.getItem('jeth-docs-theme');
  if (storedTheme) root.dataset.theme = storedTheme;

  document.querySelector('.theme-toggle')?.addEventListener('click', () => {
    const next = root.dataset.theme === 'dark' ? 'light' : 'dark';
    root.dataset.theme = next;
    localStorage.setItem('jeth-docs-theme', next);
  });

  document.querySelector('.menu-toggle')?.addEventListener('click', () => document.body.classList.toggle('nav-open'));
  document.querySelectorAll('.sidebar-link').forEach((link) => link.addEventListener('click', () => document.body.classList.remove('nav-open')));

  document.querySelectorAll('.copy-code').forEach((button) => {
    button.addEventListener('click', async () => {
      const code = button.closest('.code-block')?.querySelector('code')?.textContent || '';
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(code);
      } else {
        const area = document.createElement('textarea');
        area.value = code;
        area.style.position = 'fixed';
        area.style.opacity = '0';
        document.body.append(area);
        area.select();
        document.execCommand('copy');
        area.remove();
      }
      button.textContent = 'Copied';
      setTimeout(() => { button.textContent = 'Copy'; }, 1200);
    });
  });

  const modal = document.querySelector('.search-modal');
  const input = document.querySelector('.search-input');
  const results = document.querySelector('.search-results');
  const searchIndex = window.JETH_SEARCH_INDEX || [];
  const escapeMarkup = (value) => String(value).replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]);
  const openSearch = () => { modal.hidden = false; setTimeout(() => input.focus(), 0); };
  const closeSearch = () => { modal.hidden = true; input.value = ''; results.innerHTML = '<div class="search-empty">Start typing to search the book.</div>'; };
  document.querySelector('.search-trigger')?.addEventListener('click', openSearch);
  document.querySelector('.search-close')?.addEventListener('click', closeSearch);
  document.querySelector('.search-backdrop')?.addEventListener('click', closeSearch);
  document.addEventListener('keydown', (event) => {
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') { event.preventDefault(); openSearch(); }
    if (event.key === 'Escape' && !modal.hidden) closeSearch();
  });
  input?.addEventListener('input', () => {
    const query = input.value.trim().toLowerCase();
    if (!query) { results.innerHTML = '<div class="search-empty">Start typing to search the book.</div>'; return; }
    const terms = query.split(/\\s+/);
    const matches = searchIndex.filter((item) => terms.every((term) => (item.title + ' ' + item.group + ' ' + item.text).toLowerCase().includes(term))).slice(0, 12);
    results.innerHTML = matches.length ? matches.map((item) => '<a class="search-result" href="' + new URL(item.path, siteRoot).href + '"><strong>' + escapeMarkup(item.title) + '</strong><span>' + escapeMarkup(item.group) + ' · ' + escapeMarkup(item.text.slice(0, 150)) + '</span></a>').join('') : '<div class="search-empty">No matching guide found.</div>';
  });
})();
`;

fs.rmSync(outputRoot, { recursive: true, force: true });
fs.mkdirSync(path.join(outputRoot, 'assets'), { recursive: true });
fs.writeFileSync(path.join(outputRoot, 'assets', 'book.css'), style.trim() + '\n');
fs.writeFileSync(path.join(outputRoot, 'assets', 'book.js'), clientScript.trim() + '\n');
fs.copyFileSync(
  path.join(projectRoot, 'docs', 'assets', 'a16k-avatar-logo.png'),
  path.join(outputRoot, 'assets', 'a16k-avatar-logo.png'),
);
for (const asset of [
  'jeth-orange-icon-32.png',
  'jeth-orange-icon-128.png',
  'jeth-orange-icon-256.png',
  'jeth-orange-icon-1024.png',
]) {
  fs.copyFileSync(path.join(productBrandRoot, asset), path.join(outputRoot, 'assets', asset));
}

const rendered = pages.map((page) => {
  const sourcePath = path.resolve(projectRoot, page.source);
  if (!fs.existsSync(sourcePath)) throw new Error(`Missing documentation source: ${page.source}`);
  const markdown = fs.readFileSync(sourcePath, 'utf8');
  return { page, ...renderMarkdown(page, markdown) };
});

for (const item of rendered) {
  const destination = outputFile(item.page);
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  fs.writeFileSync(destination, pageHtml(item.page, item.html, item.toc));
}

const searchIndex = rendered.map((item) => ({
  title: item.page.title,
  group: item.page.group,
  text: item.text,
  path: item.page.slug ? item.page.slug + '/' : './',
}));
fs.writeFileSync(
  path.join(outputRoot, 'assets', 'search-index.js'),
  `window.JETH_SEARCH_INDEX = ${JSON.stringify(searchIndex)};\n`,
);

const generatedFiles = [
  ...rendered.map((item) => outputFile(item.page)),
  path.join(outputRoot, 'assets', 'book.css'),
  path.join(outputRoot, 'assets', 'book.js'),
  path.join(outputRoot, 'assets', 'a16k-avatar-logo.png'),
  path.join(outputRoot, 'assets', 'jeth-orange-icon-32.png'),
  path.join(outputRoot, 'assets', 'jeth-orange-icon-128.png'),
  path.join(outputRoot, 'assets', 'jeth-orange-icon-256.png'),
  path.join(outputRoot, 'assets', 'jeth-orange-icon-1024.png'),
  path.join(outputRoot, 'assets', 'search-index.js'),
];

for (const file of rendered.map((item) => outputFile(item.page))) {
  const html = fs.readFileSync(file, 'utf8');
  const references = [...html.matchAll(/\b(?:href|src)="([^"]+)"/g)].map((match) => match[1]);
  for (const reference of references) {
    if (/^(?:https?:|mailto:|tel:)/.test(reference)) continue;
    const [filePart, fragment] = reference.split('#', 2);
    const target = filePart ? path.resolve(path.dirname(file), filePart) : file;
    if (!fs.existsSync(target)) {
      throw new Error(`Broken generated link in ${path.relative(projectRoot, file)}: ${reference}`);
    }
    if (fragment && target.endsWith('.html')) {
      const targetHtml = fs.readFileSync(target, 'utf8');
      if (!targetHtml.includes(`id="${fragment}"`)) {
        throw new Error(`Broken generated anchor in ${path.relative(projectRoot, file)}: ${reference}`);
      }
    }
  }
}

if (new Set(generatedFiles).size !== generatedFiles.length) {
  throw new Error('The documentation build produced duplicate output paths.');
}

console.log(`Built ${pages.length} HTML documentation pages in ${path.relative(projectRoot, outputRoot)}`);
