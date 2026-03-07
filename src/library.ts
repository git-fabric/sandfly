/**
 * Library — git-based knowledge retrieval for fabric-sandfly
 *
 * The librarian model: we know where the books are, we go fetch them
 * when asked, and we return them when done. No photocopies.
 *
 * Sources:
 *   - sandfly-io/sandfly-setup — official Sandfly setup documentation
 *   - sandfly-io/sandfly-entropyscan — entropy scanner docs
 */

import { execSync } from 'child_process';
import { readFileSync, existsSync, mkdirSync } from 'fs';
import { join } from 'path';

const LIBRARY_DIR = process.env.LIBRARY_DIR || '/tmp/fabric-library';

interface LibrarySource {
  id: string;
  repo: string;
  branch: string;
  description: string;
  topics: TopicEntry[];
  useRawApi?: boolean;
}

interface TopicEntry {
  keywords: string[];
  files: string[];
  description: string;
}

const SOURCES: LibrarySource[] = [
  {
    id: 'sandfly-setup',
    repo: 'https://github.com/sandfly-io/sandfly-setup.git',
    branch: 'master',
    description: 'Sandfly Security server setup and configuration',
    topics: [
      { keywords: ['install', 'setup', 'getting started', 'deploy'],
        files: ['README.md'],
        description: 'Installation and setup' },
      { keywords: ['docker', 'container', 'compose'],
        files: ['README.md'],
        description: 'Docker deployment' },
      { keywords: ['config', 'configuration', 'settings'],
        files: ['README.md'],
        description: 'Configuration' },
      { keywords: ['license', 'licensing'],
        files: ['README.md', 'LICENSE'],
        description: 'Licensing' },
    ],
  },
  {
    id: 'sandfly-entropyscan',
    repo: 'https://github.com/sandfly-io/sandfly-entropyscan.git',
    branch: 'master',
    description: 'Sandfly entropy scanner — detect packed/encrypted malware on Linux',
    topics: [
      { keywords: ['entropy', 'scan', 'packed', 'encrypted', 'malware', 'elf'],
        files: ['README.md'],
        description: 'Entropy scanning for malware detection' },
      { keywords: ['process', 'memory', 'proc', 'pid'],
        files: ['README.md'],
        description: 'Process scanning' },
      { keywords: ['file', 'binary', 'directory'],
        files: ['README.md'],
        description: 'File scanning' },
    ],
  },
  {
    id: 'sandfly-processdecloak',
    repo: 'https://github.com/sandfly-io/sandfly-processdecloak.git',
    branch: 'master',
    description: 'Sandfly process decloaker — find hidden Linux processes',
    topics: [
      { keywords: ['hidden', 'stealth', 'rootkit', 'decloak', 'process', 'invisible'],
        files: ['README.md'],
        description: 'Hidden process detection' },
      { keywords: ['proc', 'pid', 'brute force'],
        files: ['README.md'],
        description: 'Process enumeration' },
    ],
  },
  {
    id: 'sandfly-filescan',
    repo: 'https://github.com/sandfly-io/sandfly-filescan.git',
    branch: 'master',
    description: 'Sandfly file scanner — agentless file integrity and threat detection',
    topics: [
      { keywords: ['file', 'integrity', 'hash', 'checksum', 'modified'],
        files: ['README.md'],
        description: 'File integrity scanning' },
      { keywords: ['suid', 'sgid', 'permission', 'privilege'],
        files: ['README.md'],
        description: 'Privilege escalation detection' },
    ],
  },
];

export class Library {
  private cacheDir: string;

  constructor() {
    this.cacheDir = LIBRARY_DIR;
    if (!existsSync(this.cacheDir)) {
      mkdirSync(this.cacheDir, { recursive: true });
    }
  }

  findTopics(query: string): { source: LibrarySource; topic: TopicEntry; score: number }[] {
    const q = query.toLowerCase();
    const matches: { source: LibrarySource; topic: TopicEntry; score: number }[] = [];

    for (const source of SOURCES) {
      for (const topic of source.topics) {
        let score = 0;
        for (const kw of topic.keywords) {
          if (q.includes(kw)) {
            score += kw.length;
          }
        }
        if (score > 0) {
          matches.push({ source, topic, score });
        }
      }
    }

    return matches.sort((a, b) => b.score - a.score);
  }

  checkout(source: LibrarySource): string {
    if (source.useRawApi) return '';

    const localPath = join(this.cacheDir, source.id);

    if (existsSync(join(localPath, '.git'))) {
      try {
        execSync(`git -C ${localPath} pull --depth 1 --rebase 2>/dev/null || true`, {
          timeout: 15000,
          stdio: 'pipe',
        });
      } catch {
        // Stale cache is better than no cache
      }
      return localPath;
    }

    execSync(
      `git clone --depth 1 --branch ${source.branch} ${source.repo} ${localPath}`,
      { timeout: 60000, stdio: 'pipe' }
    );

    return localPath;
  }

  readFiles(source: LibrarySource, files: string[]): string {
    if (source.useRawApi) {
      return this.readFilesFromGitHub(source, files);
    }

    const localPath = this.checkout(source);
    const sections: string[] = [];

    for (const file of files) {
      const fullPath = join(localPath, file);
      if (existsSync(fullPath)) {
        try {
          const content = readFileSync(fullPath, 'utf-8');
          const trimmed = content.length > 8000
            ? content.slice(0, 8000) + '\n\n...[truncated — full source at ' + file + ']'
            : content;
          sections.push(`--- ${file} ---\n${trimmed}`);
        } catch {
          // Skip unreadable files
        }
      }
    }

    return sections.join('\n\n');
  }

  private readFilesFromGitHub(source: LibrarySource, files: string[]): string {
    const match = source.repo.match(/github\.com\/([^/]+\/[^/.]+)/);
    if (!match) return '';

    const ownerRepo = match[1];
    const sections: string[] = [];

    for (const file of files) {
      try {
        const url = `https://raw.githubusercontent.com/${ownerRepo}/${source.branch}/${file}`;
        const content = execSync(`curl -sf --max-time 10 "${url}"`, {
          timeout: 12000,
          stdio: ['pipe', 'pipe', 'pipe'],
          encoding: 'utf-8',
        });
        if (content) {
          const trimmed = content.length > 8000
            ? content.slice(0, 8000) + '\n\n...[truncated — full source at ' + file + ']'
            : content;
          sections.push(`--- ${file} ---\n${trimmed}`);
        }
      } catch {
        // Skip unavailable files
      }
    }

    return sections.join('\n\n');
  }

  async query(queryText: string): Promise<{ context: string; confidence: number; sources: string[] } | null> {
    const matches = this.findTopics(queryText);
    if (matches.length === 0) return null;

    const topMatches = matches.slice(0, 3);
    const seenFiles = new Set<string>();
    const filesToRead: { source: LibrarySource; file: string }[] = [];

    for (const m of topMatches) {
      for (const f of m.topic.files) {
        const key = `${m.source.id}:${f}`;
        if (!seenFiles.has(key)) {
          seenFiles.add(key);
          filesToRead.push({ source: m.source, file: f });
        }
      }
    }

    const capped = filesToRead.slice(0, 6);

    const bySource = new Map<string, { source: LibrarySource; files: string[] }>();
    for (const { source, file } of capped) {
      const existing = bySource.get(source.id);
      if (existing) {
        existing.files.push(file);
      } else {
        bySource.set(source.id, { source, files: [file] });
      }
    }

    const sections: string[] = [];
    const sources: string[] = [];
    for (const { source, files } of bySource.values()) {
      try {
        const content = this.readFiles(source, files);
        if (content) {
          sections.push(content);
          sources.push(...files.map(f => `${source.id}/${f}`));
        }
      } catch {
        // Continue with other sources
      }
    }

    if (sections.length === 0) return null;

    const context = sections.join('\n\n');
    const bestScore = topMatches[0].score;
    const confidence = Math.min(0.92, 0.6 + bestScore * 0.04);

    return { context, confidence, sources };
  }

  listSources(): { id: string; repo: string; topics: number; description: string }[] {
    return SOURCES.map(s => ({
      id: s.id,
      repo: s.repo,
      topics: s.topics.length,
      description: s.description,
    }));
  }
}
