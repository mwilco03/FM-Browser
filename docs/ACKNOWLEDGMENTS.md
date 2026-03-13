# Acknowledgments

This tool exists because of the extraordinary work of people and communities who build things and share them freely. We stand on the shoulders of giants, and we are grateful.

---

## Core Infrastructure

### [SQLite](https://sqlite.org/) & [FTS5](https://www.sqlite.org/fts5.html)

D. Richard Hipp and the SQLite team have given the world the most widely deployed database engine in history, and they did it as a gift to the public domain. The fact that a single-analyst forensic tool can do full-text search across millions of browser visits with zero infrastructure is because of their decades of careful, principled engineering. The FTS5 module is a masterpiece that makes this entire project's search capability possible.

SQLite is also, quietly, the reason browser history databases exist in the format they do. Chrome, Firefox, Safari, and Edge all chose SQLite as their local storage engine. This tool reads SQLite databases that were written by SQLite. It's SQLite all the way down.

Thank you, Dr. Hipp. Thank you to everyone who has contributed to SQLite over the years.

### [Python](https://www.python.org/)

Guido van Rossum created Python in 1991, and the community that grew around it built a standard library so comprehensive that this entire four-stage forensic pipeline — archive extraction (`zipfile`, `tarfile`), binary parsing (`struct`), timestamp conversion (`datetime`), URL decomposition (`urllib.parse`), regex classification (`re`), base64 detection (`base64`), CSV export (`csv`), and a web server — runs on stdlib plus one package.

That's not an accident. It's the result of thirty years of thoughtful contributions from thousands of people who believed that batteries should be included.

Thank you.

### [Flask](https://flask.palletsprojects.com/)

Armin Ronacher and the Pallets team created a web framework that gets out of your way and lets you ship. Flask's philosophy of simplicity and extensibility means this entire server is one readable file. The ecosystem Armin built — Werkzeug, Jinja2, Click — represents some of the most thoughtfully designed Python code ever written.

Flask started as an April Fools' joke in 2010. Sixteen years later, it's one of the most widely used web frameworks in the world. Sometimes the best ideas don't take themselves too seriously at the start.

Thank you, Armin. Thank you to the Pallets maintainers who keep it going.

---

## Frontend

### [React](https://react.dev/)

Jordan Walke created React at Facebook in 2013, and the React team at Meta has continued to evolve it into one of the most transformative UI libraries ever built. The component model changed how we all think about interfaces. The fact that we can ship a single HTML file with a CDN import and build a full forensic analysis SPA — with infinite scroll, dynamic charts, interactive heatmaps, and real-time filtering — is a testament to how well React was designed from the start.

Thank you to Jordan Walke, Dan Abramov, Sophie Alpert, Andrew Clark, and the entire React team past and present.

### [Babel](https://babeljs.io/)

Sebastian McKenzie started Babel as a teenager, and the team that grew around it made modern JavaScript accessible to everyone. Babel Standalone lets us write JSX directly in the browser without a build step — no Node.js, no webpack, no npm install. That single capability is the reason this tool has zero frontend toolchain dependencies and can ship as one HTML file.

That design choice keeps FM-Browser simple, portable, and deployable anywhere. It's a direct gift from the Babel team's work.

Thank you, Sebastian. Thank you to Henry Zhu and the Babel maintainers.

### [IBM Plex](https://www.ibm.com/plex/) & [DM Sans](https://fonts.google.com/specimen/DM+Sans)

Mike Abbink and Bold Monday designed IBM Plex as IBM's corporate typeface and released it to the world as open source under the SIL Open Font License. When you're staring at thousands of URLs, timestamps, and hex strings, a well-designed monospace font is the difference between reading and squinting. IBM Plex Mono makes forensic data legible.

Colophon Foundry designed DM Sans for DeepMind, and they too released it openly. It provides the clean, readable sans-serif that keeps the UI approachable.

Beautiful typography is an act of generosity. Thank you.

---

## Infrastructure & Services

### [Cloudflare](https://cdnjs.cloudflare.com/) (cdnjs)

cdnjs is the free, open-source CDN that serves React, Babel, and countless other libraries to developers worldwide. FM-Browser loads its entire frontend framework from cdnjs. Infrastructure is invisible when it works well, and cdnjs just works — fast, reliable, and free.

Thank you to the Cloudflare team and the cdnjs community maintainers.

### [Google Fonts](https://fonts.google.com/)

For hosting and serving open-source typefaces to the world for free, making good typography accessible to every project regardless of budget. FM-Browser's fonts load in milliseconds from Google's edge network, and it costs us nothing. That's a remarkable thing.

Thank you.

---

## Tools

### [7-Zip](https://www.7-zip.org/) & [p7zip](https://p7zip.sourceforge.net/)

Igor Pavlov built 7-Zip and released it under the LGPL. The p7zip team ported it to POSIX systems. Forensic acquisitions almost always arrive as password-protected 7z archives (the convention of using passwords like `infected` and `dangerous` is itself a community tradition), and this tool's ability to recursively crack into nested archives is entirely thanks to their work.

When you hand FM-Browser a `.7z` inside a `.tar.gz` inside a `.zip` and it just figures it out — that's Igor's code doing the heavy lifting.

Thank you, Igor. Thank you to the p7zip maintainers.

---

## The Communities

### The Browser Forensics & DFIR Community

The analysts, researchers, and digital forensics practitioners who documented how Chrome, Firefox, Safari, and Edge store their history data. These schemas are largely undocumented by the browser vendors. They change between versions without notice. The knowledge exists because people in the community reverse-engineered it and wrote it up.

Every blog post explaining Chrome's `visit_source` table values. Every write-up on Firefox frecency scores and sync metadata. Every deep dive into Safari's binary Core Data timestamps and the `origin` column. Every StackOverflow answer about Chromium's epoch offset (January 1, 1601 — really, Google?). Every conference talk walking through browser artifact locations on macOS vs. Windows.

That collective body of knowledge is what makes this tool's visit source detection, sync identification, and cross-browser normalization accurate. None of it was obvious. All of it was hard-won.

Thank you to everyone who has ever shared their forensic findings publicly. You made this possible.

### The Open Source Community

This tool is built entirely from open-source components. Every dependency — from the database engine to the web framework to the UI library to the fonts — was created by people who chose to share their work freely. Some of them are paid to do it. Many are not. All of them deserve recognition.

The open-source model works because people contribute more than they take. FM-Browser is a small tool built on the shoulders of giants, and we are grateful for every one of them.

---

*If this tool saves you time in your work, consider paying it forward. Contribute to the open-source projects listed above. Write up your forensic findings. Share what you learn with the community. That's how we got here, and that's how we keep going.*
