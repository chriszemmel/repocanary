from figs_base import *  # noqa: F401,F403

LANG = 'de'


def tr(de, en):
    return de if LANG == 'de' else en


def num(v, d=1):
    s = f'{v:.{d}f}' if isinstance(v, float) else str(v)
    return s.replace('.', ',') if LANG == 'de' else s


TONES = {'n': ('#fff', LINE, IND7), 'ok': (OK50, '#86EFAC', OK7), 'bad': (BAD50, '#FCA5A5', BAD7),
         'dash': (PAPER, LINE, MUTED), 'teal': (TEAL50, TEAL200, TEAL7), 'ind': (IND50, IND200, IND7),
         'warn': ('#FFFBEB', '#FCD34D', WARN7)}


def box(x, y, w, h, icon, num_, title, body, tone='n', size=10.8, lh=14.5, tsize=12.5):
    f, s, c = TONES[tone]
    out = rect(x, y, w, h, f, s, 8, 1.3, '5 4' if tone == 'dash' else None)
    tx = x + 12
    if icon:
        out += ic(icon, x + 12, y + 11, 18, c)
        tx = x + 38
    tcol = INK if tone in ('n', 'dash', 'ind', 'teal') else c
    out += T(tx, y + 25, (f'{num_}  ' if num_ else '') + title, tsize, 600, tcol)
    out += L(x + 12, y + 46, body, size, lh, INK2 if tone != 'dash' else MUTED)
    return out


def mono(x, y, txt, size=10.8, fill=IND7, w=500, anchor='start'):
    return T(x, y, txt, size, w, fill, anchor, M)


def bar(y, h, text, tone='dash', icon=None):
    f, s, c = TONES[tone]
    out = rect(0, y, 638, h, f, s, 8, 1.2, '5 4' if tone == 'dash' else None)
    tx = 14
    if icon:
        out += ic(icon, 12, y + h / 2 - 9, 18, c)
        tx = 38
    return out + T(tx, y + h / 2 + 4, text, 10.8, 500 if tone == 'dash' else 600, INK2 if tone == 'dash' else c)


# ---------------------------------------------------------------- the attack
def fig_attack():
    b = box(0, 70, 150, 120, 'mail', '', tr('Ein Repository', 'A repository'),
            tr(['von einem Recruiter,', 'einem „Kunden“ oder', 'einer Kollegin:', '„Bitte ausführen.“'],
               ['from a recruiter,', 'a “client” or', 'a collaborator:', '“Please run it.”']), 'n', lh=14)
    trig = [
        ('download', tr('npm install', 'npm install'), [tr('postinstall, setup.py, build.rs, Gradle', 'postinstall, setup.py, build.rs, Gradle')]),
        ('folder-open', tr('Ordner öffnen', 'Opening the folder'), [tr('VS-Code-Task, MCP-Server, Agent-Hook', 'VS Code task, MCP server, agent hook')]),
        ('terminal', tr('npm start', 'npm start'), [tr('verschleierte Konfiguration, Nachlader', 'obfuscated config, a loader')]),
    ]
    for i, (icn, t, body) in enumerate(trig):
        b += box(196, i * 92, 250, 74, icn, '', t, body, 'warn', lh=13)
    b += box(492, 70, 146, 120, 'key-round', '', tr('Gestohlen', 'Stolen'),
             tr(['Browser-Passwörter,', 'SSH-Schlüssel,', 'Cloud-Tokens,', 'Wallets'],
                ['browser passwords,', 'SSH keys,', 'cloud tokens,', 'wallets']), 'bad', lh=14)
    b += bar(282, 40, tr('Jeder dieser Wege läuft, bevor jemand eine Zeile des Codes gelesen hat.',
                         'Every one of these paths runs before anyone has read a line of the code.'), 'bad', 'triangle-alert')
    # arrows last, so they sit on top of the boxes they enter
    for i in range(3):
        cy = i * 92 + 37
        b += path(f'M151 130 C 175 130, 172 {cy}, 194 {cy}', WARN7, 'aw', None, 1.4)
        b += path(f'M447 {cy} C 470 {cy}, 468 130, 490 130', BAD7, 'ar', None, 1.4)
    return svg(640, 324, b, tr('Der Angriff', 'The attack'))


# ---------------------------------------------------------------- read, never run
def fig_safe():
    b = box(0, 0, 240, 104, 'shield-check', '', 'RepoCanary',
            tr(['CLI, Website oder Action.', 'Liest Dateien als Text', 'und vergleicht Muster.'],
               ['CLI, website or Action.', 'Reads files as text and', 'matches patterns.']), 'ind', lh=14)
    b += box(0, 124, 240, 140, 'ban', '', tr('Nie', 'Never'),
             tr(['klonen', 'installieren', 'ausführen', 'auswerten (eval)', 'importieren'],
                ['clone', 'install', 'execute', 'evaluate (eval)', 'import']), 'bad', lh=17)
    b += box(300, 0, 338, 74, 'globe', '', 'api.github.com',
             [tr('Baum und ausgewählte Dateien, als reiner Text', 'The tree and selected files, as plain text')], 'teal', lh=13)
    b += box(300, 94, 338, 90, 'bot', '', tr('KI-Anbieter, nur mit --ai', 'AI provider, only with --ai'),
             tr(['Befunde und geschwärzte Ausschnitte,', 'mit dem eigenen Schlüssel der Nutzer'],
                ['Findings and redacted snippets,', "with the user's own key"]), 'dash', lh=14)
    b += box(300, 204, 338, 60, 'lock', '', tr('Sonst nichts', 'Nothing else'),
             [tr('Kein Konto, keine Datenbank, keine Telemetrie', 'No account, no database, no telemetry')], 'n', lh=13)
    b += bar(284, 40, tr('Ein bösartiges Repository zu prüfen ist so gefährlich, wie es im Browser zu lesen.',
                         'Scanning a malicious repository is as dangerous as reading it in a browser.'))
    b += arrow(241, 37, 298, 37, TEAL7, 'at', None, 1.6)
    b += path('M241 72 C 272 72, 268 139, 298 139', MUTED, 'a', '4 3', 1.4)
    return svg(640, 326, b, tr('Lesen, nie ausführen', 'Read, never run'))


# ---------------------------------------------------------------- pipeline
def fig_pipeline():
    w, g, h = 146, 18, 104
    row1 = [('git-branch', '1', tr('Baum lesen', 'Read the tree'), tr(['Alle Pfade über', 'die GitHub-API,', 'nichts geklont.'], ['Every path over', 'the GitHub API,', 'nothing cloned.'])),
            ('list-checks', '2', tr('Auswählen', 'Select'), tr(['Zuerst, wo eine', 'Falle liegen muss,', 'je Art ein Kontingent.'], ['Where a trap must', 'live comes first,', 'a quota per kind.'])),
            ('file-text', '3', tr('Als Text holen', 'Fetch as text'), tr(['Inhalt als String,', 'mit festen', 'Obergrenzen.'], ['Contents as strings,', 'under fixed', 'caps.'])),
            ('link', '4', tr('Nachverfolgen', 'Follow'), tr(['Was eine Datei', 'ausführen lässt, wird', 'eigens nachgeholt.'], ['What a file says', 'will run is fetched', 'on its own budget.']))]
    w2 = 200
    row2 = [('scan-search', '5', tr('Bewerten', 'Judge'), tr(['Jede Regel auf jeder Datei,', 'jede für sich.'], ['Every rule on every file,', 'each in isolation.'])),
            ('scale', '6', tr('Urteil', 'Score'), tr(['Die Schwere entscheidet', 'die Farbe.'], ['Severity decides', 'the color.'])),
            ('scroll-text', '7', tr('Bericht', 'Report'), tr(['Datei, Zeile, warum,', 'was zu tun ist.'], ['File, line, why,', 'and what to do.']))]
    b = ''
    for i, (icn, n, t, body) in enumerate(row1):
        b += box(i * (w + g), 0, w, h, icn, n, t, body, 'teal' if i < 3 else 'ind', lh=14)
    for i, (icn, n, t, body) in enumerate(row2):
        b += box(i * (w2 + 19), 140, w2, 88, icn, n, t, body, 'ok' if i == 2 else 'n', lh=14)
    b += bar(250, 40, tr('Scheitert eine Regel an präpariertem Inhalt, fehlen nur die Befunde dieser Datei, und der Bericht sagt es.',
                         'If a rule fails on crafted input, only that file’s findings are lost, and the report says so.'))
    for i in range(3):
        x = i * (w + g) + w
        b += arrow(x + 1, 52, x + g - 2, 52, TEAL7, 'at', None, 1.4)
    for i in range(2):
        x = i * (w2 + 19) + w2
        b += arrow(x + 1, 184, x + 19 - 2, 184, IND7, 'ai', None, 1.4)
    x4 = 3 * (w + g) + w / 2
    b += path(f'M{x4} {h + 1} L{x4} 122 L{w2 / 2} 122 L{w2 / 2} 138', IND7, 'ai', None, 1.4)
    return svg(640, 292, b, tr('Wie ein Scan läuft', 'How a scan runs'))


# ---------------------------------------------------------------- categories
def fig_categories():
    cats = [
        ('download', tr('npm beim Installieren', 'npm at install time'), tr(['Lifecycle-Skripte und', 'die Dateien, die sie starten'], ['lifecycle scripts and', 'the files they start']), 'n'),
        ('box', tr('Andere Ökosysteme', 'Other ecosystems'), tr(['Python, Rust, Go, JVM,', 'PHP, Ruby, Notebooks'], ['Python, Rust, Go, JVM,', 'PHP, Ruby, notebooks']), 'n'),
        ('git-branch', tr('Vergiftete Abhängigkeiten', 'Poisoned dependencies'), tr(['Lockfiles, Aliase, Git-', 'und URL-Quellen, Tippfehler'], ['lockfiles, aliases, git and', 'URL sources, typosquats']), 'n'),
        ('code', tr('Verschleierung, Nachlader', 'Obfuscation, loaders'), tr(['Herunterladen und ausführen,', 'versteckter, kodierter Code'], ['download and execute,', 'hidden and encoded code']), 'n'),
        ('key-round', tr('Diebstahl von Zugängen', 'Credential theft'), tr(['Browser, Wallets, SSH,', 'Cloud, Umgebung nach außen'], ['browsers, wallets, SSH,', 'cloud, environment sent out']), 'n'),
        ('network', tr('Fernsteuerung', 'Command and control'), tr(['bekannte Pfade, Ports und', 'Hintertüren der Kampagnen'], ['known paths, ports and', 'backdoors of the campaigns']), 'n'),
        ('folder-open', tr('Start beim Öffnen', 'Auto-run on open'), tr(['VS Code, MCP-Server, Agent-', 'Hooks, Dev-Container, direnv'], ['VS Code, MCP servers, agent', 'hooks, dev containers, direnv']), 'n'),
        ('clock', tr('Manifest, Dauerhaftigkeit', 'Manifest, persistence'), tr(['Autostarts, Cron, Dienste,', 'Startdateien der Shell'], ['autostarts, cron, services,', 'shell startup files']), 'n'),
        ('user', tr('Kontext', 'Context'), tr(['neues Konto, ein einziger', 'Commit: höchstens Gelb'], ['new account, one burst', 'of commits: yellow at most']), 'dash'),
    ]
    w, g, h = 206, 10, 80
    b = ''
    for i, (icn, t, body, tone) in enumerate(cats):
        b += box((i % 3) * (w + g), (i // 3) * (h + g), w, h, icn, '', t, body, tone, size=10.5, lh=14, tsize=11.8)
    return svg(640, 3 * h + 2 * g, b, tr('Neun Kategorien', 'Nine categories'))


# ---------------------------------------------------------------- verdict ladder
def fig_verdict():
    rows = [
        (tr('Ein Befund hoher Schwere', 'One high-severity finding'), tr('das Muster einer Falle', 'the shape of a trap'), tr('Rot', 'Red'), '2', 'bad'),
        (tr('Ein mittlerer Befund oder', 'A medium finding, or several'), tr('mehrere schwache zusammen', 'weak ones together'), tr('Gelb', 'Yellow'), '1', 'warn'),
        (tr('Nur Kontext: neues Konto,', 'Context alone: a new account,'), tr('ein einziger Commit', 'a single burst of commits'), tr('höchstens Gelb', 'yellow at most'), '1', 'warn'),
        (tr('Nichts Bekanntes passt', 'Nothing known matches'), tr('nie als „sicher“ formuliert', 'never worded as “safe”'), tr('Grün', 'Green'), '0', 'ok'),
        (tr('Der Scan wurde nicht fertig', 'The scan could not complete'), tr('nie als Grün gemeldet', 'never reported as green'), tr('Fehler', 'Error'), '3', 'dash'),
    ]
    b = ''
    for i, (a, a2, v, code, tone) in enumerate(rows):
        y = i * 48
        b += rect(0, y, 360, 40, '#fff', LINE, 8)
        b += T(12, y + 17, a, 11.3, 600, INK) + T(12, y + 32, a2, 10.5, 400, MUTED)
        f, s, c = TONES[tone]
        b += rect(420, y, 218, 40, f, s, 8, 1.3, '5 4' if tone == 'dash' else None)
        b += T(434, y + 25, v, 12.5, 600, c if tone != 'dash' else INK2)
        b += mono(624, y + 25, f'exit {code}', 10.5, MUTED, 600, 'end')
    for i in range(5):
        b += arrow(361, i * 48 + 20, 418, i * 48 + 20, MUTED, 'a', None, 1.4)
    return svg(640, 4 * 48 + 40, b, tr('Wie die Farbe entsteht', 'How the color is decided'))


# ---------------------------------------------------------------- AI bounds
def fig_ai():
    xs = [0, 234, 468]
    names = [(tr('Grün', 'Green'), 'ok'), (tr('Gelb', 'Yellow'), 'warn'), (tr('Rot', 'Red'), 'bad')]
    b = ''
    for x, (n, tone) in zip(xs, names):
        f, s, c = TONES[tone]
        b += rect(x, 46, 170, 52, f, s, 8, 1.4) + T(x + 85, 77, n, 13, 600, c, 'middle', D)
    b += bar(166, 40, tr('Erzwungen im Code, nicht im Prompt. Antwortet kein Anbieter, gilt das statische Urteil.',
                         'Enforced in code, not in the prompt. If no provider answers, the static verdict stands.'), 'teal', 'lock')
    c1, c2, c3 = 85, 319, 553
    b += path(f'M{c1 + 20} 44 C {c1 + 40} 4, {c2 - 40} 4, {c2 - 20} 44', OK7, 'ag', None, 1.6)
    b += T((c1 + c2) / 2, 18, tr('darf anheben', 'may raise'), 10.8, 600, OK7, 'middle', halo=True)
    b += path(f'M{c2 - 20} 100 C {c2 - 40} 140, {c1 + 40} 140, {c1 + 20} 100', OK7, 'ag', None, 1.6)
    b += T((c1 + c2) / 2, 134, tr('darf freigeben', 'may clear'), 10.8, 600, OK7, 'middle', halo=True)
    b += path(f'M{c2 + 20} 44 C {c2 + 40} 4, {c3 - 40} 4, {c3 - 20} 44', BAD7, 'ar', '5 4', 1.6)
    b += T((c2 + c3) / 2, 18, tr('nie erzeugen', 'never produce'), 10.8, 600, BAD7, 'middle', halo=True)
    b += path(f'M{c3 - 20} 100 C {c3 - 40} 140, {c2 + 40} 140, {c2 + 20} 100', BAD7, 'ar', '5 4', 1.6)
    b += T((c2 + c3) / 2, 134, tr('nie senken', 'never lower'), 10.8, 600, BAD7, 'middle', halo=True)
    return svg(640, 208, b, tr('Grenzen der KI', 'Bounds of the AI'))


# ---------------------------------------------------------------- surfaces
def fig_surfaces():
    b = box(0, 74, 220, 124, 'shield-check', '', tr('Eine Engine', 'One engine'),
            tr(['src/ in reinem Node,', 'ohne Laufzeit-', 'Abhängigkeiten. Eine Regel', 'verhält sich überall gleich.'],
               ['src/ in plain Node,', 'zero runtime', 'dependencies. A rule', 'behaves the same everywhere.']), 'ind', lh=14)
    outs = [('terminal', 'npx repocanary', tr('Text, JSON oder SARIF, mit Exit-Code', 'text, JSON or SARIF, with an exit code')),
            ('globe', 'repocanary.com', tr('Link einfügen, ohne Terminal und Konto', 'paste a link, no terminal, no account')),
            ('git-pull-request', 'GitHub Action', tr('fail-on und SARIF für den Security-Tab', 'fail-on and SARIF for the Security tab')),
            ('badge-check', tr('Badge im README', 'README badge'), tr('das Urteil neben dem CI-Status', 'the verdict beside the CI status'))]
    for i, (icn, t, d) in enumerate(outs):
        b += box(290, i * 68, 348, 56, icn, '', t, [d], 'n', lh=13, tsize=12)
    codes = [('0', tr('Grün', 'Green'), 'ok'), ('1', tr('Gelb', 'Yellow'), 'warn'), ('2', tr('Rot', 'Red'), 'bad'), ('3', tr('nicht fertig', 'incomplete'), 'dash')]
    b += T(0, 300, tr('Exit-Codes, gleich in CLI und Action', 'Exit codes, the same in CLI and Action'), 11.5, 600, INK, fam=D)
    for i, (c, t, tone) in enumerate(codes):
        f, s, cc = TONES[tone]
        x = i * 162
        b += rect(x, 312, 152, 40, f, s, 8, 1.3, '5 4' if tone == 'dash' else None)
        b += mono(x + 14, 337, c, 13, cc if tone != 'dash' else INK2, 600) + T(x + 36, 337, t, 11.5, 600, cc if tone != 'dash' else INK2)
    for i in range(4):
        cy = i * 68 + 28
        b += path(f'M221 136 C 255 136, 252 {cy}, 288 {cy}', IND7, 'ai', None, 1.4)
    return svg(640, 354, b, tr('Drei Oberflächen, eine Engine', 'Three surfaces, one engine'))


# ---------------------------------------------------------------- wrong reds chart
def fig_wrongreds():
    data = [('1', 13.1), ('2', 7.0), ('3', 4.0), ('4', 0.0), ('5', 1.7), ('6', 3.4), ('7', 0.0), ('8', 6.1), ('9-12', 3.75),
            ('13-14', 1.5), ('15', 0.4), ('16', 9.0), ('17-19', 5.3), ('20-23', 3.8), ('24-27', 2.75), ('28', 2.75), ('29', 2.8)]
    x0, x1, y0, y1 = 62, 638, 34, 214
    top = 14
    sc = (y1 - y0) / top
    b = ''
    split = x0 + (x1 - x0) / len(data) * 11
    b += f'<rect x="{split}" y="{y0 - 8}" width="{x1 - split}" height="{y1 - y0 + 8}" fill="{IND50}"/>'
    b += T(x0 + 4, 20, tr('Wellen 1 bis 15: breite Ziehungen', 'Waves 1 to 15: broad draws'), 10.8, 600, MUTED)
    b += T(x1 - 4, 20, tr('16 bis 29: schwerer, Regeln eingefroren', '16 to 29: harder, rules frozen'), 10.8, 600, IND7, 'end')
    for v in (0, 5, 10):
        y = y1 - v * sc
        b += f'<line x1="{x0}" y1="{y}" x2="{x1}" y2="{y}" stroke="{RULE if v else LINE}" stroke-width="{1 if v else 1.4}"/>'
        b += T(x0 - 8, y + 4, f'{v}', 10.5, 400, MUTED, 'end')
    b += f'<text transform="translate(14 {(y0 + y1) / 2}) rotate(-90)" style="{F};font-size:10.5px;font-weight:500" fill="{MUTED}" text-anchor="middle">{tr("falsche Rote in %", "wrong reds, %")}</text>'
    slot = (x1 - x0) / len(data)
    bw = slot * 0.62
    for i, (lab, v) in enumerate(data):
        cx = x0 + slot * i + slot / 2
        h = v * sc
        col = IND if i >= 11 else '#A1A1AA'
        if h:
            b += f'<rect x="{cx - bw / 2:.1f}" y="{y1 - h:.1f}" width="{bw:.1f}" height="{h:.1f}" fill="{col}"/>'
        b += T(cx, y1 - h - 5, num(v, 1 if v not in (2.75, 3.75) else 2) if v else '0', 10, 600, INK, 'middle')
        b += T(cx, y1 + 16, lab, 10, 500, INK2, 'middle')
    b += T((x0 + x1) / 2, y1 + 36, tr('Welle', 'Wave'), 10.5, 500, MUTED, 'middle')
    return svg(640, 254, b, tr('Falsche Rote je Welle', 'Wrong reds per wave'))


# ---------------------------------------------------------------- corpus verdicts
def fig_corpus():
    x0, x1 = 170, 638
    sc = (x1 - x0) / 100
    rows = [(tr('vorher', 'before'), (73, 25, 2)), (tr('nach den Korrekturen', 'after the fixes'), (77, 21, 2))]
    b = T(0, 14, tr('Urteile auf dem Regressionskorpus, in Prozent', 'Verdicts on the regression corpus, in percent'), 12, 600, INK, fam=D)
    for r, (lab, vals) in enumerate(rows):
        y = 30 + r * 46
        b += T(x0 - 12, y + 21, lab, 11, 600, INK2, 'end')
        x = x0
        for v, col, tcol in zip(vals, (OK, '#FBBF24', BAD), ('#fff', INK, '#fff')):
            b += f'<rect x="{x:.1f}" y="{y}" width="{v * sc:.1f}" height="30" fill="{col}"/>'
            if v > 5:
                b += T(x + 8, y + 20, f'{v}', 11, 700, tcol)
            x += v * sc
        b += T(x1, y + 21 + 0, '', 10, 400)
    b += T(x1, 138, tr('Rot: 2, jedes einzeln mit Grund gelistet', 'Red: 2, each listed with its reason'), 10.8, 600, BAD7, 'end')
    return svg(640, 146, b, tr('Urteile auf dem Korpus', 'Verdicts on the corpus'))


# ---------------------------------------------------------------- gates
def fig_gates():
    b = rect(0, 0, 310, 254, TEAL50, TEAL200, 10)
    b += ic('git-pull-request', 14, 13, 18, TEAL7) + T(40, 28, tr('Jeder Push, jeder Pull Request', 'Every push, every pull request'), 12.3, 600, INK)
    items = tr(['Lint, auch „null Abhängigkeiten“', 'Tests auf Node 20, 22 und 24', 'Katalog passt zu den Regeln', 'Abhängigkeiten ohne hohe Lücke',
                'Wächter: kein früherer Fang verloren', 'Paket installiert aus leerem Projekt', 'Website: Typen, Tests, Build', 'Selbst-Scan über die echte API'],
               ['Lint, including “zero dependencies”', 'Tests on Node 20, 22 and 24', 'Catalog matches the rules', 'No high dependency advisory',
                'Guard: no earlier catch lost', 'Package installs from an empty project', 'Website: types, tests, build', 'Self-scan over the real API'])
    for i, t in enumerate(items):
        y = 54 + i * 24.5
        b += ic('check', 14, y - 12, 14, OK7, 2.4) + T(36, y, t, 10.8, 500, INK2)
    b += box(360, 0, 278, 108, 'calendar-check', '', tr('Jede Woche', 'Every week'),
             tr(['Wächter mit jedem bestätigten', 'Rot, dann der ganze Korpus', 'neu gegen die echten Repos'],
                ['Guard with every confirmed', 'red, then the whole corpus', 'rescanned against live repos']), 'n', lh=14)
    b += box(360, 132, 278, 122, 'send', '', tr('Veröffentlichen', 'Publishing'),
             tr(['Tag muss auf main liegen,', 'dasselbe Gate noch einmal,', 'Prüfung durch eine Person,', 'Provenienz, kein Token'],
                ['tag must be on main,', 'the same gate again,', 'a human review step,', 'provenance, no token']), 'ok', lh=14)
    b += path('M311 193 L358 193', OK7, 'ag', None, 1.6)
    return svg(640, 256, b, tr('Die Prüfstrecke', 'The gates'))


FIGS = dict(attack=fig_attack, safe=fig_safe, pipeline=fig_pipeline, categories=fig_categories, verdict=fig_verdict,
            ai=fig_ai, surfaces=fig_surfaces, wrongreds=fig_wrongreds, corpus=fig_corpus, gates=fig_gates)
