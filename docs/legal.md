# Wettelijk kader · `wimsalabim`

> Niet één pdf-disclaimer, maar getoetst gedrag in de code.

## NL Sr art. 138ab — computervredebreuk

> "Hij die opzettelijk en wederrechtelijk binnendringt in een geautomatiseerd werk …"

**Hoe wij hieraan voldoen:**

- Analyzers krijgen een ``legal_class``-label: ``passive``, ``active`` of ``intrusive``.
- ``passive`` = uitsluitend openbare bronnen (DNS, CT-logs, WHOIS, single HTTP GET, single TLS-handshake). Niet beschouwd als "binnendringen".
- ``active`` (port-scan, directory-brute) = de ``AuthorizationGate`` weigert de uitvoering tenzij autorisatiebewijs voor het doel is verstrekt.
- ``intrusive`` (toekomstige analyzers met fuzzing/load) vereist daarbovenop ``--allow-intrusive`` als expliciete bevestiging.

Praktisch: zonder autorisatie raakt deze tool nooit een actieve socket op een derde-systeem.

## AVG art. 5 / 6 — beginselen rechtmatige verwerking

WHOIS-records bevatten persoonsgegevens (naam, adres, e-mail). Wij:

- **Redacten default** velden uit ``_WHOIS_PII_FIELDS`` (zie ``core/privacy.py``).
- Vereisen ``--show-pii`` om PII zichtbaar te maken — alleen logisch op data die de operator zelf bezit.
- Slaan rapporten lokaal op; sturen niets door naar externe partijen.

## AVG art. 25 — Privacy by Design

- Telemetrie-blacklist in ``core/privacy.py``; HTTP-client weigert verkeer naar deze hosts vóór de socket opent.
- ``tests/test_no_telemetry.py`` bewijst statisch dat de codebase géén bekende telemetrie-libraries importeert.
- Reports lokaal versleuteld at rest mogelijk via ``age`` (operator-key).

## NCSC-richtlijn responsible disclosure

Vindt deze tool kwetsbaarheden in een doel waarvoor je geautoriseerd bent (bug-bounty, eigen domein):

1. Genereer een SARIF/JSON-rapport.
2. Onderteken het (``--sign``) en stamp met OpenTimestamps.
3. Stuur het naar de eigenaar / het bug-bounty-programma vóór publieke disclosure.
4. Hanteer 90-dagen-window (industry standard) tenzij eigenaar korter accepteert.

## EU AI-Act

Onze ``HeuristicRiskEngine`` is **geen AI-systeem** in de zin van de AI-Act:

- Geen geleerd model, geen training, geen statistische generalisatie.
- Elke score volgt deterministisch uit een geregistreerde regel met expliciete predikaat.
- Volledig uitlegbaar; geen "automated decision-making" zonder menselijke check.

Indien wij ooit een echte ``--engine=ml`` toevoegen, gaat hij door dezelfde uitlegbaarheidstest plus dataset-card en model-card.

## Wat deze tool **niet** doet

- Geen exploitation. Geen RCE-pogingen. Geen bewijs-leverend overschrijven van staat.
- Geen credential-bruteforce.
- Geen zone transfers (AXFR).
- Geen shodan-style internet-scale crawling — één doel per scan.
- Geen telemetrie.

## Aansprakelijkheid

Door de aard van de licentie (AGPL-3.0) levert deze software **geen garantie**. Verantwoordelijkheid voor gebruik ligt bij de operator. Lees [LICENSE](../LICENSE) §15-§17.
