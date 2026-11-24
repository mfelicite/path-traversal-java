# Path traversal demo using java

## Description

Dans cette démonstration, l'application autorise uniquement l'accès au répertoire `/tmp/.../data`. Un répertoire voisin `/tmp/.../data-secret` et un fichier externe `/tmp/.../system_secret.txt` simulent des données sensibles hors périmètre.

### `public.txt`
* **Attendu :** `✅ AUTORISÉ`
* **Ce qu'il se passe :** Le fichier réside directement dans `/tmp/.../data/public.txt`.
* **Résultat :** Les trois méthodes l'autorisent car le chemin normalisé et le chemin physique réel appartiennent tous deux au répertoire autorisé `/tmp/.../data`.

### `../data-secret/secret.txt`
* **Attendu :** `✅ BLOQUÉ`
* **Méthode 1 — ❌ CONTOURNÉ**
  * Après résolution de `../`, le chemin devient `/tmp/.../data-secret/secret.txt`.
  * Comme on compare des **chaînes de caractères brutes**, la chaîne `"/tmp/.../data-secret/secret.txt"` commence bien par la sous-chaîne `"/tmp/.../data"`. La vérification est trompée.
* **Méthodes 2 — ✅ BLOQUÉ**
  * `Path.startsWith()` compare la hiérarchie **segment par segment** (dossier par dossier), et non caractère par caractère. Le segment `data-secret` est distinct du segment `data` : l'accès est refusé.

### `lien_piege.txt`
* **Attendu :** `✅ BLOQUÉ`
* **Contexte :** `lien_piege.txt` est un lien symbolique situé *à l'intérieur* de `/data`, mais qui pointe vers `/tmp/.../system_secret.txt` (à l'extérieur).
* **Méthode 1 — ❌ CONTOURNÉ**
  * Le chemin reste `/tmp/.../data/lien_piege.txt`, qui commence par `/tmp/.../data`.
* **Méthode 2 — ❌ CONTOURNÉ**
  * La normalisation est **purement lexicale** (syntaxique) : elle simplifie les `.` et `..` dans la chaîne sans jamais interroger le système de fichiers. Pour elle, le fichier semble toujours être dans `/data`.
* **Méthode 3 — ✅ BLOQUÉ**
  * Ces fonctions interrogent le système de fichiers et **suivent les liens symboliques** pour obtenir l'emplacement physique réel (`/tmp/.../system_secret.txt`). Ce chemin réel n'étant pas dans `/data`, l'accès est bloqué.

### 4. `../../etc/passwd`
* **Attendu :** `✅ BLOQUÉ`
* **Ce qu'il se passe :** Le chemin remonte jusqu'à `/etc/passwd`, complètement en dehors de `/tmp/.../data`.
* **Résultat :** Les trois méthodes le bloquent car le préfixe `/tmp/.../data` disparaît dès la résolution des `../` (et en Java, `toRealPath()` rejette également tout fichier qui n'existe pas sur le disque via une `IOException`).

## How to run the code

```bash
mvn test
```

## Références
* **CERT FIO16-J, IDS01-J**
* **CWE-22**
* **OWASP : Path Traversal**