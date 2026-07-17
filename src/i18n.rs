//! Runtime localization for operational messages assembled in Rust.
//!
//! Static UI copy lives in Slint's bundled gettext catalog. Network/filesystem errors often carry
//! a path, count, server reply, or OS error and are intentionally assembled in Rust. This module
//! translates only known copy and fixed fragments while preserving those variable details byte for
//! byte. It performs no I/O and never sends text to an external service.

const EXACT_PL: &[(&str, &str)] = &[
    ("0 transfers", "0 transferów"),
    (
        "Choose a direction, then preview the changes.",
        "Wybierz kierunek, a następnie wyświetl podgląd zmian.",
    ),
    (
        "Choose a direction, then run the dry-run preview.",
        "Wybierz kierunek, a następnie uruchom podgląd dry-run.",
    ),
    ("Calculating storage use…", "Obliczanie użycia pamięci…"),
    (
        "Calculating bounded storage use…",
        "Obliczanie ograniczonego użycia pamięci…",
    ),
    ("Calculating folder size...", "Obliczanie rozmiaru folderu…"),
    (
        "Saved servers reordered.",
        "Zmieniono kolejność zapisanych serwerów.",
    ),
    ("Favorites reordered.", "Zmieniono kolejność Ulubionych."),
    (
        "Favorite already exists.",
        "Ten folder jest już w Ulubionych.",
    ),
    (
        "Only folders can be added to Favorites.",
        "Do Ulubionych można dodać tylko foldery.",
    ),
    (
        "Only local folders can be added to Favorites.",
        "Do Ulubionych można dodać tylko foldery lokalne.",
    ),
    (
        "Encrypted settings operation cancelled.",
        "Anulowano operację zaszyfrowanych ustawień.",
    ),
    ("Passphrases don't match.", "Hasła nie są zgodne."),
    (
        "Settings imported safely.",
        "Ustawienia zaimportowano bezpiecznie.",
    ),
    (
        "Vault unlocked — passwords are available.",
        "Sejf odblokowany — hasła są dostępne.",
    ),
    (
        "Older encrypted credentials were found. Confirm the downloaded server list to recover them.",
        "Znaleziono starsze zaszyfrowane dane logowania. Potwierdź pobraną listę serwerów, aby je odzyskać.",
    ),
    (
        "Password recovery was not performed. No credential data was changed.",
        "Nie wykonano odzyskiwania haseł. Dane logowania nie zostały zmienione.",
    ),
    (
        "Could not lock saved connections for password recovery.",
        "Nie udało się zablokować zapisanych połączeń na czas odzyskiwania haseł.",
    ),
    (
        "The server list or encrypted vault changed before recovery. Review it and try again.",
        "Lista serwerów lub zaszyfrowany sejf zmieniły się przed odzyskiwaniem. Sprawdź je i spróbuj ponownie.",
    ),
    (
        "No password could be recovered. The encrypted vault was left unchanged.",
        "Nie udało się odzyskać żadnego hasła. Zaszyfrowany sejf pozostał bez zmian.",
    ),
    ("Wrong passphrase.", "Nieprawidłowe hasło."),
    (
        "SFTP host key was not trusted; connection cancelled.",
        "Klucz hosta SFTP nie został zatwierdzony; anulowano połączenie.",
    ),
    (
        "SFTP host key trusted for this server. Reconnecting…",
        "Klucz hosta SFTP został zatwierdzony dla tego serwera. Ponowne łączenie…",
    ),
    (
        "FTPS certificate was not trusted; connection cancelled.",
        "Certyfikat FTPS nie został zatwierdzony; anulowano połączenie.",
    ),
    (
        "Testing connection without saving…",
        "Testowanie połączenia bez zapisywania…",
    ),
    (
        "Connected via plaintext FTP — password was sent unencrypted.",
        "Połączono przez nieszyfrowany FTP — hasło wysłano bez szyfrowania.",
    ),
    (
        "The FTPS certificate fingerprint was malformed.",
        "Odcisk certyfikatu FTPS ma nieprawidłowy format.",
    ),
    (
        "The connection changed while the certificate dialog was open.",
        "Połączenie zmieniło się, gdy okno certyfikatu było otwarte.",
    ),
    (
        "Could not lock saved connections.",
        "Nie udało się zablokować zapisanych połączeń.",
    ),
    (
        "The saved connection no longer exists.",
        "Zapisane połączenie już nie istnieje.",
    ),
    (
        "Run a dry-run preview before applying.",
        "Przed zastosowaniem uruchom podgląd dry-run.",
    ),
    (
        "Run a dry-run preview before exporting a report.",
        "Przed eksportem raportu uruchom podgląd dry-run.",
    ),
    (
        "The server credential is unavailable.",
        "Dane logowania do serwera są niedostępne.",
    ),
    (
        "The active server credential is unavailable.",
        "Dane logowania do aktywnego serwera są niedostępne.",
    ),
    ("missing credential", "brak danych logowania"),
    ("Missing credential.", "Brak danych logowania."),
    ("Remote search cancelled.", "Anulowano wyszukiwanie zdalne."),
    (
        "Cancelling remote search…",
        "Anulowanie wyszukiwania zdalnego…",
    ),
    (
        "Wait until both directory listings are complete.",
        "Poczekaj na zakończenie wczytywania obu katalogów.",
    ),
    (
        "Both panes must contain an available local folder or server.",
        "Oba panele muszą zawierać dostępny folder lokalny lub serwer.",
    ),
    (
        "Could not enable synchronized browsing.",
        "Nie udało się włączyć zsynchronizowanego przeglądania.",
    ),
    (
        "Places are available only for a connected remote pane.",
        "Miejsca są dostępne tylko dla połączonego panelu zdalnego.",
    ),
    (
        "Could not identify the active endpoint safely.",
        "Nie udało się bezpiecznie zidentyfikować aktywnego serwera.",
    ),
    (
        "This server place is already saved.",
        "To miejsce na serwerze jest już zapisane.",
    ),
    (
        "The saved remote-place limit has been reached.",
        "Osiągnięto limit zapisanych miejsc zdalnych.",
    ),
    (
        "Current remote folder added to Places.",
        "Bieżący folder zdalny dodano do Miejsc.",
    ),
    ("Remote Place removed.", "Usunięto zdalne Miejsce."),
    (
        "Already viewing Remote Trash.",
        "Zdalny Kosz jest już otwarty.",
    ),
    (
        "Missing credential; could not open Remote Trash.",
        "Brak danych logowania; nie można otworzyć zdalnego Kosza.",
    ),
    ("Remote Trash is empty.", "Zdalny Kosz jest pusty."),
    (
        "Invalid quarantined filename; nothing was changed.",
        "Nieprawidłowa nazwa w kwarantannie; niczego nie zmieniono.",
    ),
    (
        "Missing credential; nothing was restored.",
        "Brak danych logowania; niczego nie przywrócono.",
    ),
    (
        "Select a saved server before changing its TLS policy.",
        "Przed zmianą zasad TLS wybierz zapisany serwer.",
    ),
    (
        "The active server is no longer saved.",
        "Aktywny serwer nie jest już zapisany.",
    ),
    ("Invalid folder name.", "Nieprawidłowa nazwa folderu."),
    (
        "Invalid remote filename; nothing was deleted.",
        "Nieprawidłowa zdalna nazwa; niczego nie usunięto.",
    ),
    (
        "Select at least one item to copy.",
        "Zaznacz co najmniej jeden element do skopiowania.",
    ),
    (
        "The source pane is unavailable.",
        "Panel źródłowy jest niedostępny.",
    ),
    (
        "The gmacFTP file clipboard is empty.",
        "Schowek plików gmacFTP jest pusty.",
    ),
    (
        "Paste started with normal conflict checks.",
        "Rozpoczęto wklejanie ze standardową kontrolą konfliktów.",
    ),
    (
        "Select at least one item to duplicate.",
        "Zaznacz co najmniej jeden element do zduplikowania.",
    ),
    (
        "Duplicating selected item(s) under unique names…",
        "Duplikowanie zaznaczonych elementów pod unikalnymi nazwami…",
    ),
    (
        "Select at least one item to move.",
        "Zaznacz co najmniej jeden element do przeniesienia.",
    ),
    (
        "A folder cannot be moved into itself or its descendant.",
        "Folderu nie można przenieść do niego samego ani jego podfolderu.",
    ),
    (
        "Select at least two items for batch rename.",
        "Zaznacz co najmniej dwa elementy do zmiany nazw.",
    ),
    (
        "Remote editing requires a connected server pane.",
        "Edycja zdalna wymaga połączonego panelu serwera.",
    ),
    ("copied to clipboard", "skopiowano do schowka"),
    (
        "clipboard copy failed",
        "kopiowanie do schowka nie powiodło się",
    ),
    (
        "cancelling selected transfer…",
        "anulowanie wybranego transferu…",
    ),
    (
        "transfer queued again",
        "transfer ponownie dodano do kolejki",
    ),
    (
        "Retry data is no longer available.",
        "Dane potrzebne do ponowienia nie są już dostępne.",
    ),
    ("Transfer queue is full.", "Kolejka transferów jest pełna."),
    (
        "Only a transfer that is still queued can be paused.",
        "Wstrzymać można tylko transfer pozostający w kolejce.",
    ),
    (
        "Invalid transfer priority.",
        "Nieprawidłowy priorytet transferu.",
    ),
    (
        "Priority can be changed only while a transfer is queued.",
        "Priorytet można zmienić tylko dla transferu w kolejce.",
    ),
    (
        "Transfer priority updated.",
        "Zaktualizowano priorytet transferu.",
    ),
    (
        "Only queued transfers can be reordered.",
        "Zmieniać kolejność można tylko transferom w kolejce.",
    ),
    (
        "Transfer is already at the edge of its priority group.",
        "Transfer jest już na skraju swojej grupy priorytetu.",
    ),
    (
        "Transfer started before it could be reordered.",
        "Transfer rozpoczął się przed zmianą kolejności.",
    ),
    (
        "Transfer queue reordered.",
        "Zmieniono kolejność transferów.",
    ),
    (
        "Redacted transfer history exported.",
        "Wyeksportowano zanonimizowaną historię transferów.",
    ),
    (
        "failed file skipped — continuing batch",
        "pominięto błędny plik — partia jest kontynuowana",
    ),
    (
        "stopping remaining files in this batch…",
        "zatrzymywanie pozostałych plików w tej partii…",
    ),
    ("Metadata caches cleared.", "Wyczyszczono cache metadanych."),
    (
        "Calculated folder metadata caches cleared.",
        "Wyczyszczono cache obliczonych metadanych folderów.",
    ),
    (
        "Sync folder updated safely.",
        "Folder synchronizacji zaktualizowano bezpiecznie.",
    ),
    ("folder is empty", "folder jest pusty"),
    (
        "remote→remote copy complete",
        "zakończono kopiowanie zdalne→zdalne",
    ),
    (
        "preparing folder upload…",
        "przygotowywanie wysyłania folderu…",
    ),
    (
        "preparing folder download…",
        "przygotowywanie pobierania folderu…",
    ),
    ("copying…", "kopiowanie…"),
    (
        "Update checks are available only in the public gmacFTP build.",
        "Sprawdzanie aktualizacji jest dostępne tylko w publicznej wersji gmacFTP.",
    ),
    (
        "An update check is already running.",
        "Sprawdzanie aktualizacji już trwa.",
    ),
    ("Checking for updates…", "Sprawdzanie aktualizacji…"),
    (
        "Could not prepare the verified update prompt.",
        "Nie udało się przygotować okna zweryfikowanej aktualizacji.",
    ),
    (
        "A new gmacFTP version is available.",
        "Dostępna jest nowa wersja gmacFTP.",
    ),
    (
        "The selected update is no longer available; check again.",
        "Wybrana aktualizacja nie jest już dostępna; sprawdź ponownie.",
    ),
    (
        "Downloading and verifying the signed update…",
        "Pobieranie i weryfikowanie podpisanej aktualizacji…",
    ),
];

// Ordered longest-first where overlaps matter. These fragments cover messages with a retained
// path, file name, item count, protocol reply or operating-system error.
const FRAGMENTS_PL: &[(&str, &str)] = &[
    (
        "Could not recover saved passwords: ",
        "Nie udało się odzyskać zapisanych haseł: ",
    ),
    (
        "Could not inspect saved passwords: ",
        "Nie udało się sprawdzić zapisanych haseł: ",
    ),
    (
        ". You can connect normally now.",
        ". Możesz teraz normalnie się łączyć.",
    ),
    (
        "; ambiguous passwords requiring manual re-entry: ",
        "; niejednoznaczne hasła wymagające ponownego wpisania: ",
    ),
    (
        "Ambiguous synced passwords requiring manual re-entry: ",
        "Niejednoznaczne zsynchronizowane hasła wymagające ponownego wpisania: ",
    ),
    ("Recovered saved passwords: ", "Odzyskane zapisane hasła: "),
    (
        "Could not save the FTPS certificate pin: ",
        "Nie udało się zapisać przypięcia certyfikatu FTPS: ",
    ),
    (
        "Could not migrate saved passwords: ",
        "Nie udało się zmigrować zapisanych haseł: ",
    ),
    (
        "Could not prepare folder upload: ",
        "Nie udało się przygotować wysyłania folderu: ",
    ),
    (
        "could not prepare folder upload: ",
        "nie udało się przygotować wysyłania folderu: ",
    ),
    (
        "could not prepare folder download: ",
        "nie udało się przygotować pobierania folderu: ",
    ),
    (
        "Could not save sync profile: ",
        "Nie udało się zapisać profilu synchronizacji: ",
    ),
    (
        "Could not delete sync profile: ",
        "Nie udało się usunąć profilu synchronizacji: ",
    ),
    (
        "Could not export transfer report: ",
        "Nie udało się wyeksportować raportu transferów: ",
    ),
    (
        "Could not export synchronization report: ",
        "Nie udało się wyeksportować raportu synchronizacji: ",
    ),
    (
        "Could not open Remote Trash: ",
        "Nie udało się otworzyć zdalnego Kosza: ",
    ),
    (
        "Could not save remote Place: ",
        "Nie udało się zapisać zdalnego Miejsca: ",
    ),
    (
        "Could not remove remote Place: ",
        "Nie udało się usunąć zdalnego Miejsca: ",
    ),
    (
        "Could not save Favorites order: ",
        "Nie udało się zapisać kolejności Ulubionych: ",
    ),
    (
        "Could not save Favorites: ",
        "Nie udało się zapisać Ulubionych: ",
    ),
    (
        "Could not remove Favorite: ",
        "Nie udało się usunąć z Ulubionych: ",
    ),
    (
        "Could not save server order: ",
        "Nie udało się zapisać kolejności serwerów: ",
    ),
    (
        "Could not save settings: ",
        "Nie udało się zapisać ustawień: ",
    ),
    (
        "Could not import settings: ",
        "Nie udało się zaimportować ustawień: ",
    ),
    (
        "Could not save language: ",
        "Nie udało się zapisać języka: ",
    ),
    ("Could not save theme: ", "Nie udało się zapisać motywu: "),
    (
        "Update check failed: ",
        "Sprawdzanie aktualizacji nie powiodło się: ",
    ),
    (
        "Update download failed: ",
        "Pobieranie aktualizacji nie powiodło się: ",
    ),
    (
        "Connection successful — listed ",
        "Połączenie udane — odczytano elementy (",
    ),
    (
        " item(s), but the session is plaintext FTP.",
        "), ale sesja korzysta z nieszyfrowanego FTP.",
    ),
    (
        "Connection successful — authentication and listing completed (",
        "Połączenie udane — zakończono logowanie i listowanie; elementy (",
    ),
    (" item(s)).", ")."),
    (
        "Connection test failed: ",
        "Test połączenia nie powiódł się: ",
    ),
    ("gmacFTP is up to date (v", "gmacFTP jest aktualny (v"),
    ("Verified update ", "Zweryfikowaną aktualizację "),
    (
        " opened — drag gmacFTP to Applications, then relaunch.",
        " otwarto — przeciągnij gmacFTP do Aplikacji, a następnie uruchom ponownie.",
    ),
    ("Could not copy ", "Nie udało się skopiować "),
    (
        "Could not inspect metadata: ",
        "Nie udało się odczytać metadanych: ",
    ),
    (
        "Could not start external drag.",
        "Nie udało się rozpocząć przeciągania poza aplikację.",
    ),
    (
        "Could not prepare drag: ",
        "Nie udało się przygotować przeciągania: ",
    ),
    ("Cannot save profile: ", "Nie można zapisać profilu: "),
    (
        "Sync preview failed: ",
        "Podgląd synchronizacji nie powiódł się: ",
    ),
    (
        "Invalid sync comparison settings: ",
        "Nieprawidłowe ustawienia porównania synchronizacji: ",
    ),
    (
        "Invalid comparison settings: ",
        "Nieprawidłowe ustawienia porównania: ",
    ),
    ("Invalid exclusions: ", "Nieprawidłowe wykluczenia: "),
    (
        "Invalid search result: ",
        "Nieprawidłowy wynik wyszukiwania: ",
    ),
    ("Skipped existing item: ", "Pominięto istniejący element: "),
    ("Skipped ", "Pominięto "),
    ("Copying ", "Kopiowanie "),
    ("copying ", "kopiowanie "),
    ("Copied ", "Skopiowano "),
    ("copied ", "skopiowano "),
    ("Downloading ", "Pobieranie "),
    ("downloading ", "pobieranie "),
    ("Uploading ", "Wysyłanie "),
    ("uploading ", "wysyłanie "),
    ("Moving ", "Przenoszenie "),
    ("Moved ", "Przeniesiono "),
    ("moved ", "przeniesiono "),
    ("Renaming ", "Zmiana nazw "),
    ("Renamed ", "Zmieniono nazwę "),
    ("Loading directory… ", "Wczytywanie katalogu… "),
    (
        "Opening the folder containing ",
        "Otwieranie folderu zawierającego ",
    ),
    ("Folder size: ", "Rozmiar folderu: "),
    ("folder not found: ", "nie znaleziono folderu: "),
    ("delete failed: ", "usuwanie nie powiodło się: "),
    ("copy failed: ", "kopiowanie nie powiodło się: "),
    (
        "FTP→FTP relay failed: ",
        "Przekazywanie FTP→FTP nie powiodło się: ",
    ),
    ("Passphrase exceeds ", "Hasło przekracza "),
    ("Added to Favorites: ", "Dodano do Ulubionych: "),
    ("Removed from Favorites: ", "Usunięto z Ulubionych: "),
    (
        "Saved synchronization profile ",
        "Zapisano profil synchronizacji ",
    ),
    (
        "Deleted synchronization profile ",
        "Usunięto profil synchronizacji ",
    ),
    ("Selected ", "Zaznaczono "),
    ("Searching under ", "Wyszukiwanie w "),
    (" path(s)", " ścieżek"),
    (" item(s)", " elementów"),
    (" file(s)", " plików"),
    (" files", " plików"),
    (" entries", " pozycji"),
    (" bytes.", " bajtów."),
];

pub fn runtime(message: &str, locale: &str) -> String {
    if locale != "pl" || message.is_empty() {
        return message.to_string();
    }
    if let Some((_, translation)) = EXACT_PL.iter().find(|(source, _)| *source == message) {
        return (*translation).to_string();
    }
    let mut localized = message.to_string();
    for (source, translation) in FRAGMENTS_PL {
        if localized.contains(source) {
            localized = localized.replace(source, translation);
        }
    }
    localized
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn quoted_values_after(source: &str, marker: &str) -> HashSet<String> {
        let mut values = HashSet::new();
        let mut remaining = source;
        while let Some(offset) = remaining.find(marker) {
            let value_start = offset + marker.len();
            let bytes = remaining.as_bytes();
            let mut escaped = false;
            let mut end = value_start;
            while end < bytes.len() {
                match bytes[end] {
                    b'"' if !escaped => break,
                    b'\\' if !escaped => escaped = true,
                    _ => escaped = false,
                }
                end += 1;
            }
            assert!(end < bytes.len(), "unterminated string after {marker:?}");
            values.insert(remaining[value_start..end].to_string());
            remaining = &remaining[end + 1..];
        }
        values
    }

    #[test]
    fn english_and_unknown_details_are_preserved() {
        let message = "Could not copy /private/example: permission denied";
        assert_eq!(runtime(message, "en"), message);
        let polish = runtime(message, "pl");
        assert!(polish.starts_with("Nie udało się skopiować "));
        assert!(polish.contains("/private/example: permission denied"));
    }

    #[test]
    fn exact_operational_copy_is_localized() {
        assert_eq!(
            runtime("Remote Trash is empty.", "pl"),
            "Zdalny Kosz jest pusty."
        );
        assert_eq!(runtime("opaque server reply", "pl"), "opaque server reply");
        assert_eq!(
            runtime(
                "Connection successful — listed 3 item(s), but the session is plaintext FTP.",
                "pl"
            ),
            "Połączenie udane — odczytano elementy (3), ale sesja korzysta z nieszyfrowanego FTP."
        );
        assert_eq!(
            runtime(
                "Connected via plaintext FTP — password was sent unencrypted.",
                "pl"
            ),
            "Połączono przez nieszyfrowany FTP — hasło wysłano bez szyfrowania."
        );
        assert_eq!(
            runtime(
                "Recovered saved passwords: 12. You can connect normally now.",
                "pl"
            ),
            "Odzyskane zapisane hasła: 12. Możesz teraz normalnie się łączyć."
        );
        assert_eq!(
            runtime(
                "Password recovery was not performed. No credential data was changed.",
                "pl"
            ),
            "Nie wykonano odzyskiwania haseł. Dane logowania nie zostały zmienione."
        );
    }

    #[test]
    fn slint_catalog_covers_every_static_translation() {
        let ui = [
            include_str!("../ui/app.slint"),
            include_str!("../ui/foundation.slint"),
            include_str!("../ui/controls/actions.slint"),
            include_str!("../ui/controls/visuals.slint"),
            include_str!("../ui/controls/fields.slint"),
        ]
        .join("\n");
        let polish = include_str!("../translations/pl/LC_MESSAGES/gmacftp.po");
        let used = quoted_values_after(&ui, "@tr(\"");
        let catalog = quoted_values_after(polish, "msgid \"");
        let mut missing: Vec<_> = used.difference(&catalog).cloned().collect();
        missing.sort();
        assert!(
            missing.is_empty(),
            "missing Polish msgid entries: {missing:?}"
        );
        assert!(!ui.contains("I18n.locale =="));
        assert!(!ui.contains("locale == \"pl\" ?"));
        assert!(!ui.contains("gmacFTP 0.1.1"));
    }
}
