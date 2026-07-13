# Accessibility

gmacFTP exposes its custom Slint controls to macOS accessibility services instead of relying on
pointer-only `TouchArea` elements. The implementation is intended for VoiceOver and complete
keyboard operation in both English and Polish.

## VoiceOver semantics

- Toolbar, dialog, transfer, navigation, connection, and file-management controls expose button,
  checkbox, switch, or radio-button roles with localized names and enabled/selected state.
- File panes are lists; visible rows expose the file name, file/folder kind, position, and current
  selection. Command- and Shift-based multiple selection remains available.
- Search and configuration fields expose a label, placeholder, and editable value. Password and
  passphrase values are deliberately not returned through the accessibility value API.
- Transfer and status indicators expose bounded progress values. The pane divider is a slider with
  its current value, range, step, increment/decrement actions, and Left/Right keyboard control.
- Dangerous or irreversible choices retain explicit confirmation dialogs and descriptive labels.

## Keyboard operation

- `Tab` / `Shift-Tab`: move focus between controls.
- `Space` / `Return`: activate the focused custom control.
- Arrow keys: move the active file selection; hold `Shift` to extend the range.
- `Command-A`: select all files and folders in the active pane.
- `Command-L`: edit the active pane path.
- `Command-K`: open the command palette.
- `Command-,`: open Settings.
- `Escape`: close the topmost non-mandatory panel or dialog.

Focus is shown with a high-contrast accent ring or line. Mouse behavior, Finder-style
`Shift-click` / `Command-click`, and drag and drop are unchanged.

## Regression coverage

The headless UI test `keyboard_only_shortcuts_and_focus_activation_reach_ui_actions` dispatches
real key events and verifies Command-A, Shift+Arrow, Return, Tab, and Space. It also inspects the
compiled accessibility tree and verifies representative button, text-input, checkbox, and slider
roles, localized labels, checkbox state/action, and slider values. Slint introspection metadata is
compiled into development and test profiles only; release binaries do not contain it.

## Polski

gmacFTP udostępnia własne kontrolki usługom dostępności macOS i pozwala obsługiwać interfejs bez
myszy. VoiceOver otrzymuje przetłumaczone nazwy, role, stany i wartości przycisków, pól, list
plików, przełączników, transferów oraz separatora paneli. Wartości haseł i fraz szyfrujących nie są
ujawniane przez API dostępności.

Do nawigacji służą `Tab` / `Shift-Tab`, aktywacji `Spacja` / `Return`, a do wyboru plików strzałki,
`Shift+strzałka` oraz `Command-A`. Dostępne są też `Command-L` (ścieżka), `Command-K` (paleta
poleceń), `Command-,` (Ustawienia) i `Escape` (zamknięcie bieżącej nakładki).
