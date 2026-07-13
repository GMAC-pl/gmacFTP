# gmacFTP visual system

The interface uses one restrained accent, neutral surfaces, and status color only when the color
communicates state. It follows the underlying principles of Apple's macOS guidance—familiar,
optically balanced vector symbols and a coherent sidebar scale—without copying another product's
trade dress. Tesla's status-first presentation is used only as a reference for reducing visual
noise around secondary actions.

## Scale

- Small glyph: 12 px inside a 28 px hit target (sidebar row actions).
- Regular glyph: 16 px inside a 32 px toolbar target.
- Large glyph: 24 px for empty/loading states only.
- Compact protocol badge: 34 × 16 px; it must not compete with the server name or row action.
- Saved server row: 36 px; connected session row: 44 px because it includes a second line.

The hit target and the visible glyph deliberately use different sizes. Equal numeric bounds do not
guarantee equal perceived size, so icons are adjusted optically through stroke weight and scale.

## Color and hierarchy

- Blue is the primary-action and selection accent.
- Green means an established connection or successful state.
- Red is reserved for destructive/disconnect states and becomes filled only on hover or explicit
  destructive confirmation.
- Toolbar utility actions are neutral until hover; only the current primary action is filled.
- Protocol badges are quiet semantic labels: FTP blue, FTPS green, SFTP violet.

## Icon source

UI glyphs are repository-owned Slint vector paths with a 16 × 16 view box. Raster assets are not
used for controls, so icons remain crisp at Retina scale, respond to light/dark themes, and do not
depend on a system font being present.

References:

- [Apple Human Interface Guidelines — Icons](https://developer.apple.com/design/human-interface-guidelines/icons)
- [Apple Human Interface Guidelines — Sidebars](https://developer.apple.com/design/human-interface-guidelines/sidebars)
- [Apple SF Symbols](https://developer.apple.com/sf-symbols/)
- [Tesla app support](https://www.tesla.com/support/tesla-app)
