/**
 * The security-audit surfaces' one stylesheet and its injector.
 *
 * A plugin built by the harness ships no stylesheet file, so the strings live
 * here and `apply` injects them once per page as one tagged style element.
 * @module delorun-plugin-security-audit/client/styles
 */

/** The style element's owner tag, which also keys the duplicate check. */
const STYLE_OWNER = 'delorun-plugin-security-audit'

/** Every class the plugin's surfaces use. */
const STYLES = `/* The security-audit surfaces' one stylesheet: the composer strip, the run pane
   and the session-header control. A harness-built plugin ships no stylesheet
   file, so the plugin injects this once per page and removes it when it unloads.
   Class names are namespaced because there is no hashing. Tokens only: no literal
   colours, radii or sizes that the theme already names. */

/* The composer strip: one quiet card sized to the composer, never a wide banner. */
.sa-strip {
  box-sizing: border-box;
  flex: none;
  overflow: hidden;
  margin: 0 auto;
  width: calc(
    100% -
    var(--dsh-composer-side-clearance) -
    var(--dsh-composer-side-clearance) -
    var(--dsh-composer-dock-inset) -
    var(--dsh-composer-dock-inset) -
    var(--dsh-composer-dock-inset) -
    var(--dsh-composer-dock-inset)
  );
  max-width: calc(
    var(--dsh-composer-card-max-width) -
    var(--dsh-composer-dock-inset) -
    var(--dsh-composer-dock-inset) -
    var(--dsh-composer-dock-inset) -
    var(--dsh-composer-dock-inset)
  );
  border: 0;
  --dsw-elevation-stroke-color: var(--dsw-alias-border-l1);
  border-radius: var(--dsw-radius-lg);
  background: var(--dsw-specific-menu);
  backdrop-filter: var(--dsw-menu-backdrop-filter);
  box-shadow: var(--dsw-elevation-panel);
}

.sa-strip-body {
  display: flex;
  flex-direction: column;
  gap: 6px;
  padding: 6px 12px;
}

.sa-strip-row {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 6px 8px;
  min-width: 0;
}

.sa-strip-title {
  flex: none;
  font-size: 13px;
  line-height: 24px;
  font-weight: 500;
  color: var(--dsw-alias-label-primary);
}

.sa-strip-lead {
  display: grid;
  flex: none;
  place-items: center;
  color: var(--dsw-alias-label-tertiary);
}

.sa-strip-actions {
  display: flex;
  flex: none;
  align-items: center;
  gap: 6px;
  margin-left: auto;
}

.sa-strip-note {
  margin: 0;
  font-size: 12px;
  line-height: 16px;
  color: var(--dsw-alias-label-tertiary);
}

/* One setting: its name and current value on one small capsule. */
.sa-chip {
  display: inline-flex;
  flex: none;
  align-items: center;
  gap: 5px;
  box-sizing: border-box;
  height: 24px;
  padding: 0 8px;
  border: 0;
  border-radius: var(--dsw-radius-sm);
  background: transparent;
  color: var(--dsw-alias-label-secondary);
  font-size: 12px;
  line-height: 16px;
  cursor: pointer;
  white-space: nowrap;
}

@media (hover: hover) {
  .sa-chip:hover {
    background: var(--dsw-alias-interactive-bg-hover);
  }
}

.sa-chip:focus-visible,
.sa-select:focus-visible,
.sa-icon-button:focus-visible,
.sa-header-trigger:focus-visible,
.sa-finding:focus-visible {
  outline: var(--dsw-focus-ring-width) solid var(--dsw-focus-ring-color, var(--dsw-alias-brand-primary));
  outline-offset: calc(-1 * var(--dsw-focus-ring-width));
}

.sa-chip-name {
  color: var(--dsw-alias-label-tertiary);
}

.sa-chip-value {
  color: var(--dsw-alias-label-primary);
}

.sa-chip-chevron {
  display: grid;
  place-items: center;
  color: var(--dsw-alias-label-tertiary);
}

/* The run pane: its header across the pane, then the scrolling body. */
.sa-pane {
  display: flex;
  flex: 1 1 auto;
  flex-direction: column;
  min-width: 0;
  min-height: 0;
  height: 100%;
  color: var(--dsw-alias-label-primary);
  font-size: 13px;
  line-height: 1.5;
}

.sa-pane-header {
  display: flex;
  flex: none;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  border-bottom: 0.5px solid var(--dsw-alias-border-l3);
}

.sa-pane-icon {
  position: relative;
  display: grid;
  flex: none;
  place-items: center;
  color: var(--dsw-alias-label-tertiary);
}

.sa-pane-title {
  flex: none;
  font-size: 13px;
  font-weight: 500;
  line-height: 24px;
  white-space: nowrap;
}

.sa-spacer {
  flex: 1 1 auto;
  min-width: 0;
}

.sa-select {
  display: inline-flex;
  flex: none;
  align-items: center;
  gap: 4px;
  max-width: 140px;
  height: 24px;
  padding: 0 6px;
  border: 0;
  border-radius: var(--dsw-radius-sm);
  background: transparent;
  color: var(--dsw-alias-label-secondary);
  font-size: 12px;
  line-height: 16px;
  cursor: pointer;
}

.sa-select-label {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

@media (hover: hover) {
  .sa-select:hover {
    background: var(--dsw-alias-interactive-bg-hover);
  }
}

.sa-icon-button {
  display: grid;
  flex: none;
  place-items: center;
  box-sizing: border-box;
  width: 24px;
  height: 24px;
  padding: 0;
  border: 0;
  border-radius: var(--dsw-radius-sm);
  background: transparent;
  color: var(--dsw-alias-label-tertiary);
  cursor: pointer;
}

@media (hover: hover) {
  .sa-icon-button:hover {
    color: var(--dsw-alias-label-secondary);
    background: var(--dsw-alias-interactive-bg-hover);
  }
}

.sa-notices {
  display: grid;
  flex: none;
  gap: 4px;
  padding: 6px 12px 0;
}

.sa-notice {
  margin: 0;
  font-size: 12px;
  line-height: 16px;
  color: var(--dsw-alias-label-tertiary);
}

.sa-pane-body {
  display: flex;
  flex: 1 1 auto;
  flex-direction: column;
  gap: 14px;
  min-height: 0;
  padding: 12px;
  overflow-y: auto;
  --dsh-scrollbar-thumb: var(--dsw-alias-scrollbar-bg-l2);
  --dsh-scrollbar-thumb-hover: var(--dsw-alias-scrollbar-hover-l2);
}

.sa-summary {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 8px 12px;
  margin: 0;
}

@media (max-width: 520px) {
  .sa-summary {
    grid-template-columns: minmax(0, 1fr);
  }
}

.sa-field {
  display: flex;
  flex-direction: column;
  gap: 1px;
  min-width: 0;
}

.sa-field-label {
  font-size: 11px;
  line-height: 16px;
  color: var(--dsw-alias-label-tertiary);
}

.sa-field-value {
  margin: 0;
  overflow: hidden;
  font-size: 13px;
  line-height: 18px;
  color: var(--dsw-alias-label-primary);
  text-overflow: ellipsis;
  white-space: nowrap;
}

.sa-section {
  display: flex;
  flex-direction: column;
  gap: 6px;
  min-width: 0;
}

.sa-section-title {
  margin: 0;
  font-size: 12px;
  font-weight: 500;
  line-height: 18px;
  color: var(--dsw-alias-label-secondary);
}

.sa-counts {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.sa-muted {
  margin: 0;
  font-size: 12px;
  line-height: 18px;
  color: var(--dsw-alias-label-tertiary);
}

.sa-note {
  margin: 0;
  font-size: 12px;
  line-height: 16px;
  color: var(--dsw-alias-label-secondary);
  /* Long file paths and assertions must wrap rather than widen the pane. */
  overflow-wrap: anywhere;
}

.sa-list {
  display: flex;
  flex-direction: column;
  gap: 4px;
  margin: 0;
  padding: 0;
  list-style: none;
}

.sa-unit {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
  font-size: 12px;
  line-height: 18px;
}

.sa-unit-label {
  flex: 1 1 auto;
  min-width: 0;
  overflow: hidden;
  color: var(--dsw-alias-label-secondary);
  text-overflow: ellipsis;
  white-space: nowrap;
}

.sa-unit-owner {
  flex: none;
  font-family: var(--dsw-font-family-mono, ui-monospace, monospace);
  font-size: 11px;
  color: var(--dsw-alias-label-tertiary);
}

.sa-finding {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr) auto;
  align-items: baseline;
  gap: 2px 8px;
  box-sizing: border-box;
  width: 100%;
  padding: 2px 0;
  border: 0;
  background: transparent;
  color: var(--dsw-alias-label-primary);
  font-size: 12px;
  line-height: 18px;
  text-align: left;
  cursor: pointer;
}

.sa-finding-title {
  flex: 1 1 auto;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.sa-finding-path {
  grid-column: 1 / -1;
  min-width: 0;
  overflow: hidden;
  color: var(--dsw-alias-label-tertiary);
  font-size: 11px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.sa-empty {
  display: flex;
  flex-direction: column;
  gap: 8px;
  align-items: flex-start;
  padding: 8px 0;
}

.sa-empty-icon {
  display: grid;
  place-items: center;
  color: var(--dsw-alias-label-tertiary);
}

.sa-empty-title {
  margin: 0;
  font-size: 13px;
  font-weight: 500;
  line-height: 20px;
}

.sa-prompt {
  display: flex;
  flex-direction: column;
  gap: 6px;
  padding: 6px 8px;
  border: 0.5px solid var(--dsw-alias-border-l3);
  border-radius: var(--dsw-radius-sm);
}

.sa-prompt-text {
  margin: 0;
  font-size: 12px;
  line-height: 18px;
  color: var(--dsw-alias-label-secondary);
}

.sa-prompt-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}


/* One quiet card: the overview, a phase notice, a finding and the stop form all
   ride this same hairline-edged glass, so nothing shouts. */
.sa-card {
  display: flex;
  flex-direction: column;
  gap: 6px;
  box-sizing: border-box;
  min-width: 0;
  padding: 8px 10px;
  border: 0.5px solid var(--dsw-alias-border-l1);
  border-radius: var(--dsw-radius-lg);
  background: var(--dsw-specific-menu);
  backdrop-filter: var(--dsw-menu-backdrop-filter);
  box-shadow: var(--dsw-elevation-panel);
}

.sa-overview-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 6px 10px;
}

@media (min-width: 520px) {
  .sa-overview-grid {
    grid-template-columns: repeat(4, minmax(0, 1fr));
  }
}

.sa-overview-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
}

.sa-overview-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.sa-bar {
  overflow: hidden;
  height: 4px;
  border-radius: var(--dsw-radius-sm);
  background: var(--dsw-alias-interactive-bg-hover);
}

.sa-bar-fill {
  display: block;
  height: 100%;
  border-radius: var(--dsw-radius-sm);
  background: var(--dsw-alias-brand-primary);
  transition: width 240ms ease-out;
}

/* A phase-change notification: quiet, one line, dismissible. */
.sa-notice-card {
  flex-direction: row;
  align-items: flex-start;
  gap: 8px;
}

.sa-notice-icon {
  flex: none;
  width: 6px;
  height: 6px;
  margin-top: 6px;
  border-radius: 50%;
  background: var(--dsw-alias-brand-primary);
}

.sa-notice-icon[data-kind='units'] {
  background: var(--dsw-alias-label-tertiary);
}

.sa-notice-text {
  display: flex;
  flex: 1 1 auto;
  flex-direction: column;
  gap: 1px;
  min-width: 0;
}

.sa-notice-title {
  margin: 0;
  font-size: 12px;
  font-weight: 500;
  line-height: 16px;
  color: var(--dsw-alias-label-primary);
}

.sa-notice-line {
  margin: 0;
  font-size: 11px;
  line-height: 16px;
  color: var(--dsw-alias-label-tertiary);
}

.sa-notice-close {
  display: grid;
  flex: none;
  place-items: center;
  width: 18px;
  height: 18px;
  padding: 0;
  border: 0;
  border-radius: var(--dsw-radius-sm);
  background: transparent;
  color: var(--dsw-alias-label-tertiary);
  cursor: pointer;
}

@media (hover: hover) {
  .sa-notice-close:hover {
    background: var(--dsw-alias-interactive-bg-hover);
  }
}

/* The unread dot on the pane's own glyph. */
.sa-badge {
  position: absolute;
  width: 5px;
  height: 5px;
  margin: -6px 0 0 8px;
  border-radius: 50%;
  background: var(--dsw-alias-brand-primary);
}

.sa-mode {
  flex: none;
}

/* A collapsible section head: the whole line is the target. */
.sa-disclosure {
  display: flex;
  align-items: center;
  gap: 6px;
  box-sizing: border-box;
  width: 100%;
  padding: 0;
  border: 0;
  background: transparent;
  color: inherit;
  text-align: left;
  cursor: pointer;
}

.sa-chevron {
  flex: none;
  color: var(--dsw-alias-label-tertiary);
  transition: transform 160ms ease-out;
}

.sa-chevron-open {
  transform: rotate(180deg);
}

.sa-map {
  display: flex;
  flex-direction: column;
  gap: 6px;
  padding: 6px 8px;
  border: 0.5px solid var(--dsw-alias-border-l3);
  border-radius: var(--dsw-radius-sm);
}

.sa-map-branch {
  display: flex;
  flex-direction: column;
  gap: 2px;
  min-width: 0;
}

.sa-map-boundary {
  margin: 0;
  overflow: hidden;
  font-size: 12px;
  line-height: 16px;
  color: var(--dsw-alias-label-secondary);
  text-overflow: ellipsis;
  white-space: nowrap;
}

/* The report's own header and actions. */
.sa-report-repo {
  margin: 0;
  font-size: 12px;
  font-weight: 500;
  line-height: 16px;
  color: var(--dsw-alias-label-primary);
}

.sa-partial {
  margin: 0;
  padding-top: 2px;
  border-top: 0.5px solid var(--dsw-alias-border-l3);
  font-size: 12px;
  line-height: 16px;
  color: var(--dsw-alias-state-warn-primary);
}

.sa-report-actions {
  display: flex;
  align-items: center;
  gap: 6px;
}

/* One confirmed finding. */
.sa-finding-head {
  display: flex;
  align-items: center;
  gap: 6px;
}

.sa-finding-name {
  margin: 0;
  font-size: 13px;
  font-weight: 500;
  line-height: 18px;
  color: var(--dsw-alias-label-primary);
}

.sa-boundary {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.sa-finding-summary {
  margin: 0;
  font-size: 12px;
  line-height: 17px;
  color: var(--dsw-alias-label-secondary);
}

.sa-traces {
  display: flex;
  flex-wrap: wrap;
  gap: 4px 8px;
}

.sa-trace {
  overflow: hidden;
  max-width: 100%;
  padding: 0;
  border: 0;
  background: transparent;
  color: var(--dsw-alias-brand-primary);
  font-family: var(--dsw-font-family-mono, ui-monospace, monospace);
  font-size: 11px;
  line-height: 16px;
  text-align: left;
  text-overflow: ellipsis;
  white-space: nowrap;
  cursor: pointer;
}

.sa-trace:focus-visible,
.sa-disclosure:focus-visible,
.sa-notice-close:focus-visible {
  outline: var(--dsw-focus-ring-width) solid var(--dsw-focus-ring-color, var(--dsw-alias-brand-primary));
  outline-offset: calc(-1 * var(--dsw-focus-ring-width));
}

.sa-denial {
  display: flex;
  flex-direction: column;
  gap: 2px;
  padding: 6px 8px;
  border: 0.5px solid var(--dsw-alias-border-l3);
  border-radius: var(--dsw-radius-sm);
}

.sa-denial-head {
  display: flex;
  align-items: center;
  gap: 6px;
}

.sa-denial-line {
  display: flex;
  flex-direction: column;
  gap: 1px;
  min-width: 0;
}

.sa-record-toggle {
  padding-top: 2px;
  border-top: 0.5px solid var(--dsw-alias-border-l3);
}

.sa-raw {
  overflow: auto;
  max-height: 320px;
  margin: 0;
  padding: 8px;
  border: 0.5px solid var(--dsw-alias-border-l3);
  border-radius: var(--dsw-radius-sm);
  background: var(--dsw-alias-bg-layer-1);
  color: var(--dsw-alias-label-secondary);
  font-family: var(--dsw-font-family-mono, ui-monospace, monospace);
  font-size: 11px;
  line-height: 16px;
  white-space: pre-wrap;
  word-break: break-word;
}

/* The needs-validation table: four columns, stacking to one on a phone. */
.sa-table {
  display: grid;
  grid-template-columns: minmax(0, 1.4fr) minmax(0, 1fr) minmax(0, 1.6fr) minmax(0, 1.6fr);
  gap: 4px 10px;
  padding: 6px 8px;
  border: 0.5px solid var(--dsw-alias-border-l3);
  border-radius: var(--dsw-radius-sm);
}

@media (max-width: 520px) {
  .sa-table {
    grid-template-columns: minmax(0, 1fr);
  }

  .sa-table-head {
    display: none;
  }
}

.sa-table-head,
.sa-table-row {
  display: contents;
}

.sa-table-head .sa-table-cell {
  font-size: 11px;
  line-height: 16px;
  color: var(--dsw-alias-label-tertiary);
}

.sa-table-cell {
  min-width: 0;
  font-size: 12px;
  line-height: 17px;
  color: var(--dsw-alias-label-secondary);
}

.sa-table-title {
  color: var(--dsw-alias-label-primary);
}

/* The export row: a folder field and its button, filling the pane. */
.sa-export {
  display: flex;
  gap: 6px;
  align-items: center;
}

.sa-export > span {
  flex: 1 1 auto;
  min-width: 0;
}

.sa-error {
  color: var(--dsw-alias-state-error-primary);
}

/* The stop form. */
.sa-stop {
  gap: 4px;
}

/* The session-header control: a compact icon button beside the header's quiet actions. */
.sa-header-trigger {
  display: inline-flex;
  flex: none;
  align-items: center;
  justify-content: center;
  box-sizing: border-box;
  width: 28px;
  height: 28px;
  padding: 0;
  border: 0;
  border-radius: var(--dsw-radius-sm);
  background: transparent;
  color: var(--dsw-alias-label-tertiary);
  cursor: pointer;
}

@media (hover: hover) {
  .sa-header-trigger:hover {
    color: var(--dsw-alias-label-secondary);
    background: var(--dsw-alias-interactive-bg-hover);
  }
}
`

/**
 * Inject the surfaces' stylesheet while the plugin is loaded.
 * @returns the disposer that removes the style element this call created.
 */
export function injectStyles(): () => void {
  if (document.querySelector(`style[data-plugin="${STYLE_OWNER}"]`) !== null) return () => {}
  const tag = document.createElement('style')
  tag.dataset.plugin = STYLE_OWNER
  tag.textContent = STYLES
  document.head.appendChild(tag)
  return () => { tag.remove() }
}
